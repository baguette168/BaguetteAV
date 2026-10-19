using BaguetteAV.EDR.Core.Models;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;

namespace BaguetteAV.EDR.Core.Services;

public sealed class SysmonEventReader : IDisposable
{
    private const string Channel = "Microsoft-Windows-Sysmon/Operational";
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";
    private readonly object _gate = new();
    private EventLogWatcher? _watcher;
    private Timer? _retryTimer;
    private int _retrySeconds = 5;
    private bool _disposed;

    public event Action<TelemetryEvent>? EventReceived;
    public event Action<string>? StatusChanged;
    public bool IsRunning { get; private set; }

    public void Start()
    {
        lock (_gate)
        {
            if (_disposed || IsRunning) return;
        }
        TryStart();
    }

    public void Stop()
    {
        lock (_gate)
        {
            _retryTimer?.Dispose();
            _retryTimer = null;
            if (_watcher is not null)
            {
                try { _watcher.Enabled = false; } catch { }
                try { _watcher.EventRecordWritten -= OnEventRecord; } catch { }
                try { _watcher.Dispose(); } catch { }
                _watcher = null;
            }
            IsRunning = false;
        }
    }

    private void TryStart()
    {
        try
        {
            var query = new EventLogQuery(Channel, PathType.LogName,
                "*[System[(EventID=1 or EventID=3 or EventID=6 or EventID=8 or EventID=10 or EventID=11 or EventID=19 or EventID=20 or EventID=21)]]");
            var watcher = new EventLogWatcher(query);
            watcher.EventRecordWritten += OnEventRecord;
            watcher.Enabled = true;
            lock (_gate) _watcher = watcher;
            IsRunning = true;
            _retrySeconds = 5;
            StatusChanged?.Invoke("Sysmon 事件通道已连接");
        }
        catch (Exception ex)
        {
            IsRunning = false;
            StatusChanged?.Invoke(string.Concat("Sysmon 订阅失败，稍后重试：", ex.Message));
            ScheduleRetry();
        }
    }

    private void ScheduleRetry()
    {
        lock (_gate)
        {
            if (_disposed) return;
            _retryTimer?.Dispose();
            var delay = TimeSpan.FromSeconds(_retrySeconds);
            _retrySeconds = Math.Min(60, _retrySeconds * 2);
            _retryTimer = new Timer(_ => TryStart(), null, delay, Timeout.InfiniteTimeSpan);
        }
    }

    private void OnEventRecord(object? sender, EventRecordWrittenEventArgs e)
    {
        try
        {
            if (e.EventRecord is null) return;
            var parsed = Parse(e.EventRecord.ToXml());
            if (parsed is not null) EventReceived?.Invoke(parsed);
        }
        catch
        {
            // A single malformed record must not stop the subscription.
        }
    }

    public static TelemetryEvent? Parse(string xml)
    {
        var document = XDocument.Parse(xml);
        var system = document.Root?.Element(Ns + "System");
        if (system is null) return null;
        if (!int.TryParse(system.Element(Ns + "EventID")?.Value, out var eventId)) return null;

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var node in document.Descendants(Ns + "EventData").Elements(Ns + "Data"))
        {
            var name = node.Attribute("Name")?.Value;
            if (!string.IsNullOrEmpty(name)) fields[name] = node.Value;
        }
        string Get(string key) => fields.TryGetValue(key, out var value) ? value : string.Empty;
        int GetInt(string key) => int.TryParse(Get(key), out var value) ? value : 0;

        var kind = eventId switch
        {
            1 => TelemetryKind.ProcessCreate,
            3 => TelemetryKind.NetworkConnect,
            6 => TelemetryKind.DriverLoad,
            8 => TelemetryKind.RemoteThread,
            10 => TelemetryKind.ProcessAccess,
            11 => TelemetryKind.FileCreate,
            19 => TelemetryKind.WmiFilter,
            20 => TelemetryKind.WmiConsumer,
            21 => TelemetryKind.WmiBinding,
            _ => TelemetryKind.Unknown
        };
        if (kind == TelemetryKind.Unknown) return null;

        var isInjection = kind == TelemetryKind.RemoteThread || kind == TelemetryKind.ProcessAccess;
        return new TelemetryEvent
        {
            Kind = kind,
            EventId = eventId,
            Timestamp = DateTime.Now,
            ProcessId = isInjection ? GetInt("SourceProcessId") : GetInt("ProcessId"),
            ParentProcessId = GetInt("ParentProcessId"),
            Image = isInjection ? Get("SourceImage") : Get("Image"),
            ParentImage = Get("ParentImage"),
            CommandLine = Get("CommandLine"),
            User = Get("User"),
            IntegrityLevel = Get("IntegrityLevel"),
            Hashes = Get("Hashes"),
            TargetProcessId = GetInt("TargetProcessId"),
            TargetImage = Get("TargetImage"),
            GrantedAccess = Get("GrantedAccess"),
            DestinationIp = Get("DestinationIp"),
            DestinationPort = GetInt("DestinationPort"),
            DestinationHost = Get("DestinationHostname"),
            Protocol = Get("Protocol"),
            FilePath = Get("TargetFilename"),
            DriverPath = Get("ImageLoaded"),
            WmiName = Get("Name"),
            WmiQuery = Get("Query"),
            WmiConsumerType = Get("Type"),
            WmiDestination = Get("Destination"),
            Source = "sysmon",
            Fields = fields
        };
    }

    public void Dispose()
    {
        lock (_gate) _disposed = true;
        Stop();
    }
}
