using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;
using BaguetteAV.EDR.Core.Rules;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace BaguetteAV.EDR.Core.Services;

public sealed class ServiceEdrBackend : IEdrBackend
{
    private readonly object _gate = new();
    private readonly List<DetectionRecord> _detections = new();
    private readonly HashSet<Guid> _detectionIds = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly ProcessInspector _inspector = new();
    private Task? _pollTask;
    private List<DetectionRule> _rules = new();
    private List<PolicyLoadError> _policyErrors = new();
    private bool _running;
    private bool _connected;
    private long _eventCount;
    private long _blockedCount;
    private int _processCount;
    private int _recentSampleCount;
    private string _sysmonStatus = "正在连接保护服务";

    public ServiceEdrBackend()
    {
        Settings = new SettingsStore().Load();
        Log = new LogService();
        Policies = new PolicyRepository();
        Quarantine = new QuarantineService(Log, () => Settings.QuarantinePath);
        var firewall = new FirewallService(Log);
        Response = new ResponseEngine(Log, Quarantine, firewall);
        Rootkit = new RootkitScanner(_inspector, Log);
        ClamAv = new ClamAvScanner(Log);
        _rules = BuildLocalRules();
    }

    public static ServiceEdrBackend? TryCreate(out string error, int timeoutMs = 1800)
    {
        var backend = new ServiceEdrBackend();
        try
        {
            var status = backend.QueryStatusAsync(timeoutMs, backend._cts.Token).GetAwaiter().GetResult();
            if (status is null)
            {
                backend.Dispose();
                error = "B-EDR 保护服务未运行";
                return null;
            }
            backend.ApplyStatus(status, initial: true);
            backend._pollTask = Task.Run(() => backend.PollLoopAsync(backend._cts.Token));
            error = string.Empty;
            return backend;
        }
        catch (Exception ex)
        {
            backend.Dispose();
            error = string.Concat("连接 B-EDR 保护服务失败：", ex.Message);
            return null;
        }
    }

    public EdrSettings Settings { get; private set; }
    public PolicyRepository Policies { get; }
    public LogService Log { get; }
    public ClamAvScanner ClamAv { get; }
    public QuarantineService Quarantine { get; }
    public ResponseEngine Response { get; }
    public RootkitScanner Rootkit { get; }
    public bool IsRunning => _running;
    public string SysmonStatus => _sysmonStatus;
    public long EventCount => Interlocked.Read(ref _eventCount);
    public long BlockedCount => Interlocked.Read(ref _blockedCount);
    public int ProcessCount => _processCount;
    public int RecentSampleCount => _recentSampleCount;

    public IReadOnlyList<DetectionRecord> RecentDetections
    {
        get { lock (_gate) return _detections.ToArray(); }
    }

    public IReadOnlyList<PolicyFixtureSample> RecentSamples => Array.Empty<PolicyFixtureSample>();

    public IReadOnlyList<DetectionRule> AvailableRules
    {
        get { lock (_gate) return _rules.ToArray(); }
    }

    public IReadOnlyList<PolicyLoadError> PolicyErrors
    {
        get { lock (_gate) return _policyErrors.ToArray(); }
    }

    public event Action<DetectionRecord>? DetectionRaised;
    public event Action<string>? StatusChanged;
    public event Action? StateChanged;

    public void Start() => SetProtection(true);
    public void Stop() => SetProtection(false);

    public void SetProtection(bool enabled)
    {
        var response = Send("setProtection", new { enabled }, 5000);
        if (!response.Ok)
        {
            StatusChanged?.Invoke(string.Concat("保护服务控制失败：", response.Error));
            return;
        }
        Settings.ProtectionEnabled = enabled;
        StatusChanged?.Invoke(enabled ? "已向保护服务请求开启实时防护" : "已向保护服务请求暂停实时防护");
        _ = RefreshStatusAsync();
    }

    public void ApplySettings(EdrSettings settings)
    {
        var response = Send("applySettings", settings, 8000);
        if (!response.Ok)
        {
            StatusChanged?.Invoke(string.Concat("设置下发失败：", response.Error));
            return;
        }
        Settings = settings.Clone();
        ReloadLocalRules();
        StatusChanged?.Invoke("设置已由保护服务应用");
    }

    public void ReloadPolicies()
    {
        var response = Send("reloadPolicies", null, 8000);
        ReloadLocalRules();
        StatusChanged?.Invoke(response.Ok ? "策略已由保护服务重新加载" : string.Concat("策略重载失败：", response.Error));
        _ = RefreshStatusAsync();
    }

    public IReadOnlyList<ProcessInfo> RefreshProcesses()
    {
        var response = Send("processes", null, 20000);
        if (response.Ok && response.Data is { } data)
        {
            try
            {
                return data.Deserialize<List<ProcessInfo>>(PolicyJson.Options) ?? new List<ProcessInfo>();
            }
            catch { }
        }
        return _inspector.Snapshot();
    }

    public void AppendDetection(DetectionRecord detection)
    {
        Send("appendDetection", detection, 5000);
        lock (_gate)
        {
            if (_detectionIds.Add(detection.Id)) _detections.Insert(0, detection);
            else
            {
                var index = _detections.FindIndex(item => item.Id == detection.Id);
                if (index >= 0) _detections[index] = detection;
            }
        }
    }

    public bool ExportRecentSamples(string path, int max = 200)
    {
        var response = Send("exportSamples", new { path, max }, 15000);
        if (!response.Ok) StatusChanged?.Invoke(string.Concat("样本导出失败：", response.Error));
        return response.Ok;
    }

    private async Task PollLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            await RefreshStatusAsync().ConfigureAwait(false);
            try { await Task.Delay(1000, token).ConfigureAwait(false); } catch (OperationCanceledException) { break; }
        }
    }

    private async Task RefreshStatusAsync()
    {
        var status = await QueryStatusAsync(2500, _cts.Token).ConfigureAwait(false);
        if (status is null)
        {
            if (_connected)
            {
                _connected = false;
                _running = false;
                StatusChanged?.Invoke("B-EDR 保护服务连接中断，正在重连");
                StateChanged?.Invoke();
            }
            return;
        }
        ApplyStatus(status, initial: false);
    }

    private async Task<EdrServiceStatus?> QueryStatusAsync(int timeoutMs, CancellationToken token)
    {
        try
        {
            var response = await SendAsync("status", null, timeoutMs, token).ConfigureAwait(false);
            if (!response.Ok || response.Data is null) return null;
            return response.Data.Value.Deserialize<EdrServiceStatus>(EdrIpc.Json);
        }
        catch
        {
            return null;
        }
    }

    private void ApplyStatus(EdrServiceStatus status, bool initial)
    {
        var newlyRaised = new List<DetectionRecord>();
        var statusChanged = false;
        lock (_gate)
        {
            statusChanged = status.SysmonStatus != _sysmonStatus || !_connected;
            _connected = true;
            _running = status.IsRunning;
            _eventCount = status.EventCount;
            _blockedCount = status.BlockedCount;
            _processCount = status.ProcessCount;
            _recentSampleCount = status.RecentSampleCount;
            _sysmonStatus = status.SysmonStatus;
            _policyErrors = status.PolicyErrors.ToList();
            foreach (var detection in status.RecentDetections.OrderBy(d => d.Timestamp))
            {
                var index = _detections.FindIndex(item => item.Id == detection.Id);
                if (index >= 0) _detections[index] = detection;
                else _detections.Insert(0, detection);
                if (_detectionIds.Add(detection.Id) && !initial) newlyRaised.Add(detection);
            }
            while (_detections.Count > 1000) _detections.RemoveAt(_detections.Count - 1);
        }
        foreach (var line in status.RecentLogs.TakeLast(300)) Log.Ingest(line);
        if (statusChanged) StatusChanged?.Invoke("B-EDR 保护服务已连接");
        foreach (var detection in newlyRaised) DetectionRaised?.Invoke(detection);
        StateChanged?.Invoke();
    }

    private ControlResponse Send(string command, object? payload, int timeoutMs)
    {
        try { return SendAsync(command, payload, timeoutMs, _cts.Token).GetAwaiter().GetResult(); }
        catch (Exception ex) { return new ControlResponse { Ok = false, Error = ex.Message }; }
    }

    private async Task<ControlResponse> SendAsync(string command, object? payload, int timeoutMs, CancellationToken token)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(token);
        linked.CancelAfter(timeoutMs);
        using var pipe = new NamedPipeClientStream(".", EdrIpc.PipeName, PipeDirection.InOut,
            PipeOptions.Asynchronous);
        await pipe.ConnectAsync(linked.Token).ConfigureAwait(false);
        var request = new ControlRequest
        {
            Command = command,
            Payload = payload is null ? null : JsonSerializer.SerializeToElement(payload, EdrIpc.Json)
        };
        var json = JsonSerializer.Serialize(request, EdrIpc.Json);
        if (Encoding.UTF8.GetByteCount(json) > EdrIpc.MaxMessageBytes)
            return new ControlResponse { Ok = false, Error = "控制消息超过 1 MB" };
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true };
        using var reader = new StreamReader(pipe, new UTF8Encoding(false), leaveOpen: true);
        await writer.WriteLineAsync(json).ConfigureAwait(false);
        var line = await reader.ReadLineAsync(linked.Token).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(line)) return new ControlResponse { Ok = false, Error = "保护服务未返回响应" };
        return JsonSerializer.Deserialize<ControlResponse>(line, EdrIpc.Json)
            ?? new ControlResponse { Ok = false, Error = "保护服务响应格式无效" };
    }

    private List<DetectionRule> BuildLocalRules()
    {
        var rules = RuleCatalog.CreateDefault().ToList();
        var ids = new HashSet<string>(rules.Select(rule => rule.Id), StringComparer.OrdinalIgnoreCase);
        foreach (var pack in Policies.LoadActive().Packs)
        foreach (var rule in pack.Rules)
            if (ids.Add(rule.Id)) rules.Add(new PolicyRuleAdapter(pack, rule));
        return rules;
    }

    private void ReloadLocalRules()
    {
        var rules = BuildLocalRules();
        lock (_gate) _rules = rules;
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _pollTask?.Wait(1500); } catch { }
        _cts.Dispose();
    }
}
