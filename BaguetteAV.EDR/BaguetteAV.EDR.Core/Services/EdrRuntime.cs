using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;
using BaguetteAV.EDR.Core.Rules;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Channels;

namespace BaguetteAV.EDR.Core.Services;

public sealed class EdrRuntime : IDisposable
{
    private readonly SettingsStore _settingsStore = new();
    private readonly Dictionary<int, ProcessInfo> _known = new();
    private readonly HashSet<string> _knownConnections = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, DateTime> _dedup = new();
    private readonly Dictionary<int, (DateTime Stamp, string Path)> _pathCache = new();
    private readonly List<DetectionRecord> _detections = new();
    private readonly ConcurrentQueue<PolicyFixtureSample> _recentSamples = new();
    private readonly object _detectionLock = new();
    private readonly object _policyWatchGate = new();
    private Channel<TelemetryEvent>? _channel;
    private CancellationTokenSource? _cts;
    private Task? _worker;
    private Timer? _pollTimer;
    private Timer? _policyReloadTimer;
    private FileSystemWatcher? _policyWatcher;
    private RuleEngine _rules;
    private long _eventCount;
    private long _blockedCount;
    private int _processCount;
    private bool _disposed;

    public EdrRuntime(PolicyRepository? policies = null, PluginLoader? plugins = null)
    {
        Settings = _settingsStore.Load();
        Log = new LogService();
        Inspector = new ProcessInspector();
        Detections = new DetectionStore(Log);
        Quarantine = new QuarantineService(Log, () => Settings.QuarantinePath);
        Firewall = new FirewallService(Log);
        Response = new ResponseEngine(Log, Quarantine, Firewall);
        Rootkit = new RootkitScanner(Inspector, Log);
        ClamAv = new ClamAvScanner(Log);
        Tcp = new TcpTableReader();
        Sysmon = new SysmonEventReader();
        Policies = policies ?? new PolicyRepository();
        Plugins = plugins ?? new PluginLoader();
        _rules = BuildRules();
    }

    public EdrSettings Settings { get; private set; }
    public LogService Log { get; }
    public ProcessInspector Inspector { get; }
    public DetectionStore Detections { get; }
    public QuarantineService Quarantine { get; }
    public FirewallService Firewall { get; }
    public ResponseEngine Response { get; }
    public RootkitScanner Rootkit { get; }
    public ClamAvScanner ClamAv { get; }
    public TcpTableReader Tcp { get; }
    public SysmonEventReader Sysmon { get; }
    public PolicyRepository Policies { get; }
    public PluginLoader Plugins { get; }
    public RuleEngine Rules => _rules;
    public IReadOnlyList<PolicyLoadError> PolicyErrors { get; private set; } = Array.Empty<PolicyLoadError>();
    public bool IsRunning { get; private set; }
    public string SysmonStatus { get; private set; } = "未启动";
    public long EventCount => Interlocked.Read(ref _eventCount);
    public long BlockedCount => Interlocked.Read(ref _blockedCount);
    public int ProcessCount => _processCount;

    public event Action<DetectionRecord>? DetectionRaised;
    public event Action<string>? StatusChanged;
    public event Action? StateChanged;

    public IReadOnlyList<DetectionRecord> RecentDetections
    {
        get { lock (_detectionLock) return _detections.ToArray(); }
    }

    public IReadOnlyList<PolicyFixtureSample> RecentSamples => _recentSamples.ToArray();

    public bool ExportRecentSamples(string path, int max = 200)
    {
        var samples = RecentSamples.TakeLast(Math.Clamp(max, 1, 2000)).ToArray();
        return samples.Length > 0 && PolicyFixtures.Save(path, samples, "live-telemetry");
    }

    public void Start()
    {
        if (_disposed || IsRunning) return;
        _cts = new CancellationTokenSource();
        _channel = Channel.CreateBounded<TelemetryEvent>(new BoundedChannelOptions(Settings.EventQueueCapacity)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false
        });
        _worker = Task.Run(() => ProcessLoopAsync(_cts.Token));
        Sysmon.EventReceived += OnSysmonEvent;
        Sysmon.StatusChanged += OnSysmonStatus;
        Sysmon.Start();
        StartPolicyWatcher();
        _pollTimer = new Timer(_ => Poll(), null, 1500, 2500);
        LoadRecent();
        IsRunning = true;
        StatusChanged?.Invoke("实时防护已启动");
        Log.Info("BaguetteAV EDR 实时防护已启动");
    }

    public void Stop()
    {
        if (!IsRunning) return;
        IsRunning = false;
        try { _cts?.Cancel(); } catch { }
        _pollTimer?.Dispose();
        _pollTimer = null;
        Sysmon.EventReceived -= OnSysmonEvent;
        Sysmon.StatusChanged -= OnSysmonStatus;
        Sysmon.Stop();
        StopPolicyWatcher();
        StatusChanged?.Invoke("实时防护已暂停");
        Log.Warn("实时防护已暂停");
        StateChanged?.Invoke();
    }

    public void SetProtection(bool enabled)
    {
        Settings.ProtectionEnabled = enabled;
        _settingsStore.Save(Settings);
        if (enabled) Start(); else Stop();
    }

    public void ApplySettings(EdrSettings settings)
    {
        Settings = settings.Clone();
        _settingsStore.Save(Settings);
        _rules = BuildRules();
        Log.Info("设置已应用");
        StateChanged?.Invoke();
    }

    public void ReloadPolicies()
    {
        Plugins.Reload();
        _rules = BuildRules();
        Log.Info(string.Concat("策略已重新加载：", _rules.Rules.Count, " 条规则"));
        StateChanged?.Invoke();
    }

    private void StartPolicyWatcher()
    {
        try
        {
            Directory.CreateDirectory(Policies.Root);
            var watcher = new FileSystemWatcher(Policies.Root, "*.json")
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.DirectoryName
            };
            watcher.Changed += OnPolicyFileChanged;
            watcher.Created += OnPolicyFileChanged;
            watcher.Deleted += OnPolicyFileChanged;
            watcher.Renamed += OnPolicyFileChanged;
            watcher.EnableRaisingEvents = true;
            _policyWatcher = watcher;
        }
        catch (Exception ex)
        {
            Log.Warn(string.Concat("策略目录监视启动失败：", ex.Message));
        }
    }

    private void OnPolicyFileChanged(object sender, FileSystemEventArgs args)
    {
        if (_disposed || !IsRunning) return;
        lock (_policyWatchGate)
        {
            _policyReloadTimer?.Dispose();
            _policyReloadTimer = new Timer(_ =>
            {
                if (_disposed || !IsRunning) return;
                try
                {
                    ReloadPolicies();
                }
                catch (Exception ex)
                {
                    Log.Warn(string.Concat("策略自动重载失败：", ex.Message));
                }
            }, null, 450, Timeout.Infinite);
        }
    }

    private void StopPolicyWatcher()
    {
        lock (_policyWatchGate)
        {
            _policyReloadTimer?.Dispose();
            _policyReloadTimer = null;
            if (_policyWatcher is not null)
            {
                _policyWatcher.EnableRaisingEvents = false;
                _policyWatcher.Changed -= OnPolicyFileChanged;
                _policyWatcher.Created -= OnPolicyFileChanged;
                _policyWatcher.Deleted -= OnPolicyFileChanged;
                _policyWatcher.Renamed -= OnPolicyFileChanged;
                _policyWatcher.Dispose();
                _policyWatcher = null;
            }
        }
    }

    public IReadOnlyList<DetectionRule> AvailableRules => _rules.Rules;

    private RuleEngine BuildRules()
    {
        var rules = RuleCatalog.CreateDefault().ToList();
        var ids = new HashSet<string>(rules.Select(r => r.Id), StringComparer.OrdinalIgnoreCase);
        var bundle = Policies.LoadActive();
        var errors = new List<PolicyLoadError>(bundle.Errors);
        foreach (var pack in bundle.Packs)
        {
            foreach (var policyRule in pack.Rules)
            {
                if (!ids.Add(policyRule.Id))
                {
                    errors.Add(new PolicyLoadError(pack.Id, string.Concat("规则 ID 与内置规则或其他策略冲突：", policyRule.Id)));
                    continue;
                }
                rules.Add(new PolicyRuleAdapter(pack, policyRule));
            }
        }
        var pluginResult = Plugins.Load();
        errors.AddRange(pluginResult.Errors);
        foreach (var pack in pluginResult.Packs)
        {
            foreach (var policyRule in pack.Rules)
            {
                if (!ids.Add(policyRule.Id))
                {
                    errors.Add(new PolicyLoadError(pack.Id, string.Concat("插件规则 ID 冲突：", policyRule.Id)));
                    continue;
                }
                rules.Add(new PolicyRuleAdapter(pack, policyRule));
            }
        }
        foreach (var rule in pluginResult.Rules)
        {
            if (!ids.Add(rule.Id))
            {
                errors.Add(new PolicyLoadError("plugin", string.Concat("插件规则 ID 冲突：", rule.Id)));
                continue;
            }
            rules.Add(rule);
        }
        PolicyErrors = errors;
        foreach (var error in errors) Log.Warn(string.Concat("策略加载失败 ", error.PolicyId, "：", error.Message));
        var engine = new RuleEngine(rules, RuleCatalog.CreateContext(Settings));
        foreach (var rule in engine.Rules)
            rule.Enabled = !Settings.DisabledRuleIds.Contains(rule.Id, StringComparer.OrdinalIgnoreCase);
        return engine;
    }

    private void OnSysmonStatus(string status)
    {
        SysmonStatus = status;
        Log.Info(status);
        StatusChanged?.Invoke(status);
        StateChanged?.Invoke();
    }

    private void OnSysmonEvent(TelemetryEvent telemetry)
    {
        _channel?.Writer.TryWrite(telemetry);
    }

    private async Task ProcessLoopAsync(CancellationToken token)
    {
        if (_channel is null) return;
        try
        {
            await foreach (var telemetry in _channel.Reader.ReadAllAsync(token))
            {
                Interlocked.Increment(ref _eventCount);
                if (!Settings.ProtectionEnabled) continue;
                await EvaluateAsync(telemetry, token);
                if (EventCount % 20 == 0) StateChanged?.Invoke();
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Log.Error(string.Concat("事件处理循环异常：", ex.Message));
        }
    }

    private async Task EvaluateAsync(TelemetryEvent telemetry, CancellationToken token)
    {
        try
        {
            var parentPath = LookupPath(telemetry.ParentProcessId);
            var context = Inspector.BuildContext(telemetry, parentPath);
            CaptureSample(telemetry, context);
            var hits = _rules.Evaluate(telemetry, context);
            if (hits.Count == 0) return;
            var ordered = hits.OrderByDescending(h => h.Match.Score).ToList();
            var primary = ordered[0];
            var key = string.Concat(primary.Rule.Id, ":", telemetry.ProcessId, ":", telemetry.DestinationIp, ":", telemetry.DestinationPort);
            var now = DateTime.UtcNow;
            if (_dedup.TryGetValue(key, out var last) && (now - last).TotalSeconds < 30) return;
            _dedup[key] = now;
            if (_dedup.Count > 5000)
            {
                foreach (var pair in _dedup.Where(p => (now - p.Value).TotalMinutes > 5).Take(1000))
                    _dedup.TryRemove(pair.Key, out _);
            }

            var detection = new DetectionRecord
            {
                Timestamp = DateTime.Now,
                RuleId = primary.Rule.Id,
                RuleName = primary.Rule.Name,
                Mitre = primary.Rule.Mitre,
                Score = RuleEngine.AggregateScore(ordered.Select(h => h.Match)),
                Severity = RuleEngine.SeverityFor(RuleEngine.AggregateScore(ordered.Select(h => h.Match))),
                Description = string.Join("；", ordered.Select(h => h.Match.Detail)),
                ProcessId = telemetry.ProcessId,
                ProcessName = context.FileName,
                ImagePath = context.ImagePath,
                ParentName = Path.GetFileName(context.ParentImage),
                CommandLine = telemetry.CommandLine,
                User = telemetry.User,
                Sha256 = context.Sha256,
                Destination = telemetry.DestinationIp.Length == 0 ? string.Empty
                    : string.Concat(telemetry.DestinationIp, ":", telemetry.DestinationPort),
                Action = Settings.ResponseMode == ResponseMode.AlertOnly ? "仅告警" : "检测命中"
            };
            DetectionRaised?.Invoke(detection);
            StateChanged?.Invoke();

            try
            {
                if (Settings.ResponseMode == ResponseMode.AutoContain)
                {
                    var action = await Response.RespondAsync(detection, context, Settings, primary.Rule.Response, token);
                    detection.Action = action;
                    if (action.Contains("已终止") || action.Contains("已阻断"))
                        Interlocked.Increment(ref _blockedCount);
                }
            }
            catch (Exception responseError)
            {
                detection.Action = string.Concat("处置失败：", responseError.Message);
                Log.Error(detection.Action);
            }

            AddDetection(detection);
            Log.Warn(string.Concat("命中 ", detection.RuleName, " PID=", detection.ProcessId, " 评分=", detection.Score));
            DetectionRaised?.Invoke(detection);
            StateChanged?.Invoke();
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            Log.Error(string.Concat("检测评估异常：", ex.Message));
        }
    }

    private void AddDetection(DetectionRecord detection)
    {
        lock (_detectionLock)
        {
            _detections.Insert(0, detection);
            var limit = Math.Max(100, Settings.MaxDetectionsInMemory);
            if (_detections.Count > limit) _detections.RemoveRange(limit, _detections.Count - limit);
        }
        Detections.Append(detection);
    }

    public void UpdateDetection(DetectionRecord detection)
    {
        lock (_detectionLock)
        {
            var index = _detections.FindIndex(item => item.Id == detection.Id);
            if (index >= 0) _detections[index] = detection;
            else _detections.Insert(0, detection);
        }
        Detections.Append(detection);
        StateChanged?.Invoke();
    }

    private void CaptureSample(TelemetryEvent telemetry, ProcessContext context)
    {
        _recentSamples.Enqueue(new PolicyFixtureSample { Event = telemetry, Process = context });
        while (_recentSamples.Count > 512) _recentSamples.TryDequeue(out _);
    }

    private void LoadRecent()
    {
        var records = Detections.LoadRecent(Math.Max(100, Settings.MaxDetectionsInMemory));
        lock (_detectionLock)
        {
            _detections.Clear();
            _detections.AddRange(records);
        }
        Detections.Trim(DateTime.UtcNow.AddDays(-Math.Max(1, Settings.RetentionDays)));
    }

    private string LookupPath(int processId)
    {
        if (processId <= 0) return string.Empty;
        lock (_pathCache)
        {
            if (_pathCache.TryGetValue(processId, out var cached) && (DateTime.UtcNow - cached.Stamp).TotalSeconds < 10)
                return cached.Path;
        }
        var path = Inspector.TryGetImagePath(processId);
        lock (_pathCache) _pathCache[processId] = (DateTime.UtcNow, path);
        return path;
    }

    private void Poll()
    {
        try
        {
            var snapshot = Inspector.Snapshot();
            _processCount = snapshot.Count;
            var byPid = snapshot.GroupBy(p => p.ProcessId).ToDictionary(g => g.Key, g => g.First());
            if (!Sysmon.IsRunning)
            {
                foreach (var process in snapshot)
                {
                    if (_known.ContainsKey(process.ProcessId)) continue;
                    var image = LookupPath(process.ProcessId);
                    _channel?.Writer.TryWrite(new TelemetryEvent
                    {
                        Kind = TelemetryKind.ProcessCreate,
                        Timestamp = DateTime.Now,
                        ProcessId = process.ProcessId,
                        ParentProcessId = process.ParentProcessId,
                        Image = string.IsNullOrWhiteSpace(image) ? process.Name : image,
                        ParentImage = LookupPath(process.ParentProcessId),
                        Source = "poll"
                    });
                }
            }
            _known.Clear();
            foreach (var pair in byPid) _known[pair.Key] = pair.Value;

            if (!Sysmon.IsRunning && Settings.MonitorNetwork)
            {
                foreach (var connection in Tcp.Read())
                {
                    var key = string.Concat(connection.ProcessId, "|", connection.RemoteAddress, "|", connection.RemotePort);
                    if (!_knownConnections.Add(key)) continue;
                    _channel?.Writer.TryWrite(new TelemetryEvent
                    {
                        Kind = TelemetryKind.NetworkConnect,
                        Timestamp = DateTime.Now,
                        ProcessId = connection.ProcessId,
                        Image = LookupPath(connection.ProcessId),
                        DestinationIp = connection.RemoteAddress,
                        DestinationPort = connection.RemotePort,
                        Protocol = "TCP",
                        Source = "tcp-table"
                    });
                }
                if (_knownConnections.Count > 20000) _knownConnections.Clear();
            }
            StateChanged?.Invoke();
        }
        catch (Exception ex)
        {
            Log.Warn(string.Concat("轮询失败：", ex.Message));
        }
    }

    public IReadOnlyList<ProcessInfo> RefreshProcesses()
    {
        var snapshot = Inspector.Snapshot();
        var result = new List<ProcessInfo>(snapshot.Count);
        foreach (var process in snapshot)
        {
            var path = LookupPath(process.ProcessId);
            var userWritable = RuleContext.IsUserWritable(path);
            result.Add(new ProcessInfo
            {
                ProcessId = process.ProcessId,
                ParentProcessId = process.ParentProcessId,
                Name = process.Name,
                ParentName = process.ParentName,
                ImagePath = path,
                IsUserWritable = userWritable,
                IsSigned = userWritable && !string.IsNullOrWhiteSpace(path) && Inspector.IsSigned(path),
                Sha256 = userWritable ? Inspector.TryHash(path) : string.Empty
            });
        }
        return result.OrderByDescending(p => p.IsUserWritable).ThenBy(p => p.Name).ToList();
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
        _cts?.Dispose();
        Sysmon.Dispose();
    }
}
