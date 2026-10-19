using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;
using BaguetteAV.EDR.Core.Rules;

namespace BaguetteAV.EDR.Core.Services;

public sealed class LocalEdrBackend : IEdrBackend
{
    private readonly EdrRuntime _runtime;

    public LocalEdrBackend(EdrRuntime runtime)
    {
        _runtime = runtime;
        _runtime.DetectionRaised += OnDetection;
        _runtime.StatusChanged += OnStatus;
        _runtime.StateChanged += OnState;
    }

    public EdrSettings Settings => _runtime.Settings;
    public PolicyRepository Policies => _runtime.Policies;
    public LogService Log => _runtime.Log;
    public ClamAvScanner ClamAv => _runtime.ClamAv;
    public QuarantineService Quarantine => _runtime.Quarantine;
    public ResponseEngine Response => _runtime.Response;
    public RootkitScanner Rootkit => _runtime.Rootkit;
    public bool IsRunning => _runtime.IsRunning;
    public string SysmonStatus => _runtime.SysmonStatus;
    public long EventCount => _runtime.EventCount;
    public long BlockedCount => _runtime.BlockedCount;
    public int ProcessCount => _runtime.ProcessCount;
    public IReadOnlyList<DetectionRecord> RecentDetections => _runtime.RecentDetections;
    public IReadOnlyList<PolicyFixtureSample> RecentSamples => _runtime.RecentSamples;
    public int RecentSampleCount => _runtime.RecentSamples.Count;
    public IReadOnlyList<DetectionRule> AvailableRules => _runtime.AvailableRules;
    public IReadOnlyList<PolicyLoadError> PolicyErrors => _runtime.PolicyErrors;

    public event Action<DetectionRecord>? DetectionRaised;
    public event Action<string>? StatusChanged;
    public event Action? StateChanged;

    public void Start() => _runtime.Start();
    public void Stop() => _runtime.Stop();
    public void SetProtection(bool enabled) => _runtime.SetProtection(enabled);
    public void ApplySettings(EdrSettings settings) => _runtime.ApplySettings(settings);
    public void ReloadPolicies() => _runtime.ReloadPolicies();
    public IReadOnlyList<ProcessInfo> RefreshProcesses() => _runtime.RefreshProcesses();
    public void AppendDetection(DetectionRecord detection) => _runtime.UpdateDetection(detection);
    public bool ExportRecentSamples(string path, int max = 200) => _runtime.ExportRecentSamples(path, max);

    private void OnDetection(DetectionRecord detection) => DetectionRaised?.Invoke(detection);
    private void OnStatus(string status) => StatusChanged?.Invoke(status);
    private void OnState() => StateChanged?.Invoke();

    public void Dispose()
    {
        _runtime.DetectionRaised -= OnDetection;
        _runtime.StatusChanged -= OnStatus;
        _runtime.StateChanged -= OnState;
        _runtime.Dispose();
    }
}
