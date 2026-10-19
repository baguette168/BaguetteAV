using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;
using BaguetteAV.EDR.Core.Rules;

namespace BaguetteAV.EDR.Core.Services;

public interface IEdrBackend : IDisposable
{
    EdrSettings Settings { get; }
    PolicyRepository Policies { get; }
    LogService Log { get; }
    ClamAvScanner ClamAv { get; }
    QuarantineService Quarantine { get; }
    ResponseEngine Response { get; }
    RootkitScanner Rootkit { get; }
    bool IsRunning { get; }
    string SysmonStatus { get; }
    long EventCount { get; }
    long BlockedCount { get; }
    int ProcessCount { get; }
    IReadOnlyList<DetectionRecord> RecentDetections { get; }
    IReadOnlyList<PolicyFixtureSample> RecentSamples { get; }
    int RecentSampleCount { get; }
    IReadOnlyList<DetectionRule> AvailableRules { get; }
    IReadOnlyList<PolicyLoadError> PolicyErrors { get; }

    event Action<DetectionRecord>? DetectionRaised;
    event Action<string>? StatusChanged;
    event Action? StateChanged;

    void Start();
    void Stop();
    void SetProtection(bool enabled);
    void ApplySettings(EdrSettings settings);
    void ReloadPolicies();
    IReadOnlyList<ProcessInfo> RefreshProcesses();
    void AppendDetection(DetectionRecord detection);
    bool ExportRecentSamples(string path, int max = 200);
}
