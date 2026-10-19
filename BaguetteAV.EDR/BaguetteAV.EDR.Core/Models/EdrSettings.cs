namespace BaguetteAV.EDR.Core.Models;

public enum ResponseMode
{
    AlertOnly = 0,
    AutoContain = 1
}

public sealed class EdrSettings
{
    public bool ProtectionEnabled { get; set; } = true;
    public ResponseMode ResponseMode { get; set; } = ResponseMode.AlertOnly;
    public bool AutoQuarantine { get; set; } = true;
    public bool BlockC2Endpoint { get; set; }
    public bool MonitorNetwork { get; set; } = true;
    public bool MonitorDrivers { get; set; } = true;
    public bool MonitorWmi { get; set; } = true;
    public bool MonitorFileCreation { get; set; }
    public bool StartWithWindows { get; set; }
    public bool MinimizeToTray { get; set; } = true;
    public int RetentionDays { get; set; } = 30;
    public int MaxDetectionsInMemory { get; set; } = 5000;
    public int EventQueueCapacity { get; set; } = 20000;
    public string QuarantinePath { get; set; } = string.Empty;
    public string ClamAvPath { get; set; } = string.Empty;
    public string ScanPath { get; set; } = string.Empty;
    public List<int> MonitoredPorts { get; set; } = new() { 8443 };
    public List<string> IocHashes { get; set; } = new();
    public List<string> DisabledRuleIds { get; set; } = new();

    public EdrSettings Clone()
    {
        var copy = (EdrSettings)MemberwiseClone();
        copy.MonitoredPorts = new List<int>(MonitoredPorts);
        copy.IocHashes = new List<string>(IocHashes);
        copy.DisabledRuleIds = new List<string>(DisabledRuleIds);
        return copy;
    }
}
