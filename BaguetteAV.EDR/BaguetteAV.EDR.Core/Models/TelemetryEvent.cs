namespace BaguetteAV.EDR.Core.Models;

public enum TelemetryKind
{
    Unknown = 0,
    ProcessCreate,
    NetworkConnect,
    DriverLoad,
    FileCreate,
    WmiFilter,
    WmiConsumer,
    WmiBinding,
    RemoteThread,
    ProcessAccess
}

public sealed class TelemetryEvent
{
    public TelemetryKind Kind { get; init; }
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public int EventId { get; init; }
    public int ProcessId { get; init; }
    public int ParentProcessId { get; init; }
    public string Image { get; init; } = string.Empty;
    public string ParentImage { get; init; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;
    public string User { get; init; } = string.Empty;
    public string IntegrityLevel { get; init; } = string.Empty;
    public string Hashes { get; init; } = string.Empty;
    public int TargetProcessId { get; init; }
    public string TargetImage { get; init; } = string.Empty;
    public string GrantedAccess { get; init; } = string.Empty;
    public string Source { get; init; } = "sysmon";
    public IReadOnlyDictionary<string, string> Fields { get; init; } = new Dictionary<string, string>();

    public string DestinationIp { get; init; } = string.Empty;
    public int DestinationPort { get; init; }
    public string DestinationHost { get; init; } = string.Empty;
    public string Protocol { get; init; } = string.Empty;
    public string FilePath { get; init; } = string.Empty;
    public string DriverPath { get; init; } = string.Empty;
    public string WmiName { get; init; } = string.Empty;
    public string WmiQuery { get; init; } = string.Empty;
    public string WmiConsumerType { get; init; } = string.Empty;
    public string WmiDestination { get; init; } = string.Empty;

    public string EffectiveFile => !string.IsNullOrWhiteSpace(DriverPath) ? DriverPath
        : !string.IsNullOrWhiteSpace(FilePath) ? FilePath
        : Image;

    public override string ToString() => string.Format("{0} pid={1} image={2}", Kind, ProcessId, Image);
}
