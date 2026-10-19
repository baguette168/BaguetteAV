using System.Text.Json;
using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;

namespace BaguetteAV.EDR.Core.Services;

public static class EdrIpc
{
    public const string PipeName = "BEDR.Local.Control";
    public const int MaxMessageBytes = 1024 * 1024;
    public static readonly JsonSerializerOptions Json = new(PolicyJson.Options) { WriteIndented = false };
}

public sealed class ControlRequest
{
    public string Command { get; set; } = string.Empty;
    public JsonElement? Payload { get; set; }
}

public sealed class ControlResponse
{
    public bool Ok { get; set; }
    public string Error { get; set; } = string.Empty;
    public JsonElement? Data { get; set; }
}

public sealed class EdrServiceStatus
{
    public bool ServiceAvailable { get; set; } = true;
    public bool IsRunning { get; set; }
    public bool ProtectionEnabled { get; set; }
    public string SysmonStatus { get; set; } = string.Empty;
    public long EventCount { get; set; }
    public long BlockedCount { get; set; }
    public int ProcessCount { get; set; }
    public int RecentSampleCount { get; set; }
    public List<DetectionRecord> RecentDetections { get; set; } = new();
    public List<PolicyLoadError> PolicyErrors { get; set; } = new();
    public List<string> RecentLogs { get; set; } = new();
}
