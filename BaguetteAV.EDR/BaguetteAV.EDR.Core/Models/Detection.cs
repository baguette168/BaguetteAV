namespace BaguetteAV.EDR.Core.Models;

public enum Severity
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

public sealed class DetectionRecord
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public string RuleId { get; init; } = string.Empty;
    public string RuleName { get; init; } = string.Empty;
    public string Mitre { get; init; } = string.Empty;
    public int Score { get; init; }
    public Severity Severity { get; init; }
    public string Description { get; init; } = string.Empty;
    public int ProcessId { get; init; }
    public string ProcessName { get; init; } = string.Empty;
    public string ImagePath { get; init; } = string.Empty;
    public string ParentName { get; init; } = string.Empty;
    public string CommandLine { get; init; } = string.Empty;
    public string User { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public string Destination { get; init; } = string.Empty;
    public string Action { get; set; } = "仅告警";
    public bool IsFalsePositive { get; set; }
    public bool Acknowledged { get; set; }

    public string SeverityText => Severity switch
    {
        Severity.Critical => "严重",
        Severity.High => "高危",
        Severity.Medium => "中危",
        _ => "低危"
    };

    public string TimeText => Timestamp.ToString("MM-dd HH:mm:ss");
}
