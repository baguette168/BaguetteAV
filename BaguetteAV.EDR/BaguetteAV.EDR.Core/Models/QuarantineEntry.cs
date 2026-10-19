namespace BaguetteAV.EDR.Core.Models;

public sealed class QuarantineEntry
{
    public Guid Id { get; init; } = Guid.NewGuid();
    public DateTime QuarantinedAt { get; init; } = DateTime.Now;
    public string OriginalPath { get; init; } = string.Empty;
    public string StoredPath { get; init; } = string.Empty;
    public string Sha256 { get; init; } = string.Empty;
    public string RuleName { get; init; } = string.Empty;
    public long Size { get; init; }
    public bool OriginalRemoved { get; init; }
    public bool Deleted { get; init; }
    public string FileName => System.IO.Path.GetFileName(OriginalPath);
    public string TimeText => QuarantinedAt.ToString("MM-dd HH:mm:ss");
}
