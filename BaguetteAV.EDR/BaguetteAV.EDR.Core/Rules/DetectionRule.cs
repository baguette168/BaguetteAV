using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Rules;

public sealed record RuleMatch(int Score, string Detail);

public abstract class DetectionRule
{
    public abstract string Id { get; }
    public abstract string Name { get; }
    public abstract string Description { get; }
    public abstract string Mitre { get; }
    public abstract int MaxScore { get; }
    public virtual ResponseAction Response => ResponseAction.Inherit;
    public bool Enabled { get; set; } = true;
    public abstract RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc);

    protected static string FileNameOf(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return string.Empty;
        try { return Path.GetFileName(path); }
        catch { return path; }
    }
}
