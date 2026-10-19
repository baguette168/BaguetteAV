using System.Text.Json;
using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Policy;

public sealed class PolicyPack
{
    public int SchemaVersion { get; set; } = 1;
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Author { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string MinEngineVersion { get; set; } = "2.0.0";
    public List<string> Tags { get; set; } = new();
    public List<PolicyRule> Rules { get; set; } = new();
}

public sealed class PolicyRule
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Mitre { get; set; } = string.Empty;
    public string Severity { get; set; } = "Medium";
    public int Score { get; set; } = 10;
    public string Response { get; set; } = "inherit";
    public bool Enabled { get; set; } = true;
    public List<string> EventKinds { get; set; } = new();
    public List<string> Tags { get; set; } = new();
    public List<string> References { get; set; } = new();
    public PolicyCondition Condition { get; set; } = new();
}

public sealed class PolicyCondition
{
    public string? Field { get; set; }
    public string? Op { get; set; }
    public JsonElement? Value { get; set; }
    public bool IgnoreCase { get; set; } = true;
    public List<PolicyCondition>? All { get; set; }
    public List<PolicyCondition>? Any { get; set; }
    public PolicyCondition? Not { get; set; }
}

public sealed record PolicyValidationIssue(string Path, string Message, bool IsWarning = false);

public sealed class PolicyValidationResult
{
    public List<PolicyValidationIssue> Issues { get; } = new();
    public bool IsValid => Issues.All(i => i.IsWarning);
    public IEnumerable<string> Errors => Issues.Where(i => !i.IsWarning).Select(i => string.Concat(i.Path, ": ", i.Message));
    public IEnumerable<string> Warnings => Issues.Where(i => i.IsWarning).Select(i => string.Concat(i.Path, ": ", i.Message));

    public void Error(string path, string message) => Issues.Add(new PolicyValidationIssue(path, message));
    public void Warn(string path, string message) => Issues.Add(new PolicyValidationIssue(path, message, true));
}

public sealed class InstalledPolicy
{
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public string Author { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public int RuleCount { get; init; }
    public bool Active { get; init; }
    public bool CanRollback { get; init; }
    public DateTime ImportedAt { get; init; }
    public string Sha256 { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;
}

public sealed record PolicyLoadError(string PolicyId, string Message);

public sealed class PolicyBundle
{
    public List<PolicyPack> Packs { get; } = new();
    public List<PolicyLoadError> Errors { get; } = new();
}

public sealed record PolicySimulationHit(string RuleId, string RuleName, int Score, string Detail);

public sealed class PolicySimulationResult
{
    public int SampleCount { get; set; }
    public List<PolicySimulationHit> Hits { get; } = new();
}

public sealed record PolicyImportResult(bool Success, string Message, InstalledPolicy? Policy, PolicyValidationResult? Validation);
