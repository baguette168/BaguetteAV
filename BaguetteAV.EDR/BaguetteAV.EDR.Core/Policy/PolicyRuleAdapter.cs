using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Rules;

namespace BaguetteAV.EDR.Core.Policy;

public sealed class PolicyRuleAdapter : DetectionRule
{
    private readonly PolicyPack _pack;
    private readonly PolicyRule _policyRule;

    public PolicyRuleAdapter(PolicyPack pack, PolicyRule rule)
    {
        _pack = pack;
        _policyRule = rule;
    }

    public override string Id => _policyRule.Id;
    public override string Name => _policyRule.Name;
    public override string Description => _policyRule.Description;
    public override string Mitre => _policyRule.Mitre;
    public override int MaxScore => _policyRule.Score;
    public string PackId => _pack.Id;
    public string PackName => _pack.Name;
    public string PackVersion => _pack.Version;
    public override ResponseAction Response => ParseResponse(_policyRule.Response);

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (!_policyRule.Enabled) return null;
        if (_policyRule.EventKinds.Count > 0 &&
            !_policyRule.EventKinds.Contains(e.Kind.ToString(), StringComparer.OrdinalIgnoreCase))
            return null;
        if (!PolicyConditionEvaluator.Matches(_policyRule.Condition, e, ctx, out var detail))
            return null;
        return new RuleMatch(_policyRule.Score,
            string.Concat("[", _pack.Name, "/", _policyRule.Name, "] ", detail));
    }

    public static ResponseAction ParseResponse(string? value) => (value ?? string.Empty).Trim().ToLowerInvariant() switch
    {
        "alert" => ResponseAction.Alert,
        "terminate" or "terminate_process" => ResponseAction.TerminateProcess,
        "quarantine" or "quarantine_file" => ResponseAction.QuarantineFile,
        "block" or "block_destination" => ResponseAction.BlockDestination,
        "contain" => ResponseAction.Contain,
        _ => ResponseAction.Inherit
    };
}
