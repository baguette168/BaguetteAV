using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Policy;

public static class PolicySimulator
{
    public static PolicySimulationResult Simulate(PolicyPack pack, IEnumerable<(TelemetryEvent Event, ProcessContext Context)> samples)
    {
        var result = new PolicySimulationResult { SampleCount = 0 };
        foreach (var (telemetry, context) in samples)
        {
            result.SampleCount++;
            foreach (var rule in pack.Rules.Where(r => r.Enabled))
            {
                if (rule.EventKinds.Count > 0 &&
                    !rule.EventKinds.Contains(telemetry.Kind.ToString(), StringComparer.OrdinalIgnoreCase))
                    continue;
                if (PolicyConditionEvaluator.Matches(rule.Condition, telemetry, context, out var detail))
                    result.Hits.Add(new PolicySimulationHit(rule.Id, rule.Name, rule.Score, detail));
            }
        }
        return result;
    }
}
