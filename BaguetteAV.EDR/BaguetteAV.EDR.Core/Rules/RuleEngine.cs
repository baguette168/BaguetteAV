using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Rules;

public sealed record RuleHit(DetectionRule Rule, RuleMatch Match);

public sealed class RuleEngine
{
    private readonly List<DetectionRule> _rules;
    private readonly RuleContext _context;

    public RuleEngine(IEnumerable<DetectionRule> rules, RuleContext context)
    {
        _rules = rules.ToList();
        _context = context;
    }

    public IReadOnlyList<DetectionRule> Rules => _rules;

    public IReadOnlyList<RuleHit> Evaluate(TelemetryEvent e, ProcessContext ctx)
    {
        var matches = new List<RuleHit>();
        foreach (var rule in _rules)
        {
            if (!rule.Enabled) continue;
            try
            {
                var match = rule.Evaluate(e, ctx, _context);
                if (match is not null && match.Score > 0) matches.Add(new RuleHit(rule, match));
            }
            catch
            {
                // A malformed event must never take down the protection engine.
            }
        }
        return matches;
    }

    public static int AggregateScore(IEnumerable<RuleMatch> matches) =>
        Math.Min(100, matches.Sum(m => m.Score));

    public static Severity SeverityFor(int score) => score switch
    {
        >= 30 => Severity.Critical,
        >= 18 => Severity.High,
        >= 8 => Severity.Medium,
        _ => Severity.Low
    };
}
