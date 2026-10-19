using System.Text;
using System.Text.RegularExpressions;

namespace BaguetteAV.EDR.Core.Policy;

public sealed class PolicyCoverageRule
{
    public string PackId { get; init; } = string.Empty;
    public string RuleId { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Mitre { get; init; } = string.Empty;
    public string Severity { get; init; } = string.Empty;
    public string Response { get; init; } = string.Empty;
    public List<string> EventKinds { get; init; } = new();
    public IReadOnlyList<string> Techniques { get; init; } =
        Array.Empty<string>();
}

public sealed class PolicyCoverageReport
{
    public int PackCount { get; init; }
    public int RuleCount { get; init; }
    public int EnabledRuleCount { get; init; }
    public int MappedRuleCount { get; init; }
    public int UnmappedRuleCount => RuleCount - MappedRuleCount;
    public SortedDictionary<string, int> Techniques { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);
    public SortedDictionary<string, int> EventKinds { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);
    public SortedDictionary<string, int> Severities { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);
    public SortedDictionary<string, int> Responses { get; init; } =
        new(StringComparer.OrdinalIgnoreCase);
    public List<PolicyCoverageRule> Rules { get; init; } = new();
    public List<string> DuplicateRuleIds { get; init; } = new();
    public List<PolicyLoadError> LoadErrors { get; init; } = new();

    public string Summary => RuleCount == 0
        ? "尚未启用策略包"
        : string.Concat(
            RuleCount, " 条活动规则 · ",
            Techniques.Count, " 个 ATT&CK 技术 · ",
            EventKinds.Count, " 类遥测 · ",
            UnmappedRuleCount, " 条未标注技术");
}

public static partial class PolicyCoverageAnalyzer
{
    [GeneratedRegex(@"T\d{4}(?:\.\d{3})?",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex TechniquePattern();

    public static PolicyCoverageReport Analyze(
        IEnumerable<PolicyPack> packs,
        IEnumerable<PolicyLoadError>? errors = null)
    {
        var packList = packs.ToList();
        var techniques = new SortedDictionary<string, int>(
            StringComparer.OrdinalIgnoreCase);
        var eventKinds = new SortedDictionary<string, int>(
            StringComparer.OrdinalIgnoreCase);
        var severities = new SortedDictionary<string, int>(
            StringComparer.OrdinalIgnoreCase);
        var responses = new SortedDictionary<string, int>(
            StringComparer.OrdinalIgnoreCase);
        var rules = new List<PolicyCoverageRule>();
        var mapped = 0;
        var enabled = 0;

        foreach (var pack in packList)
        {
            foreach (var rule in pack.Rules)
            {
                if (rule.Enabled) enabled++;
                var ids = TechniquePattern()
                    .Matches(rule.Mitre ?? string.Empty)
                    .Select(match => match.Value.ToUpperInvariant())
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToArray();
                if (ids.Length > 0) mapped++;
                foreach (var id in ids) Increment(techniques, id);

                var kinds = rule.EventKinds.Count == 0
                    ? new List<string> { "Unspecified" }
                    : rule.EventKinds.ToList();
                foreach (var kind in kinds)
                    Increment(eventKinds, kind);
                Increment(severities, rule.Severity);
                Increment(responses, rule.Response);

                rules.Add(new PolicyCoverageRule
                {
                    PackId = pack.Id,
                    RuleId = rule.Id,
                    Name = rule.Name,
                    Mitre = rule.Mitre ?? string.Empty,
                    Severity = rule.Severity,
                    Response = rule.Response,
                    EventKinds = kinds,
                    Techniques = ids
                });
            }
        }

        var duplicates = rules
            .GroupBy(rule => rule.RuleId, StringComparer.OrdinalIgnoreCase)
            .Where(group => group.Count() > 1)
            .Select(group => group.Key)
            .OrderBy(id => id, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new PolicyCoverageReport
        {
            PackCount = packList.Count,
            RuleCount = rules.Count,
            EnabledRuleCount = enabled,
            MappedRuleCount = mapped,
            Techniques = techniques,
            EventKinds = eventKinds,
            Severities = severities,
            Responses = responses,
            Rules = rules,
            DuplicateRuleIds = duplicates,
            LoadErrors = (errors ?? Array.Empty<PolicyLoadError>()).ToList()
        };
    }

    private static void Increment(
        IDictionary<string, int> values, string key)
    {
        var normalized = string.IsNullOrWhiteSpace(key)
            ? "Unknown"
            : key.Trim();
        values[normalized] = values.TryGetValue(normalized, out var count)
            ? count + 1
            : 1;
    }

    public static string ToMarkdown(
        PolicyCoverageReport report, DateTime? generatedAt = null)
    {
        var builder = new StringBuilder();
        builder.AppendLine("# B-EDR 策略覆盖报告");
        builder.AppendLine();
        builder.AppendLine(string.Concat(
            "- 生成时间：",
            (generatedAt ?? DateTime.Now).ToString("yyyy-MM-dd HH:mm:ss")));
        builder.AppendLine(string.Concat(
            "- 策略包：", report.PackCount));
        builder.AppendLine(string.Concat(
            "- 规则：", report.RuleCount,
            "（启用 ", report.EnabledRuleCount, "）"));
        builder.AppendLine(string.Concat(
            "- ATT&CK 已标注：", report.MappedRuleCount,
            "；未标注：", report.UnmappedRuleCount));
        builder.AppendLine();
        AppendTable(builder, "ATT&CK 技术分布", report.Techniques);
        AppendTable(builder, "遥测事件分布", report.EventKinds);
        AppendTable(builder, "严重级别分布", report.Severities);
        AppendTable(builder, "响应动作分布", report.Responses);

        builder.AppendLine("## 未标注 ATT&CK 的规则");
        builder.AppendLine();
        var unmapped = report.Rules
            .Where(rule => rule.Techniques.Count == 0)
            .ToList();
        if (unmapped.Count == 0) builder.AppendLine("无。");
        foreach (var rule in unmapped)
        {
            builder.AppendLine(string.Concat(
                "- `", rule.RuleId, "` ", rule.Name,
                "（", rule.PackId, "）"));
        }
        builder.AppendLine();

        builder.AppendLine("## 重复规则 ID");
        builder.AppendLine();
        if (report.DuplicateRuleIds.Count == 0)
            builder.AppendLine("无。");
        foreach (var id in report.DuplicateRuleIds)
            builder.AppendLine(string.Concat("- `", id, "`"));
        builder.AppendLine();

        builder.AppendLine("## 加载错误");
        builder.AppendLine();
        if (report.LoadErrors.Count == 0)
            builder.AppendLine("无。");
        foreach (var error in report.LoadErrors)
        {
            builder.AppendLine(string.Concat(
                "- ", error.PolicyId, "：", error.Message));
        }
        return builder.ToString();
    }

    private static void AppendTable(
        StringBuilder builder,
        string title,
        IEnumerable<KeyValuePair<string, int>> values)
    {
        builder.AppendLine(string.Concat("## ", title));
        builder.AppendLine();
        builder.AppendLine("| 名称 | 规则数 |");
        builder.AppendLine("|---|---:|");
        foreach (var pair in values)
        {
            builder.AppendLine(string.Concat(
                "| ", pair.Key, " | ", pair.Value, " |"));
        }
        builder.AppendLine();
    }
}
