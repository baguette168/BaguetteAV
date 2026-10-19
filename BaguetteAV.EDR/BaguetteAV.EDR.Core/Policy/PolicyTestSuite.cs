using System.Text.Json;
using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Policy;

public sealed class PolicyTestSuite
{
    public int SchemaVersion { get; set; } = 1;
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public bool Strict { get; set; }
    public List<PolicyTestCase> Cases { get; set; } = new();
}

public sealed class PolicyTestCase
{
    public string Name { get; set; } = string.Empty;
    public TelemetryEvent Event { get; set; } = new();
    public ProcessContext Process { get; set; } = new();
    public List<string> Expect { get; set; } = new();
    public List<string> Forbid { get; set; } = new();
    public bool? Strict { get; set; }
}

public sealed record PolicyTestLoadResult(
    bool Success, string Message, PolicyTestSuite? Suite);

public sealed record PolicyTestCaseResult(
    string Name,
    bool Passed,
    IReadOnlyList<string> Expected,
    IReadOnlyList<string> Actual,
    IReadOnlyList<string> Problems);

public sealed class PolicyTestRunResult
{
    public string SuiteName { get; init; } = string.Empty;
    public int CaseCount { get; init; }
    public int PassedCount { get; init; }
    public int FailedCount { get; init; }
    public List<PolicyTestCaseResult> Cases { get; init; } = new();
    public bool Success => FailedCount == 0;
}

public static class PolicyTestSuiteLoader
{
    public const int MaxBytes = 16 * 1024 * 1024;
    public const int MaxCases = 10000;

    public static PolicyTestLoadResult Load(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
                return Fail("回归测试文件不存在");
            if (info.Length > MaxBytes)
                return Fail("回归测试文件超过 16 MB 限制");
            return Parse(File.ReadAllText(path));
        }
        catch (Exception ex)
        {
            return Fail(string.Concat("读取回归测试失败：", ex.Message));
        }
    }

    public static PolicyTestLoadResult Parse(string json)
    {
        try
        {
            var suite = JsonSerializer.Deserialize<PolicyTestSuite>(
                json, PolicyJson.Options);
            if (suite is null)
                return Fail("回归测试文件为空或格式无效");
            if (suite.SchemaVersion != 1)
                return Fail("仅支持回归测试 schemaVersion = 1");
            if (suite.Cases.Count == 0)
                return Fail("回归测试至少需要一个用例");
            if (suite.Cases.Count > MaxCases)
                return Fail(string.Concat("回归测试用例不能超过 ", MaxCases));
            for (var i = 0; i < suite.Cases.Count; i++)
            {
                var testCase = suite.Cases[i];
                if (testCase.Event is null || testCase.Process is null)
                {
                    return Fail(string.Concat(
                        "用例 ", i + 1, " 缺少 event/process"));
                }
                var hasExpect = (testCase.Expect?.Count ?? 0) > 0;
                var hasForbid = (testCase.Forbid?.Count ?? 0) > 0;
                if (!hasExpect && !hasForbid &&
                    !(testCase.Strict ?? suite.Strict))
                {
                    return Fail(string.Concat(
                        "用例 ", i + 1,
                        " 未声明 expect/forbid/strict"));
                }
            }
            return new PolicyTestLoadResult(
                true,
                string.Concat("已加载 ", suite.Cases.Count, " 个回归测试用例"),
                suite);
        }
        catch (Exception ex)
        {
            return Fail(string.Concat("回归测试格式无效：", ex.Message));
        }
    }

    private static PolicyTestLoadResult Fail(string message) =>
        new(false, message, null);
}

public static class PolicyTestRunner
{
    public static PolicyTestRunResult Run(
        PolicyPack pack, PolicyTestSuite suite)
    {
        var knownRules = pack.Rules
            .Select(rule => rule.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var results = new List<PolicyTestCaseResult>();
        foreach (var testCase in suite.Cases)
            results.Add(RunCase(pack, suite, testCase, knownRules,
                results.Count));

        var failed = results.Count(result => !result.Passed);
        return new PolicyTestRunResult
        {
            SuiteName = string.IsNullOrWhiteSpace(suite.Name)
                ? "未命名回归集"
                : suite.Name,
            CaseCount = results.Count,
            PassedCount = results.Count - failed,
            FailedCount = failed,
            Cases = results
        };
    }

    private static PolicyTestCaseResult RunCase(
        PolicyPack pack,
        PolicyTestSuite suite,
        PolicyTestCase testCase,
        HashSet<string> knownRules,
        int index)
    {
        var name = string.IsNullOrWhiteSpace(testCase.Name)
            ? string.Concat("case-", index + 1)
            : testCase.Name.Trim();
        var expected = NormalizeIds(testCase.Expect);
        var forbidden = NormalizeIds(testCase.Forbid);
        var problems = new List<string>();

        foreach (var id in expected.Concat(forbidden)
            .Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!knownRules.Contains(id))
                problems.Add(string.Concat("策略包中不存在规则：", id));
        }

        var simulation = PolicySimulator.Simulate(
            pack, new[] { (testCase.Event, testCase.Process) });
        var actual = simulation.Hits
            .Select(hit => hit.RuleId)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(id => id, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var missing = expected
            .Where(id => !actual.Contains(id, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        if (missing.Length > 0)
            problems.Add(string.Concat(
                "预期命中但未命中：", string.Join(", ", missing)));

        var forbiddenHits = forbidden
            .Where(id => actual.Contains(id, StringComparer.OrdinalIgnoreCase))
            .ToArray();
        if (forbiddenHits.Length > 0)
            problems.Add(string.Concat(
                "禁止命中但命中：", string.Join(", ", forbiddenHits)));

        if (testCase.Strict ?? suite.Strict)
        {
            var allowed = expected.Concat(forbidden)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var unexpected = actual
                .Where(id => !allowed.Contains(id))
                .ToArray();
            if (unexpected.Length > 0)
                problems.Add(string.Concat(
                    "严格模式下出现未声明命中：",
                    string.Join(", ", unexpected)));
        }

        return new PolicyTestCaseResult(
            name,
            problems.Count == 0,
            expected,
            actual,
            problems);
    }

    private static IReadOnlyList<string> NormalizeIds(
        IEnumerable<string>? values) =>
        (values ?? Array.Empty<string>())
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
}
