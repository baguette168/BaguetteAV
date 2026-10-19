using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;
using BaguetteAV.EDR.Core.Rules;
using BaguetteAV.EDR.Core.Services;

namespace BaguetteAV.EDR.Tests;

public sealed class PolicyTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "b-edr-policy-tests", Guid.NewGuid().ToString("N"));

    private const string KernelPack = """
    {
      "schemaVersion": 1,
      "id": "research.kernel.baseline",
      "name": "内核研究基线",
      "version": "1.0.0",
      "author": "B-EDR Lab",
      "description": "针对用户目录驱动落地与脆弱驱动加载的研究策略",
      "minEngineVersion": "2.0.0",
      "tags": ["kernel", "driver"],
      "rules": [
        {
          "id": "KERNEL-001",
          "name": "用户目录驱动落地",
          "description": "检测用户可写目录中的 .sys 文件落地",
          "mitre": "T1014",
          "severity": "High",
          "score": 24,
          "eventKinds": ["FileCreate"],
          "condition": {
            "all": [
              { "field": "file.path", "op": "endswith", "value": ".sys" },
              { "field": "process.userwritable", "op": "eq", "value": "true" }
            ]
          }
        },
        {
          "id": "KERNEL-002",
          "name": "8443 外联",
          "description": "检测 8443 端口外联",
          "mitre": "T1071",
          "severity": "Critical",
          "score": 30,
          "response": "block_destination",
          "eventKinds": ["NetworkConnect"],
          "condition": {
            "any": [
              { "field": "network.destination.port", "op": "eq", "value": 8443 },
              { "field": "network.destination.port", "op": "eq", "value": 31337 }
            ]
          }
        }
      ]
    }
    """;

    [Fact]
    public void ValidatorAcceptsResearchPack()
    {
        var result = PolicyValidator.ValidateJson(KernelPack, out var pack);

        Assert.True(result.IsValid, string.Join(Environment.NewLine, result.Errors));
        Assert.NotNull(pack);
        Assert.Equal("research.kernel.baseline", pack!.Id);
        Assert.Equal(2, pack.Rules.Count);
    }

    [Fact]
    public void ValidatorRejectsUnknownOperatorAndDuplicateIds()
    {
        var json = KernelPack
            .Replace("\"op\": \"endswith\"", "\"op\": \"does-not-exist\"")
            .Replace("KERNEL-002", "KERNEL-001");

        var result = PolicyValidator.ValidateJson(json, out _);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("未知操作符", StringComparison.Ordinal));
        Assert.Contains(result.Errors, e => e.Contains("重复", StringComparison.Ordinal));
    }

    [Fact]
    public void ConditionEvaluatorMatchesFileAndNetwork()
    {
        var result = PolicyValidator.ValidateJson(KernelPack, out var pack);
        Assert.True(result.IsValid);
        var driver = pack!.Rules[0];
        var telemetry = new TelemetryEvent
        {
            Kind = TelemetryKind.FileCreate,
            ProcessId = 42,
            FilePath = @"C:\Users\Public\variantF.sys"
        };
        var context = new ProcessContext
        {
            ProcessId = 42,
            ImagePath = @"C:\Users\Public\loader.exe",
            IsUserWritable = true,
            IsSigned = false
        };

        Assert.True(PolicyConditionEvaluator.Matches(driver.Condition, telemetry, context, out var detail));
        Assert.Contains("file.path", detail, StringComparison.OrdinalIgnoreCase);

        var networkRule = pack.Rules[1];
        var network = new TelemetryEvent { Kind = TelemetryKind.NetworkConnect, DestinationIp = "192.168.127.100", DestinationPort = 8443 };
        Assert.True(PolicyConditionEvaluator.Matches(networkRule.Condition, network, context, out _));
    }

    [Fact]
    public void AdapterProducesRuleMatchForImportedPolicy()
    {
        var result = PolicyValidator.ValidateJson(KernelPack, out var pack);
        Assert.True(result.IsValid);
        var adapter = new PolicyRuleAdapter(pack!, pack!.Rules[0]);
        var telemetry = new TelemetryEvent { Kind = TelemetryKind.FileCreate, FilePath = @"C:\Users\Public\unstrip.sys" };
        var context = new ProcessContext { ImagePath = @"C:\Users\Public\unstrip.sys", IsUserWritable = true };

        var match = adapter.Evaluate(telemetry, context, new RuleContext());

        Assert.NotNull(match);
        Assert.Equal(24, match!.Score);
        Assert.Contains("内核研究基线", match.Detail, StringComparison.Ordinal);
        var networkAdapter = new PolicyRuleAdapter(pack, pack.Rules[1]);
        Assert.Equal(ResponseAction.BlockDestination, networkAdapter.Response);
    }

    [Fact]
    public void ValidatorRejectsUnknownResponseAction()
    {
        var json = KernelPack.Replace("block_destination", "launch_shell");
        var result = PolicyValidator.ValidateJson(json, out _);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("response", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidatorRejectsPolicyForNewerEngine()
    {
        var json = KernelPack.Replace("\"minEngineVersion\": \"2.0.0\"", "\"minEngineVersion\": \"99.0.0\"");
        var result = PolicyValidator.ValidateJson(json, out _);

        Assert.False(result.IsValid);
        Assert.Contains(result.Errors, e => e.Contains("minEngineVersion", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ValidatorRejectsUnknownFieldAndMixedConditionShape()
    {
        var unknownField = KernelPack.Replace("file.path", "file.typo");
        var unknownResult = PolicyValidator.ValidateJson(unknownField, out _);
        Assert.False(unknownResult.IsValid);
        Assert.Contains(unknownResult.Errors, e => e.Contains("未知字段", StringComparison.Ordinal));

        var mixed = KernelPack.Replace(
            "\"condition\": {",
            "\"condition\": {\n           \"field\": \"file.path\", \"op\": \"eq\", \"value\": \".sys\",");
        var mixedResult = PolicyValidator.ValidateJson(mixed, out _);
        Assert.False(mixedResult.IsValid);
        Assert.Contains(mixedResult.Errors, e => e.Contains("组合条件", StringComparison.Ordinal));
    }

    [Fact]
    public void ResponsePlanRequiresGlobalAutoContainAndHonorsRuleAction()
    {
        var alertOnly = ResponseEngine.ResolvePlan(ResponseAction.Contain, new EdrSettings { ResponseMode = ResponseMode.AlertOnly });
        Assert.True(alertOnly.AlertOnly);

        var settings = new EdrSettings { ResponseMode = ResponseMode.AutoContain, AutoQuarantine = true, BlockC2Endpoint = false };
        var rulePlan = ResponseEngine.ResolvePlan(ResponseAction.BlockDestination, settings);
        Assert.False(rulePlan.AlertOnly);
        Assert.False(rulePlan.Terminate);
        Assert.False(rulePlan.Quarantine);
        Assert.True(rulePlan.BlockDestination);

        var inherited = ResponseEngine.ResolvePlan(ResponseAction.Inherit, settings);
        Assert.True(inherited.Terminate);
        Assert.True(inherited.Quarantine);
        Assert.False(inherited.BlockDestination);
    }

    [Fact]
    public void FixturesRoundTripArrayAndDocumentFormats()
    {
        var samples = new[]
        {
            new PolicyFixtureSample
            {
                Event = new TelemetryEvent { Kind = TelemetryKind.NetworkConnect, DestinationPort = 8443 },
                Process = new ProcessContext { ImagePath = @"C:\Users\Public\np_rce.exe", IsUserWritable = true }
            }
        };

        var document = PolicyFixtures.Serialize(samples);
        var fromDocument = PolicyFixtures.Parse(document);
        var fromArray = PolicyFixtures.Parse("""
        [{"event":{"kind":"NetworkConnect","destinationPort":8443},"process":{"imagePath":"C:\\Users\\Public\\np_rce.exe","isUserWritable":true}}]
        """);

        Assert.True(fromDocument.Success, fromDocument.Message);
        Assert.Single(fromDocument.Samples);
        Assert.Equal(TelemetryKind.NetworkConnect, fromDocument.Samples[0].Event.Kind);
        Assert.True(fromArray.Success, fromArray.Message);
        Assert.Equal(8443, fromArray.Samples[0].Event.DestinationPort);
    }

    [Fact]
    public void RepositoryInstallsActivatesAndRollsBack()
    {
        var repository = new PolicyRepository(_root);
        var first = repository.Install(KernelPack, "test-v1.json", activate: true);
        Assert.True(first.Success, first.Message);
        Assert.Single(repository.LoadActive().Packs);

        var version2 = KernelPack.Replace("\"version\": \"1.0.0\"", "\"version\": \"1.0.1\"");
        var second = repository.Install(version2, "test-v2.json", activate: true);
        Assert.True(second.Success, second.Message);
        Assert.Equal("1.0.1", repository.LoadActive().Packs.Single().Version);

        Assert.True(repository.Rollback("research.kernel.baseline"));
        Assert.Equal("1.0.0", repository.LoadActive().Packs.Single().Version);

        var installed = repository.List();
        Assert.Equal(2, installed.Count);
        Assert.Single(installed.Where(p => p.Active));
    }

    [Fact]
    public void RepositoryRejectsTamperedInstalledPolicy()
    {
        var repository = new PolicyRepository(_root);
        var imported = repository.Install(KernelPack, "tamper-test.json", activate: true);
        Assert.True(imported.Success, imported.Message);

        var policyPath = Path.Combine(_root, "installed", "research.kernel.baseline", "1.0.0", "policy.json");
        File.WriteAllText(policyPath, KernelPack.Replace("\"score\": 24", "\"score\": 99"));

        var loaded = repository.LoadActive();

        Assert.Empty(loaded.Packs);
        Assert.Contains(loaded.Errors, e => e.Message.Contains("完整性", StringComparison.Ordinal));
    }

    [Fact]
    public void RepositoryRejectsPathTraversalVersion()
    {
        var repository = new PolicyRepository(_root);
        var imported = repository.Install(KernelPack, "path-test.json", activate: true);
        Assert.True(imported.Success, imported.Message);

        Assert.False(repository.SetActive("research.kernel.baseline", @"..\..\outside"));
        Assert.False(repository.Remove("research.kernel.baseline", @"..\..\outside"));
        Assert.Empty(repository.LoadActive().Errors);
    }

    [Fact]
    public void SimulatorReportsOnlyMatchingSamples()
    {
        var result = PolicyValidator.ValidateJson(KernelPack, out var pack);
        Assert.True(result.IsValid);
        var samples = new[]
        {
            (new TelemetryEvent { Kind = TelemetryKind.FileCreate, FilePath = @"C:\Users\Public\a.sys" },
                new ProcessContext { ImagePath = @"C:\Users\Public\a.sys", IsUserWritable = true }),
            (new TelemetryEvent { Kind = TelemetryKind.FileCreate, FilePath = @"C:\Windows\System32\drivers\safe.sys" },
                new ProcessContext { ImagePath = @"C:\Windows\System32\drivers\safe.sys", IsUserWritable = false })
        };

        var simulation = PolicySimulator.Simulate(pack!, samples);

        Assert.Equal(2, simulation.SampleCount);
        Assert.Single(simulation.Hits);
        Assert.Equal("KERNEL-001", simulation.Hits[0].RuleId);
    }

    [Fact]
    public void RuntimeLoadsActivePolicyIntoRuleEngine()
    {
        var repository = new PolicyRepository(_root);
        var imported = repository.Install(KernelPack, "runtime-test.json", activate: true);
        Assert.True(imported.Success, imported.Message);

        using var runtime = new EdrRuntime(repository);

        Assert.Contains(runtime.AvailableRules, r => r.Id == "KERNEL-001");
        Assert.Contains(runtime.AvailableRules, r => r.Id == "KERNEL-002");
        Assert.Empty(runtime.PolicyErrors);
    }

    [Fact]
    public void TestSuitePassesPositiveAndStrictNegativeCases()
    {
        var validation = PolicyValidator.ValidateJson(KernelPack, out var pack);
        Assert.True(validation.IsValid);
        var suite = new PolicyTestSuite { Name = "kernel-regression" };
        suite.Cases.Add(new PolicyTestCase
        {
            Name = "driver drop",
            Expect = new List<string> { "KERNEL-001" },
            Event = new TelemetryEvent
            {
                Kind = TelemetryKind.FileCreate,
                FilePath = @"C:\Users\Public\dropper.sys"
            },
            Process = new ProcessContext
            {
                ImagePath = @"C:\Users\Public\dropper.exe",
                IsUserWritable = true
            }
        });
        suite.Cases.Add(new PolicyTestCase
        {
            Name = "benign driver",
            Strict = true,
            Event = new TelemetryEvent
            {
                Kind = TelemetryKind.FileCreate,
                FilePath = @"C:\Windows\System32\drivers\disk.sys"
            },
            Process = new ProcessContext
            {
                ImagePath = @"C:\Windows\System32\drivers\disk.sys"
            }
        });

        var result = PolicyTestRunner.Run(pack!, suite);

        Assert.True(result.Success);
        Assert.Equal(2, result.PassedCount);
        Assert.Equal(0, result.FailedCount);
    }

    [Fact]
    public void TestSuiteReportsMissingExpectedRule()
    {
        var validation = PolicyValidator.ValidateJson(KernelPack, out var pack);
        Assert.True(validation.IsValid);
        var suite = new PolicyTestSuite();
        suite.Cases.Add(new PolicyTestCase
        {
            Name = "wrong expectation",
            Expect = new List<string> { "KERNEL-002" },
            Event = new TelemetryEvent
            {
                Kind = TelemetryKind.FileCreate,
                FilePath = @"C:\Users\Public\dropper.sys"
            },
            Process = new ProcessContext
            {
                ImagePath = @"C:\Users\Public\dropper.exe",
                IsUserWritable = true
            }
        });

        var result = PolicyTestRunner.Run(pack!, suite);

        Assert.False(result.Success);
        Assert.Contains(result.Cases[0].Problems,
            problem => problem.Contains("预期命中但未命中"));
    }

    [Fact]
    public void TestSuiteRejectsUnknownRuleReference()
    {
        var validation = PolicyValidator.ValidateJson(KernelPack, out var pack);
        Assert.True(validation.IsValid);
        var suite = new PolicyTestSuite();
        suite.Cases.Add(new PolicyTestCase
        {
            Name = "typo",
            Expect = new List<string> { "KERNEL-999" },
            Event = new TelemetryEvent { Kind = TelemetryKind.FileCreate },
            Process = new ProcessContext()
        });

        var result = PolicyTestRunner.Run(pack!, suite);

        Assert.False(result.Success);
        Assert.Contains(result.Cases[0].Problems,
            problem => problem.Contains("不存在规则"));
    }

    [Fact]
    public void CoverageAggregatesTechniquesAndDuplicates()
    {
        var validation = PolicyValidator.ValidateJson(KernelPack, out var pack);
        Assert.True(validation.IsValid);
        var duplicate = new PolicyPack
        {
            Id = "research.kernel.duplicate",
            Rules = pack!.Rules
        };

        var report = PolicyCoverageAnalyzer.Analyze(
            new[] { pack, duplicate });

        Assert.Equal(4, report.RuleCount);
        Assert.Equal(4, report.MappedRuleCount);
        Assert.Equal(0, report.UnmappedRuleCount);
        Assert.Contains("T1014", report.Techniques.Keys);
        Assert.Equal(2, report.DuplicateRuleIds.Count);
        Assert.Contains("# B-EDR 策略覆盖报告",
            PolicyCoverageAnalyzer.ToMarkdown(report));
    }

    [Fact]
    public void InstallRejectsChangedContentForExistingVersion()
    {
        var repository = new PolicyRepository(_root);
        Assert.True(repository.Install(KernelPack, "first.json", activate: true).Success);

        var changed = KernelPack.Replace("\"score\": 24", "\"score\": 25");
        var second = repository.Install(changed, "second.json", activate: true);

        Assert.False(second.Success);
        Assert.Contains(second.Validation!.Errors,
            error => error.Contains("不可变") || error.Contains("提升版本"));
    }

    [Fact]
    public void InstallRejectsRuleIdConflictAcrossPolicies()
    {
        var repository = new PolicyRepository(_root);
        Assert.True(repository.Install(KernelPack, "first.json", activate: true).Success);
        var conflicting = KernelPack
            .Replace("research.kernel.baseline", "research.kernel.other")
            .Replace("KERNEL-002", "KERNEL-003");

        var result = repository.Install(conflicting, "conflict.json", activate: true);

        Assert.False(result.Success);
        Assert.Contains(result.Validation!.Errors,
            error => error.Contains("KERNEL-001") && error.Contains("冲突"));
    }

    [Fact]
    public void InstallWritesAuditTrail()
    {
        var repository = new PolicyRepository(_root);
        var result = repository.Install(KernelPack, "audit.json", activate: true);

        Assert.True(result.Success, result.Message);
        Assert.True(File.Exists(repository.AuditPath));
        var audit = File.ReadAllText(repository.AuditPath);
        Assert.Contains("\"action\":\"install\"", audit);
        Assert.Contains("research.kernel.baseline", audit);
    }

    [Fact]
    public void InstallFailsClosedWhenAuditTrailIsNotWritable()
    {
        var repository = new PolicyRepository(_root);
        Directory.CreateDirectory(repository.AuditPath);

        var result = repository.Install(KernelPack, "fail-closed.json", activate: true);

        Assert.False(result.Success);
        Assert.Contains("审计日志不可写", result.Message);
        Assert.False(Directory.Exists(Path.Combine(
            repository.InstalledDirectory, "research.kernel.baseline", "1.0.0")));
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_root)) Directory.Delete(_root, true); } catch { }
    }
}
