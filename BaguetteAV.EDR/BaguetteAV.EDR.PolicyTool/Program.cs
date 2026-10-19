using System.Text;
using System.Text.Json;
using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;
using BaguetteAV.EDR.Core.Services;

namespace BaguetteAV.EDR.PolicyTool;

internal static class Program
{
    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
        {
            PrintHelp();
            return 0;
        }

        var command = args[0].ToLowerInvariant();
        var rest = args.Skip(1).ToList();
        var root = TakeOption(rest, "--root");
        var pluginRoot = TakeOption(rest, "--plugin-root");
        var json = rest.Remove("--json");
        var repository = new PolicyRepository(root);
        var mutating = command is "install" or "activate" or "deactivate" or "rollback" or "remove" or "trust-plugin";
        if (root is null && (command != "trust-plugin" || pluginRoot is null) && mutating &&
            !DataDirectorySecurity.TryHarden(SettingsStore.DataDirectory, out var aclError))
        {
            Console.Error.WriteLine(string.Concat("数据目录权限加固失败，拒绝写入策略或插件信任清单：", aclError));
            return 2;
        }
        try
        {
            return command switch
            {
                "validate" => Validate(rest, json),
                "install" => Install(repository, rest, json),
                "list" => List(repository, json),
                "activate" => Activate(repository, rest),
                "deactivate" => Deactivate(repository, rest),
                "rollback" => Rollback(repository, rest),
                "remove" => Remove(repository, rest),
                "simulate" => Simulate(rest, json),
                "test" => Test(rest, json),
                "coverage" => Coverage(repository, rest, json),
                "plugins" => Plugins(new PluginLoader(pluginRoot), json),
                "trust-plugin" => TrustPlugin(new PluginLoader(pluginRoot), rest),
                "fields" => Fields(json),
                "example" => Example(),
                _ => Unknown(command)
            };
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(string.Concat("错误：", ex.Message));
            return 1;
        }
    }

    private static int Validate(List<string> args, bool json)
    {
        if (args.Count != 1) return Usage("validate <policy.json>");
        var source = File.ReadAllText(args[0]);
        var result = PolicyValidator.ValidateJson(source, out var pack);
        if (json)
        {
            WriteJson(new { valid = result.IsValid, errors = result.Errors, warnings = result.Warnings, policy = pack });
        }
        else
        {
            PrintValidation(result);
            if (pack is not null)
                Console.WriteLine($"策略：{pack.Name} ({pack.Id} v{pack.Version})，规则 {pack.Rules.Count} 条");
        }
        return result.IsValid ? 0 : 2;
    }

    private static int Install(PolicyRepository repository, List<string> args, bool json)
    {
        var activate = !args.Remove("--no-activate");
        if (args.Count != 1) return Usage("install <policy.json> [--no-activate]");
        var result = repository.InstallFromFile(args[0], activate);
        if (json) WriteJson(result);
        else
        {
            Console.WriteLine(result.Message);
            if (result.Validation is not null) PrintValidation(result.Validation);
            if (result.Policy is not null)
                Console.WriteLine($"已安装：{result.Policy.Name} ({result.Policy.Id} v{result.Policy.Version})，{result.Policy.RuleCount} 条规则");
        }
        return result.Success ? 0 : 2;
    }

    private static int List(PolicyRepository repository, bool json)
    {
        var installed = repository.List();
        if (json) { WriteJson(installed); return 0; }
        if (installed.Count == 0) { Console.WriteLine("尚未安装策略包"); return 0; }
        foreach (var policy in installed)
            Console.WriteLine($"{(policy.Active ? "*" : " ")} {policy.Name}  {policy.Id} v{policy.Version}  规则={policy.RuleCount}  导入={policy.ImportedAt:yyyy-MM-dd HH:mm:ss}  sha256={policy.Sha256[..12]}");
        return 0;
    }

    private static int Activate(PolicyRepository repository, List<string> args)
    {
        if (args.Count != 2) return Usage("activate <policy-id> <version>");
        var ok = repository.SetActive(args[0], args[1]);
        Console.WriteLine(ok ? "已启用" : "启用失败：策略或版本不存在");
        return ok ? 0 : 2;
    }

    private static int Deactivate(PolicyRepository repository, List<string> args)
    {
        if (args.Count != 1) return Usage("deactivate <policy-id>");
        var ok = repository.SetActive(args[0], null);
        Console.WriteLine(ok ? "已停用" : "停用失败：策略不存在");
        return ok ? 0 : 2;
    }

    private static int Rollback(PolicyRepository repository, List<string> args)
    {
        if (args.Count != 1) return Usage("rollback <policy-id>");
        var ok = repository.Rollback(args[0]);
        Console.WriteLine(ok ? "已回滚到上一版本" : "回滚失败：没有可用历史版本");
        return ok ? 0 : 2;
    }

    private static int Remove(PolicyRepository repository, List<string> args)
    {
        if (args.Count != 2) return Usage("remove <policy-id> <version>");
        var ok = repository.Remove(args[0], args[1]);
        Console.WriteLine(ok ? "已删除" : "删除失败：策略正在使用或不存在");
        return ok ? 0 : 2;
    }

    private static int Simulate(List<string> args, bool json)
    {
        var failOnHit = args.Remove("--fail-on-hit");
        if (args.Count != 2) return Usage("simulate <policy.json> <events.json> [--fail-on-hit]");
        var validation = PolicyValidator.ValidateJson(File.ReadAllText(args[0]), out var pack);
        if (pack is null || !validation.IsValid)
        {
            PrintValidation(validation);
            return 2;
        }
        var fixture = PolicyFixtures.Load(args[1]);
        if (!fixture.Success)
        {
            Console.Error.WriteLine(fixture.Message);
            return 2;
        }
        var result = PolicySimulator.Simulate(pack, fixture.Samples.Select(s => (s.Event, s.Process)));
        if (json)
        {
            WriteJson(result);
        }
        else
        {
            Console.WriteLine($"样本 {result.SampleCount} 个，命中 {result.Hits.Count} 次");
            foreach (var hit in result.Hits)
                Console.WriteLine($"  [{hit.RuleId}] {hit.RuleName} score={hit.Score} {hit.Detail}");
        }
        return failOnHit && result.Hits.Count > 0 ? 3 : 0;
    }

    private static int Test(List<string> args, bool json)
    {
        if (args.Count != 2)
            return Usage("test <policy.json> <tests.json> [--json]");
        var source = File.ReadAllText(args[0]);
        var validation = PolicyValidator.ValidateJson(source, out var pack);
        if (pack is null || !validation.IsValid)
        {
            PrintValidation(validation);
            return 2;
        }
        var loaded = PolicyTestSuiteLoader.Load(args[1]);
        if (!loaded.Success || loaded.Suite is null)
        {
            Console.Error.WriteLine(loaded.Message);
            return 2;
        }
        var result = PolicyTestRunner.Run(pack, loaded.Suite);
        if (json)
        {
            WriteJson(result);
        }
        else
        {
            Console.WriteLine(string.Concat(
                "回归集：", result.SuiteName));
            Console.WriteLine(string.Concat(
                "用例 ", result.CaseCount, " 个，通过 ",
                result.PassedCount, "，失败 ", result.FailedCount));
            foreach (var testCase in result.Cases)
            {
                var status = testCase.Passed ? "PASS" : "FAIL";
                Console.WriteLine(string.Concat(
                    "  [", status, "] ", testCase.Name));
                foreach (var problem in testCase.Problems)
                    Console.WriteLine(string.Concat("         ", problem));
                if (!testCase.Passed)
                {
                    var actual = testCase.Actual.Count == 0
                        ? "无"
                        : string.Join(", ", testCase.Actual);
                    Console.WriteLine(string.Concat(
                        "         实际命中：", actual));
                }
            }
        }
        return result.Success ? 0 : 3;
    }

    private static int Coverage(
        PolicyRepository repository,
        List<string> args,
        bool json)
    {
        var markdown = args.Remove("--markdown");
        var policyPath = TakeOption(args, "--policy");
        if (args.Count != 0)
        {
            return Usage(
                "coverage [--policy <policy.json>] [--json|--markdown]");
        }
        PolicyCoverageReport report;
        if (!string.IsNullOrWhiteSpace(policyPath))
        {
            var validation = PolicyValidator.ValidateJson(
                File.ReadAllText(policyPath), out var pack);
            if (pack is null || !validation.IsValid)
            {
                PrintValidation(validation);
                return 2;
            }
            report = PolicyCoverageAnalyzer.Analyze(new[] { pack });
        }
        else
        {
            var bundle = repository.LoadActive();
            report = PolicyCoverageAnalyzer.Analyze(
                bundle.Packs, bundle.Errors);
        }

        if (json)
        {
            WriteJson(report);
        }
        else if (markdown)
        {
            Console.WriteLine(
                PolicyCoverageAnalyzer.ToMarkdown(report));
        }
        else
        {
            Console.WriteLine(report.Summary);
            Console.WriteLine(string.Concat(
                "策略包 ", report.PackCount,
                " 个，规则 ", report.RuleCount,
                " 条，启用 ", report.EnabledRuleCount, " 条"));
            Console.WriteLine("ATT&CK 技术：");
            foreach (var pair in report.Techniques)
                Console.WriteLine(string.Concat(
                    "  ", pair.Key, "  ", pair.Value));
            Console.WriteLine("遥测事件：");
            foreach (var pair in report.EventKinds)
                Console.WriteLine(string.Concat(
                    "  ", pair.Key, "  ", pair.Value));
            if (report.UnmappedRuleCount > 0)
                Console.WriteLine(string.Concat(
                    "未标注 ATT&CK：", report.UnmappedRuleCount, " 条"));
            if (report.DuplicateRuleIds.Count > 0)
            {
                Console.WriteLine(string.Concat(
                    "重复规则 ID：",
                    string.Join(", ", report.DuplicateRuleIds)));
            }
            if (report.LoadErrors.Count > 0)
                Console.WriteLine(string.Concat(
                    "加载错误：", report.LoadErrors.Count, " 个"));
        }
        return 0;
    }

    private static int Fields(bool json)
    {
        if (json) { WriteJson(PolicyFields.KnownFields); return 0; }
        foreach (var field in PolicyFields.KnownFields) Console.WriteLine(field);
        return 0;
    }

    private static int Plugins(PluginLoader loader, bool json)
    {
        var result = loader.Load();
        if (json)
        {
            WriteJson(new { descriptors = result.Descriptors, errors = result.Errors });
            return result.Errors.Count == 0 ? 0 : 2;
        }
        if (result.Descriptors.Count == 0) Console.WriteLine("未加载受信任插件");
        foreach (var plugin in result.Descriptors)
            Console.WriteLine($"* {plugin.Name} ({plugin.Id} v{plugin.Version}) 策略包={plugin.PolicyCount} 自定义规则={plugin.RuleCount} sha256={plugin.Sha256[..12]}");
        foreach (var error in result.Errors) Console.Error.WriteLine($"ERROR {error.PolicyId}: {error.Message}");
        return result.Errors.Count == 0 ? 0 : 2;
    }

    private static int TrustPlugin(PluginLoader loader, List<string> args)
    {
        if (args.Count != 1) return Usage("trust-plugin <plugin.dll> [--plugin-root <dir>]");
        var ok = loader.Trust(args[0]);
        Console.WriteLine(ok ? "已写入插件信任清单" : "写入信任清单失败");
        return ok ? 0 : 2;
    }

    private static int Example()
    {
        Console.WriteLine(ExamplePolicy);
        return 0;
    }

    private static int Unknown(string command)
    {
        Console.Error.WriteLine(string.Concat("未知命令：", command));
        PrintHelp();
        return 1;
    }

    private static int Usage(string usage)
    {
        Console.Error.WriteLine(string.Concat("用法：bedr-policy ", usage));
        return 1;
    }

    private static void PrintValidation(PolicyValidationResult result)
    {
        if (result.IsValid) Console.WriteLine("校验通过");
        foreach (var error in result.Errors) Console.Error.WriteLine(string.Concat("ERROR ", error));
        foreach (var warning in result.Warnings) Console.WriteLine(string.Concat("WARN  ", warning));
    }

    private static string? TakeOption(List<string> args, string name)
    {
        var index = args.IndexOf(name);
        if (index < 0 || index + 1 >= args.Count) return null;
        var value = args[index + 1];
        args.RemoveRange(index, 2);
        return value;
    }

    private static void WriteJson(object value) =>
        Console.WriteLine(JsonSerializer.Serialize(value, new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase }));

    private static void PrintHelp()
    {
        Console.WriteLine("""
B-EDR 策略工具

  bedr-policy validate <policy.json> [--json]
  bedr-policy install <policy.json> [--no-activate] [--root <dir>] [--json]
  bedr-policy list [--root <dir>] [--json]
  bedr-policy activate <policy-id> <version> [--root <dir>]
  bedr-policy deactivate <policy-id> [--root <dir>]
  bedr-policy rollback <policy-id> [--root <dir>]
  bedr-policy remove <policy-id> <version> [--root <dir>]
  bedr-policy simulate <policy.json> <events.json> [--fail-on-hit] [--json]
  bedr-policy test <policy.json> <tests.json> [--json]
  bedr-policy coverage [--policy <policy.json>] [--json|--markdown]
  bedr-policy plugins [--plugin-root <dir>] [--json]
  bedr-policy trust-plugin <plugin.dll> [--plugin-root <dir>]
  bedr-policy fields [--json]
  bedr-policy example

策略包只包含声明式条件，不允许在策略中执行任意代码。
需要深度扩展时使用独立的 .NET 插件接口。
""");
    }

    private const string ExamplePolicy = """
{
  "schemaVersion": 1,
  "id": "research.example.kernel",
  "name": "内核行为研究示例",
  "version": "1.0.0",
  "author": "B-EDR Lab",
  "description": "示例：用户目录 .sys 落地 + 8443 外联",
  "minEngineVersion": "2.0.0",
  "tags": ["kernel", "c2"],
  "rules": [
    {
      "id": "RESEARCH-KERNEL-001",
      "name": "用户目录驱动落地",
      "description": "用户可写目录出现 .sys 文件",
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
      "id": "RESEARCH-C2-001",
      "name": "C2 端口外联",
      "description": "连接到研究环境中的 C2 端口",
      "mitre": "T1071",
      "severity": "Critical",
      "score": 30,
      "eventKinds": ["NetworkConnect"],
      "condition": {
        "field": "network.destination.port",
        "op": "in",
        "value": [8443, 31337]
      }
    }
  ]
}
""";
}
