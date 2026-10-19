using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
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
        var mutating = command is "install" or "install-package" or "activate" or "deactivate" or "rollback" or "remove" or "trust-plugin" or "trust-key" or "revoke-key";
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
                "install-package" => InstallPackage(repository, rest, json),
                "verify-package" => VerifyPackage(repository, rest, json),
                "pack" => Pack(rest, json),
                "keygen" => KeyGen(rest, json),
                "trust-key" => TrustKey(repository, rest),
                "revoke-key" => RevokeKey(repository, rest),
                "publishers" => Publishers(repository, json),
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
        {
            var marker = policy.EffectiveActive ? "*" : policy.Active ? "!" : " ";
            var loadState = string.IsNullOrEmpty(policy.LoadError)
                ? string.Empty
                : string.Concat("  加载拒绝=", policy.LoadError);
            Console.WriteLine($"{marker} {policy.Name}  {policy.Id} v{policy.Version}  规则={policy.RuleCount}  验签={policy.SignatureVerified}  发布者={policy.Publisher}  回归={policy.TestPassedCount}/{policy.TestCaseCount}  风险={policy.RiskLevel}  sha256={policy.Sha256[..12]}{loadState}");
        }
        return 0;
    }

    private static int InstallPackage(PolicyRepository repository, List<string> args, bool json)
    {
        var activate = !args.Remove("--no-activate");
        if (args.Count != 1) return Usage("install-package <package.bedrpack> [--no-activate]");
        var result = repository.InstallPackageFromFile(args[0], activate);
        if (json) WriteJson(result);
        else
        {
            Console.WriteLine(result.Message);
            if (result.Validation is not null) PrintValidation(result.Validation);
            if (result.Inspection is { Success: true } inspection)
            {
                Console.WriteLine(string.Concat(
                    "发布者：", inspection.PublisherName,
                    "  验签=", inspection.SignatureValid,
                    "  回归=", inspection.TestResult?.PassedCount, "/", inspection.TestResult?.CaseCount,
                    "  覆盖=", inspection.CoveredEnabledRuleCount, "/", inspection.EnabledRuleCount,
                    "  风险=", inspection.RiskLevel));
            }
        }
        return result.Success ? 0 : 2;
    }

    private static int VerifyPackage(PolicyRepository repository, List<string> args, bool json)
    {
        var allowUntrusted = args.Remove("--allow-untrusted");
        if (args.Count != 1) return Usage("verify-package <package.bedrpack> [--allow-untrusted] [--json]");
        var inspection = PolicyPackageVerifier.Verify(
            args[0], new PolicyTrustStore(repository.Root), allowUntrusted);
        if (json)
        {
            WriteJson(inspection);
        }
        else
        {
            Console.WriteLine(inspection.Message);
            if (inspection.Success)
            {
                Console.WriteLine(string.Concat(
                    "策略：", inspection.Pack?.Name,
                    " v", inspection.Pack?.Version,
                    "  发布者=", inspection.PublisherName,
                    "  验签=", inspection.SignatureValid));
                Console.WriteLine(string.Concat(
                    "回归=", inspection.TestResult?.PassedCount, "/", inspection.TestResult?.CaseCount,
                    "  规则覆盖=", inspection.CoveredEnabledRuleCount, "/", inspection.EnabledRuleCount,
                    "  风险=", inspection.RiskLevel));
                Console.WriteLine(string.Concat("能力：", string.Join(",", inspection.Capabilities)));
            }
            foreach (var warning in inspection.Warnings) Console.WriteLine(string.Concat("WARN  ", warning));
            if (inspection.Validation is not null) PrintValidation(inspection.Validation);
        }
        return inspection.Success ? 0 : 2;
    }

    private static int Pack(List<string> args, bool json)
    {
        var policy = TakeOption(args, "--policy");
        var tests = TakeOption(args, "--tests");
        var fixtures = TakeOption(args, "--fixtures");
        var readme = TakeOption(args, "--readme");
        var key = TakeOption(args, "--key");
        var publisher = TakeOption(args, "--publisher");
        var output = TakeOption(args, "--out");
        var requireAllRulesCovered = !args.Remove("--allow-uncovered");
        var requireNegativeCase = !args.Remove("--allow-no-negative");
        if (args.Count != 0 || string.IsNullOrWhiteSpace(policy) ||
            string.IsNullOrWhiteSpace(tests) || string.IsNullOrWhiteSpace(key) ||
            string.IsNullOrWhiteSpace(publisher) || string.IsNullOrWhiteSpace(output))
            return Usage("pack --policy <json> --tests <json> --key <pem> --publisher <name> --out <bedrpack> [--fixtures <json>] [--readme <md>]");
        var result = PolicyPackageBuilder.Build(
            policy!, tests!, fixtures, readme, key!, publisher!, output!,
            requireAllRulesCovered, requireNegativeCase);
        if (json) WriteJson(result);
        else Console.WriteLine(result.Message);
        return result.Success ? 0 : 2;
    }

    private static int KeyGen(List<string> args, bool json)
    {
        var privatePath = TakeOption(args, "--private");
        var publicPath = TakeOption(args, "--public");
        if (args.Count != 0 || string.IsNullOrWhiteSpace(privatePath) || string.IsNullOrWhiteSpace(publicPath))
            return Usage("keygen --private <private.pem> --public <public.pem>");
        try
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            File.WriteAllText(privatePath!, key.ExportPkcs8PrivateKeyPem(), new UTF8Encoding(false));
            File.WriteAllText(publicPath!, key.ExportSubjectPublicKeyInfoPem(), new UTF8Encoding(false));
            var keyId = PolicyTrustStore.ComputeKeyId(key);
            if (json) WriteJson(new { keyId, privateKey = privatePath, publicKey = publicPath });
            else
            {
                Console.WriteLine(string.Concat("已生成P-256发布者密钥：", keyId));
                Console.WriteLine(string.Concat("私钥：", privatePath));
                Console.WriteLine(string.Concat("公钥：", publicPath));
            }
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine(string.Concat("生成密钥失败：", ex.Message));
            return 2;
        }
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

    private static int TrustKey(PolicyRepository repository, List<string> args)
    {
        var name = TakeOption(args, "--name");
        if (args.Count != 1) return Usage("trust-key <public.pem> [--name <publisher>]");
        var result = new PolicyTrustStore(repository.Root).ImportPublicKey(args[0], name);
        Console.WriteLine(result.Message);
        if (result.Publisher is not null)
            Console.WriteLine(string.Concat("KeyId=", result.Publisher.KeyId));
        return result.Success ? 0 : 2;
    }

    private static int Publishers(PolicyRepository repository, bool json)
    {
        var publishers = new PolicyTrustStore(repository.Root).List(out var error);
        if (!string.IsNullOrWhiteSpace(error))
        {
            Console.Error.WriteLine(error);
            return 2;
        }
        if (json) { WriteJson(publishers); return 0; }
        if (publishers.Count == 0) { Console.WriteLine("尚未信任任何策略发布者"); return 0; }
        foreach (var publisher in publishers)
            Console.WriteLine(string.Concat(
                publisher.Name, "  ", publisher.KeyId,
                "  ", publisher.TrustedAt.ToString("yyyy-MM-dd HH:mm:ss")));
        return 0;
    }

    private static int RevokeKey(PolicyRepository repository, List<string> args)
    {
        if (args.Count != 1) return Usage("revoke-key <publisher-key-id> [--root <dir>]");
        var result = new PolicyTrustStore(repository.Root).RemovePublisher(args[0]);
        Console.WriteLine(result.Message);
        return result.Success ? 0 : 2;
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
  bedr-policy keygen --private <pem> --public <pem> [--json]
  bedr-policy trust-key <public.pem> [--name <publisher>] [--root <dir>]
  bedr-policy revoke-key <publisher-key-id> [--root <dir>]
  bedr-policy publishers [--root <dir>] [--json]
  bedr-policy pack --policy <json> --tests <json> --key <pem> --publisher <name> --out <bedrpack> [--fixtures <json>] [--readme <md>]
  bedr-policy verify-package <package.bedrpack> [--allow-untrusted] [--json]
  bedr-policy install-package <package.bedrpack> [--no-activate] [--root <dir>] [--json]
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

普通JSON用于本机快速研究；.bedrpack用于可分发交付。
签名策略包会校验发布者、逐文件哈希、回归测试和规则覆盖。
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
