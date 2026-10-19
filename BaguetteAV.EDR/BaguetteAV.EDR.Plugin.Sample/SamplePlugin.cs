using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;
using BaguetteAV.EDR.Core.Rules;
using System.Text.Json;

namespace BaguetteAV.EDR.Plugin.Sample;

public sealed class SamplePlugin : IEdrPlugin
{
    public string Id => "research.sample.kernel";
    public string Name => "内核研究示例插件";
    public string Version => "1.0.0";

    public IEnumerable<PolicyPack> GetPolicyPacks()
    {
        yield return new PolicyPack
        {
            Id = "research.sample.kernel-pack",
            Name = "插件声明式策略示例",
            Version = "1.0.0",
            Author = "B-EDR Lab",
            Description = "由插件提供的声明式策略包",
            Rules =
            {
                new PolicyRule
                {
                    Id = "PLUGIN-POLICY-001",
                    Name = "临时目录可执行文件",
                    Description = "进程镜像位于 Temp 目录",
                    Mitre = "T1204",
                    Severity = "Medium",
                    Score = 12,
                    EventKinds = { "ProcessCreate" },
                    Condition = new PolicyCondition
                    {
                        Field = "process.path",
                        Op = "regex",
                        Value = JsonSerializer.SerializeToElement("(?i)\\\\Temp\\\\")
                    }
                }
            }
        };
    }

    public IEnumerable<DetectionRule> GetRules()
    {
        yield return new NpRceRule();
    }

    private sealed class NpRceRule : DetectionRule
    {
        public override string Id => "PLUGIN-CODE-001";
        public override string Name => "np_rce.exe 研究样本";
        public override string Description => "代码级插件示例：识别研究链中的 np_rce.exe 进程名";
        public override string Mitre => "T1204";
        public override int MaxScore => 35;

        public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
        {
            var name = ctx.FileName;
            if (name.Equals("np_rce.exe", StringComparison.OrdinalIgnoreCase))
                return new RuleMatch(35, "命中研究样本 np_rce.exe");
            return null;
        }
    }
}
