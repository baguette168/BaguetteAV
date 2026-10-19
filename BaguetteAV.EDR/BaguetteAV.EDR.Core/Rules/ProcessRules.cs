using BaguetteAV.EDR.Core.Models;
using System.Text.RegularExpressions;

namespace BaguetteAV.EDR.Core.Rules;

public sealed class WmiLineageRule : DetectionRule
{
    public override string Id => "EDR-001";
    public override string Name => "WMI 派生的用户目录进程";
    public override string Description => "WmiPrvSE.exe 直接拉起用户可写目录中的可执行文件，符合 Geoserver 漏洞经 WMI 投放载荷的链路。";
    public override string Mitre => "T1047 / T1059";
    public override int MaxScore => 18;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (e.Kind != TelemetryKind.ProcessCreate) return null;
        var parent = FileNameOf(e.ParentImage);
        if (!parent.Equals("WmiPrvSE.exe", StringComparison.OrdinalIgnoreCase)) return null;
        if (!ctx.IsUserWritable) return null;
        return new RuleMatch(18, string.Concat("父进程 WmiPrvSE.exe，子进程位于用户可写路径：", ctx.ImagePath));
    }
}

public sealed class UnsignedUserPathRule : DetectionRule
{
    public override string Id => "EDR-002";
    public override string Name => "用户目录中的未签名可执行文件";
    public override string Description => "进程镜像位于用户可写目录且不具备有效数字签名。";
    public override string Mitre => "T1204 / T1036";
    public override int MaxScore => 8;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (e.Kind != TelemetryKind.ProcessCreate) return null;
        if (!ctx.IsUserWritable || ctx.IsSigned) return null;
        if (!ctx.ImagePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return null;
        return new RuleMatch(8, string.Concat("未签名镜像：", ctx.ImagePath));
    }
}

public sealed class SuspiciousNameRule : DetectionRule
{
    private static readonly Regex NamePattern = new(
        "^(np_[a-z0-9]{1,12}|payload[0-9]*|beacon[0-9]*|svch0st|lsasss|winlogonx|tmp[0-9a-f]{6})\\.exe$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public override string Id => "EDR-003";
    public override string Name => "可疑载荷命名";
    public override string Description => "文件命名命中本次内核马投放链使用的随机化命名模式。";
    public override string Mitre => "T1036.005";
    public override int MaxScore => 10;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (e.Kind != TelemetryKind.ProcessCreate) return null;
        if (!NamePattern.IsMatch(ctx.FileName)) return null;
        return new RuleMatch(10, string.Concat("命中可疑文件名：", ctx.FileName));
    }
}
