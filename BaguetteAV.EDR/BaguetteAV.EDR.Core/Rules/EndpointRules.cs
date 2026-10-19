using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Rules;

public sealed class C2PortRule : DetectionRule
{
    public override string Id => "EDR-020";
    public override string Name => "受控端口外联";
    public override string Description => "用户目录进程连接实验 C2 使用的 8443 端口。";
    public override string Mitre => "T1071";
    public override int MaxScore => 12;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (e.Kind != TelemetryKind.NetworkConnect || !rc.MonitorNetwork) return null;
        if (!rc.MonitoredPorts.Contains(e.DestinationPort)) return null;
        if (!ctx.IsUserWritable && ctx.IsSigned) return null;
        return new RuleMatch(12, string.Concat("外联 ", e.DestinationIp, ":", e.DestinationPort));
    }
}

public sealed class IocHashRule : DetectionRule
{
    public override string Id => "EDR-021";
    public override string Name => "已知样本哈希";
    public override string Description => "进程镜像 SHA256 命中本地 IOC 库。";
    public override string Mitre => "T1204";
    public override int MaxScore => 40;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (string.IsNullOrWhiteSpace(ctx.Sha256) || rc.IocHashes.Count == 0) return null;
        if (!rc.IocHashes.Contains(ctx.Sha256)) return null;
        return new RuleMatch(40, string.Concat("SHA256：", ctx.Sha256));
    }
}

public sealed class VulnerableDriverRule : DetectionRule
{
    public override string Id => "EDR-022";
    public override string Name => "易受攻击驱动加载";
    public override string Description => "加载的驱动命中已知脆弱驱动名单或位于用户可写目录。";
    public override string Mitre => "T1068 / T1543.003";
    public override int MaxScore => 30;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (e.Kind != TelemetryKind.DriverLoad || !rc.MonitorDrivers) return null;
        var name = FileNameOf(e.DriverPath);
        if (rc.VulnerableDriverNames.Contains(name))
            return new RuleMatch(30, string.Concat("已知脆弱驱动：", name));
        if (RuleContext.IsUserWritable(e.DriverPath))
            return new RuleMatch(25, string.Concat("用户目录驱动：", e.DriverPath));
        return null;
    }
}

public sealed class WmiPersistenceRule : DetectionRule
{
    public override string Id => "EDR-023";
    public override string Name => "WMI 事件订阅持久化";
    public override string Description => "检测到 WMI 事件过滤器、消费者或绑定创建。";
    public override string Mitre => "T1546.003";
    public override int MaxScore => 25;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (!rc.MonitorWmi) return null;
        if (e.Kind != TelemetryKind.WmiFilter && e.Kind != TelemetryKind.WmiConsumer
            && e.Kind != TelemetryKind.WmiBinding) return null;
        var detail = string.Concat(e.WmiName, " ", e.WmiQuery, " ", e.WmiDestination).Trim();
        return new RuleMatch(25, string.Concat("WMI 订阅：", detail));
    }
}

public sealed class SysFileDropRule : DetectionRule
{
    public override string Id => "EDR-024";
    public override string Name => "用户目录驱动落地";
    public override string Description => "驱动文件被写入用户可写目录。";
    public override string Mitre => "T1543.003";
    public override int MaxScore => 15;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (e.Kind != TelemetryKind.FileCreate || !rc.MonitorFileCreation) return null;
        if (!e.FilePath.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)) return null;
        if (!RuleContext.IsUserWritable(e.FilePath)) return null;
        return new RuleMatch(15, string.Concat("驱动落地：", e.FilePath));
    }
}
