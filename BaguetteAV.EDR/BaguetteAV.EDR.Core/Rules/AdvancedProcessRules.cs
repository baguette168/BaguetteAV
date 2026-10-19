using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Rules;

public sealed class DefenderTamperRule : DetectionRule
{
    private static readonly string[] Markers =
    {
        "Add-MpPreference", "-ExclusionPath", "DisableRealtimeMonitoring",
        "sc stop WinDefend", "sc config WinDefend", "fltmc unload"
    };

    public override string Id => "EDR-010";
    public override string Name => "安全组件篡改";
    public override string Description => "命令行包含关闭或排除 Microsoft Defender 的操作。";
    public override string Mitre => "T1562.001";
    public override int MaxScore => 20;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (e.Kind != TelemetryKind.ProcessCreate) return null;
        foreach (var marker in Markers)
        {
            if (e.CommandLine.Contains(marker, StringComparison.OrdinalIgnoreCase))
                return new RuleMatch(20, string.Concat("命中篡改特征：", marker));
        }
        return null;
    }
}

public sealed class RemoteThreadRule : DetectionRule
{
    public override string Id => "EDR-011";
    public override string Name => "向关键进程注入线程";
    public override string Description => "远程线程目标为 lsass、winlogon 或 services。";
    public override string Mitre => "T1055";
    public override int MaxScore => 28;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (e.Kind != TelemetryKind.RemoteThread) return null;
        var target = FileNameOf(e.TargetImage);
        if (!target.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase)
            && !target.Equals("winlogon.exe", StringComparison.OrdinalIgnoreCase)
            && !target.Equals("services.exe", StringComparison.OrdinalIgnoreCase)) return null;
        return new RuleMatch(28, string.Concat("远程线程目标：", target));
    }
}

public sealed class LsassAccessRule : DetectionRule
{
    public override string Id => "EDR-012";
    public override string Name => "LSASS 高权限访问";
    public override string Description => "非系统进程以读取或全权限掩码打开 lsass。";
    public override string Mitre => "T1003.001";
    public override int MaxScore => 22;

    public override RuleMatch? Evaluate(TelemetryEvent e, ProcessContext ctx, RuleContext rc)
    {
        if (e.Kind != TelemetryKind.ProcessAccess) return null;
        if (!FileNameOf(e.TargetImage).Equals("lsass.exe", StringComparison.OrdinalIgnoreCase)) return null;
        var access = e.GrantedAccess;
        if (!access.Contains("0x1010", StringComparison.OrdinalIgnoreCase)
            && !access.Contains("0x1410", StringComparison.OrdinalIgnoreCase)
            && !access.Contains("0x1fffff", StringComparison.OrdinalIgnoreCase)) return null;
        return new RuleMatch(22, string.Concat("访问掩码：", access));
    }
}
