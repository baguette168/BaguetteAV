namespace BaguetteAV.EDR.Core.Rules;

public sealed class RuleContext
{
    public HashSet<string> IocHashes { get; } = new(StringComparer.OrdinalIgnoreCase);
    public HashSet<int> MonitoredPorts { get; } = new();
    public HashSet<string> VulnerableDriverNames { get; } = new(StringComparer.OrdinalIgnoreCase)
    {
        "AsIO64.sys", "asio.sys", "AsIO3.sys", "gdrv.sys", "gdrv2.sys",
        "winio64.sys", "winio32.sys", "dbgv.sys", "kprocesshacker.sys",
        "physmem.sys", "ene.sys", "iqvw64e.sys", "msio64.sys", "rtcore64.sys"
    };

    public bool MonitorNetwork { get; set; } = true;
    public bool MonitorDrivers { get; set; } = true;
    public bool MonitorWmi { get; set; } = true;
    public bool MonitorFileCreation { get; set; }

    public static bool IsUserWritable(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var normalized = path.Replace('/', '\\');
        return normalized.Contains("\\Users\\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\\ProgramData\\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\\Windows\\Temp\\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\\Desktop\\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("\\Public\\", StringComparison.OrdinalIgnoreCase);
    }
}
