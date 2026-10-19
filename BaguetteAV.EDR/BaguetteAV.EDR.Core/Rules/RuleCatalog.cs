using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Rules;

public static class RuleCatalog
{
    public static IReadOnlyList<DetectionRule> CreateDefault() => new List<DetectionRule>
    {
        new WmiLineageRule(),
        new UnsignedUserPathRule(),
        new SuspiciousNameRule(),
        new DefenderTamperRule(),
        new RemoteThreadRule(),
        new LsassAccessRule(),
        new C2PortRule(),
        new IocHashRule(),
        new VulnerableDriverRule(),
        new WmiPersistenceRule(),
        new SysFileDropRule()
    };

    public static RuleContext CreateContext(EdrSettings settings)
    {
        var context = new RuleContext
        {
            MonitorNetwork = settings.MonitorNetwork,
            MonitorDrivers = settings.MonitorDrivers,
            MonitorWmi = settings.MonitorWmi,
            MonitorFileCreation = settings.MonitorFileCreation
        };
        foreach (var port in settings.MonitoredPorts) context.MonitoredPorts.Add(port);
        foreach (var hash in settings.IocHashes)
        {
            if (!string.IsNullOrWhiteSpace(hash)) context.IocHashes.Add(hash.Trim());
        }
        return context;
    }
}
