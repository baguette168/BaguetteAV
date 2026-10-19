namespace BaguetteAV.EDR.Core.Models;

public enum RootkitFindingKind
{
    Driver,
    Service,
    Startup,
    Hosts,
    WmiSubscription,
    Process
}

public sealed class RootkitFinding
{
    public RootkitFindingKind Kind { get; init; }
    public Severity Severity { get; init; }
    public string Title { get; init; } = string.Empty;
    public string Detail { get; init; } = string.Empty;
    public string Path { get; init; } = string.Empty;
    public string Mitre { get; init; } = string.Empty;
    public DateTime Timestamp { get; init; } = DateTime.Now;

    public string KindText => Kind switch
    {
        RootkitFindingKind.Driver => "驱动",
        RootkitFindingKind.Service => "服务",
        RootkitFindingKind.Startup => "启动项",
        RootkitFindingKind.Hosts => "Hosts",
        RootkitFindingKind.WmiSubscription => "WMI 订阅",
        _ => "进程"
    };
}
