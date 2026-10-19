using BaguetteAV.EDR.Core.Models;
using System.Diagnostics;

namespace BaguetteAV.EDR.Core.Services;

public sealed record ResponsePlan(bool AlertOnly, bool Terminate, bool Quarantine, bool BlockDestination);

public sealed class ResponseEngine
{
    private static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe",
        "smss.exe", "winlogon.exe", "svchost.exe", "MsMpEng.exe", "avp.exe", "avpui.exe"
    };

    private static readonly HashSet<string> ProtectedDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        @"\Windows\System32\", @"\Windows\SysWOW64\", @"\Windows\WinSxS\"
    };

    private readonly LogService _log;
    private readonly QuarantineService _quarantine;
    private readonly FirewallService _firewall;

    public ResponseEngine(LogService log, QuarantineService quarantine, FirewallService firewall)
    {
        _log = log;
        _quarantine = quarantine;
        _firewall = firewall;
    }

    public static ResponsePlan ResolvePlan(ResponseAction requested, EdrSettings settings)
    {
        if (settings.ResponseMode == ResponseMode.AlertOnly || requested == ResponseAction.Alert)
            return new ResponsePlan(true, false, false, false);
        if (requested == ResponseAction.Inherit)
            return new ResponsePlan(false, true, settings.AutoQuarantine, settings.BlockC2Endpoint);
        return new ResponsePlan(
            false,
            requested.HasFlag(ResponseAction.TerminateProcess),
            requested.HasFlag(ResponseAction.QuarantineFile),
            requested.HasFlag(ResponseAction.BlockDestination));
    }

    public async Task<string> RespondAsync(DetectionRecord detection, ProcessContext context,
        EdrSettings settings, ResponseAction requested, CancellationToken cancellationToken)
    {
        var plan = ResolvePlan(requested, settings);
        if (plan.AlertOnly) return "仅告警";
        var actions = new List<string>();
        if (!IsProtected(context))
        {
            if (plan.Terminate && await TryKillAsync(detection.ProcessId, cancellationToken)) actions.Add("已终止进程");
            if (plan.Quarantine && context.FileExists && !IsSystemFile(context.ImagePath))
            {
                var entry = await Task.Run(() => _quarantine.Quarantine(context.ImagePath, context.Sha256, detection.RuleName), cancellationToken);
                actions.Add(entry is null ? "隔离失败" : "已隔离文件");
            }
        }
        else
        {
            actions.Add("受保护进程，已跳过终止");
        }
        if (plan.BlockDestination && TryGetDestinationIp(detection.Destination, out var ip))
        {
            var blocked = await Task.Run(() => _firewall.BlockRemoteAddress(ip, detection.RuleName), cancellationToken);
            actions.Add(blocked ? string.Concat("已阻断 ", ip) : "阻断失败");
        }
        return actions.Count == 0 ? "已记录，无自动处置动作" : string.Join("；", actions);
    }

    public bool IsProtected(ProcessContext context)
    {
        if (context.ProcessId <= 4) return true;
        if (context.ProcessId == Environment.ProcessId) return true;
        return ProtectedNames.Contains(context.FileName);
    }

    public async Task<bool> TryKillAsync(int processId, CancellationToken cancellationToken)
    {
        if (processId <= 4 || processId == Environment.ProcessId) return false;
        try
        {
            using var process = Process.GetProcessById(processId);
            if (ProtectedNames.Contains(process.ProcessName + ".exe")) return false;
            process.Kill(true);
            await process.WaitForExitAsync(cancellationToken).WaitAsync(TimeSpan.FromSeconds(3), cancellationToken);
            _log.Warn(string.Concat("已终止 PID=", processId));
            return true;
        }
        catch (Exception ex)
        {
            _log.Error(string.Concat("终止失败 PID=", processId, "：", ex.Message));
            return false;
        }
    }

    private static bool IsSystemFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return true;
        foreach (var dir in ProtectedDirectories)
            if (path.Contains(dir, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static bool TryGetDestinationIp(string destination, out string address)
    {
        address = string.Empty;
        if (string.IsNullOrWhiteSpace(destination)) return false;
        var value = destination.Split(':')[0].Trim();
        if (!System.Net.IPAddress.TryParse(value, out _)) return false;
        address = value;
        return true;
    }
}
