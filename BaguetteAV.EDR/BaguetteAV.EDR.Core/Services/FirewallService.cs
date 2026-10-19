using System.Diagnostics;
using System.Net;
using System.Text;

namespace BaguetteAV.EDR.Core.Services;

public sealed class FirewallService
{
    private readonly LogService _log;
    public FirewallService(LogService log) => _log = log;

    public bool BlockRemoteAddress(string address, string ruleName)
    {
        if (!IPAddress.TryParse(address, out _)) return false;
        var name = string.Concat("BaguetteAV EDR Block ", address);
        var arguments = new StringBuilder()
            .Append("advfirewall firewall add rule name=\"")
            .Append(name.Replace("\"", string.Empty))
            .Append("\" dir=out action=block remoteip=")
            .Append(address)
            .Append(" enable=yes profile=any")
            .ToString();
        return RunNetsh(arguments);
    }

    private bool RunNetsh(string arguments)
    {
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var process = Process.Start(info);
            if (process is null) return false;
            if (!process.WaitForExit(8000))
            {
                try { process.Kill(true); } catch { }
                return false;
            }
            var ok = process.ExitCode == 0;
            _log.Info(string.Concat(ok ? "防火墙规则已生效：" : "防火墙规则下发失败：", arguments));
            return ok;
        }
        catch (Exception ex)
        {
            _log.Error(string.Concat("netsh 调用失败：", ex.Message));
            return false;
        }
    }
}
