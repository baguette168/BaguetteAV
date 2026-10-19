using BaguetteAV.EDR.Core.Models;
using Microsoft.Win32;
using System.Management;

namespace BaguetteAV.EDR.Core.Services;

public sealed class RootkitScanner
{
    private static readonly HashSet<string> VulnerableDrivers = new(StringComparer.OrdinalIgnoreCase)
    {
        "AsIO64.sys", "AsIO3.sys", "asio.sys", "gdrv.sys", "gdrv2.sys", "winio64.sys",
        "winio32.sys", "dbgv.sys", "kprocesshacker.sys", "physmem.sys", "iqvw64e.sys",
        "msio64.sys", "rtcore64.sys", "ene.sys"
    };

    private static readonly string[] HijackDomains =
    {
        "microsoft.com", "windowsupdate.com", "defender", "kaspersky", "update.microsoft"
    };

    private readonly ProcessInspector _inspector;
    private readonly LogService _log;
    public RootkitScanner(ProcessInspector inspector, LogService log)
    {
        _inspector = inspector;
        _log = log;
    }

    public Task<IReadOnlyList<RootkitFinding>> ScanAsync(IProgress<string>? progress, CancellationToken cancellationToken)
    {
        return Task.Run<IReadOnlyList<RootkitFinding>>(() =>
        {
            var findings = new List<RootkitFinding>();
            progress?.Report("正在检查驱动服务...");
            ScanDrivers(findings, cancellationToken);
            progress?.Report("正在检查启动项...");
            ScanRunKeys(findings, cancellationToken);
            progress?.Report("正在检查 Hosts 文件...");
            ScanHosts(findings, cancellationToken);
            progress?.Report("正在检查 WMI 订阅...");
            ScanWmi(findings, cancellationToken);
            progress?.Report("检查完成");
            return findings;
        }, cancellationToken);
    }

    private void ScanDrivers(List<RootkitFinding> findings, CancellationToken token)
    {
        try
        {
            using var services = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                .OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is null) return;
            foreach (var name in services.GetSubKeyNames())
            {
                token.ThrowIfCancellationRequested();
                using var key = services.OpenSubKey(name);
                if (key is null) continue;
                var type = key.GetValue("Type");
                if (type is not int typeValue || (typeValue != 1 && typeValue != 2)) continue;
                var image = key.GetValue("ImagePath") as string ?? string.Empty;
                var path = NormalizeDriverPath(image);
                var fileName = Path.GetFileName(path);
                var exists = !string.IsNullOrWhiteSpace(path) && File.Exists(path);
                var signed = exists && _inspector.IsSigned(path);
                var userWritable = Rules.RuleContext.IsUserWritable(path);
                if (VulnerableDrivers.Contains(fileName))
                {
                    findings.Add(new RootkitFinding
                    {
                        Kind = RootkitFindingKind.Driver,
                        Severity = Severity.Critical,
                        Title = string.Concat("加载已知脆弱驱动：", name),
                        Detail = "该驱动存在已知提权漏洞，常被用于绕过内核回调。",
                        Path = path,
                        Mitre = "T1068"
                    });
                }
                else if (userWritable)
                {
                    findings.Add(new RootkitFinding
                    {
                        Kind = RootkitFindingKind.Driver,
                        Severity = Severity.High,
                        Title = string.Concat("用户目录驱动服务：", name),
                        Detail = "驱动映像位于用户可写目录，存在被替换风险。",
                        Path = path,
                        Mitre = "T1543.003"
                    });
                }
                else if (!exists)
                {
                    findings.Add(new RootkitFinding
                    {
                        Kind = RootkitFindingKind.Driver,
                        Severity = Severity.High,
                        Title = string.Concat("驱动文件缺失：", name),
                        Detail = string.Concat("注册表映像路径不存在：", image),
                        Path = path,
                        Mitre = "T1014"
                    });
                }
                else if (!signed && !path.Contains(@"\System32\", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(new RootkitFinding
                    {
                        Kind = RootkitFindingKind.Driver,
                        Severity = Severity.Medium,
                        Title = string.Concat("未签名驱动：", name),
                        Detail = "驱动未通过数字签名校验，且不在系统目录。",
                        Path = path,
                        Mitre = "T1543.003"
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _log.Warn(string.Concat("驱动服务枚举失败：", ex.Message));
        }
    }

    private void ScanRunKeys(List<RootkitFinding> findings, CancellationToken token)
    {
        var paths = new[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce"
        };
        foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
        {
            foreach (var sub in paths)
            {
                token.ThrowIfCancellationRequested();
                try
                {
                    using var key = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64).OpenSubKey(sub);
                    if (key is null) continue;
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName) as string ?? string.Empty;
                        var suspicious = Rules.RuleContext.IsUserWritable(value)
                            || value.Contains("powershell", StringComparison.OrdinalIgnoreCase)
                            || value.Contains("mshta", StringComparison.OrdinalIgnoreCase)
                            || value.Contains("wscript", StringComparison.OrdinalIgnoreCase);
                        if (!suspicious) continue;
                        findings.Add(new RootkitFinding
                        {
                            Kind = RootkitFindingKind.Startup,
                            Severity = Severity.High,
                            Title = string.Concat("可疑启动项：", valueName),
                            Detail = value,
                            Path = value,
                            Mitre = "T1547.001"
                        });
                    }
                }
                catch { }
            }
        }
    }

    private void ScanHosts(List<RootkitFinding> findings, CancellationToken token)
    {
        try
        {
            var hosts = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "drivers", "etc", "hosts");
            if (!File.Exists(hosts)) return;
            foreach (var raw in File.ReadLines(hosts))
            {
                token.ThrowIfCancellationRequested();
                var line = raw.Trim();
                if (line.Length == 0 || line.StartsWith("#")) continue;
                foreach (var domain in HijackDomains)
                {
                    if (!line.Contains(domain, StringComparison.OrdinalIgnoreCase)) continue;
                    findings.Add(new RootkitFinding
                    {
                        Kind = RootkitFindingKind.Hosts,
                        Severity = Severity.High,
                        Title = "Hosts 文件存在可疑映射",
                        Detail = line,
                        Path = hosts,
                        Mitre = "T1565.001"
                    });
                    break;
                }
            }
        }
        catch (Exception ex)
        {
            _log.Warn(string.Concat("Hosts 文件检查失败：", ex.Message));
        }
    }

    private void ScanWmi(List<RootkitFinding> findings, CancellationToken token)
    {
        try
        {
            var scope = new ManagementScope(@"\\.\root\subscription");
            scope.Connect();
            var queries = new[]
            {
                "SELECT * FROM __EventFilter",
                "SELECT * FROM CommandLineEventConsumer",
                "SELECT * FROM ActiveScriptEventConsumer",
                "SELECT * FROM __FilterToConsumerBinding"
            };
            foreach (var query in queries)
            {
                token.ThrowIfCancellationRequested();
                using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query));
                foreach (ManagementObject item in searcher.Get())
                {
                    var name = item["Name"]?.ToString() ?? item.ClassPath.ClassName;
                    var detail = item["Query"]?.ToString() ?? item["CommandLineTemplate"]?.ToString() ?? string.Empty;
                    findings.Add(new RootkitFinding
                    {
                        Kind = RootkitFindingKind.WmiSubscription,
                        Severity = Severity.High,
                        Title = string.Concat("WMI 事件订阅：", name),
                        Detail = detail,
                        Path = scope.Path.Path,
                        Mitre = "T1546.003"
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _log.Warn(string.Concat("WMI 订阅检查失败：", ex.Message));
        }
    }

    private static string NormalizeDriverPath(string image)
    {
        if (string.IsNullOrWhiteSpace(image)) return string.Empty;
        var value = image.Trim().Trim('"');
        if (value.StartsWith(@"\??\", StringComparison.Ordinal)) value = value.Substring(4);
        value = Environment.ExpandEnvironmentVariables(value);
        if (value.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            value = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), value.Substring(12));
        else if (value.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase))
            value = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), value);
        var space = value.IndexOf(".sys", StringComparison.OrdinalIgnoreCase);
        if (space > 0) value = value.Substring(0, space + 4);
        return value;
    }
}
