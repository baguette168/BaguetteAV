using System.Diagnostics;

namespace BaguetteAV.EDR.Core.Services;

public sealed record ScanFinding(string Path, string Signature);

public sealed class ScanResult
{
    public bool EngineAvailable { get; init; }
    public bool Cancelled { get; init; }
    public string Message { get; init; } = string.Empty;
    public string EngineVersion { get; init; } = string.Empty;
    public int ScannedFiles { get; init; }
    public List<ScanFinding> Findings { get; init; } = new();
}

public sealed class ClamAvScanner
{
    private readonly LogService _log;
    public ClamAvScanner(LogService log) => _log = log;

    public string? FindEngine(string configuredPath)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(configuredPath)) candidates.Add(configuredPath);
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "clamav", "clamscan.exe"));
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "clamscan.exe"));
        candidates.Add(@"C:\Program Files\ClamAV\clamscan.exe");
        foreach (var candidate in candidates)
        {
            try { if (File.Exists(candidate)) return candidate; } catch { }
        }
        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        foreach (var dir in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim(), "clamscan.exe");
                if (File.Exists(candidate)) return candidate;
            }
            catch { }
        }
        return null;
    }

    public async Task<ScanResult> ScanAsync(string targetPath, string? configuredEngine,
        IProgress<string>? progress, CancellationToken cancellationToken)
    {
        var engine = FindEngine(configuredEngine ?? string.Empty);
        if (engine is null)
        {
            return new ScanResult
            {
                EngineAvailable = false,
                Message = "未找到 clamscan.exe，请安装 ClamAV 或在设置中指定引擎路径。"
            };
        }
        if (string.IsNullOrWhiteSpace(targetPath) || (!File.Exists(targetPath) && !Directory.Exists(targetPath)))
        {
            return new ScanResult { EngineAvailable = true, Message = "扫描目标不存在" };
        }

        var findings = new List<ScanFinding>();
        var scanned = 0;
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = engine,
                Arguments = string.Concat("--stdout --infected --recursive --no-summary \"", targetPath, "\""),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            using var process = new Process { StartInfo = info };
            process.OutputDataReceived += (_, e) =>
            {
                if (string.IsNullOrWhiteSpace(e.Data)) return;
                var line = e.Data.Trim();
                if (line.EndsWith(" FOUND", StringComparison.OrdinalIgnoreCase))
                {
                    var marker = line.LastIndexOf(": ", StringComparison.Ordinal);
                    if (marker > 1)
                        findings.Add(new ScanFinding(line.Substring(0, marker), line.Substring(marker + 2, line.Length - marker - 8)));
                }
                else if (line.Contains(": OK", StringComparison.OrdinalIgnoreCase) || line.Contains(": Empty file", StringComparison.OrdinalIgnoreCase))
                {
                    scanned++;
                }
                progress?.Report(line);
            };
            process.ErrorDataReceived += (_, e) => { if (!string.IsNullOrWhiteSpace(e.Data)) progress?.Report(e.Data); };
            process.Start();
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            var completed = await Task.Run(() => process.WaitForExit(600000), cancellationToken);
            if (!completed)
            {
                try { process.Kill(true); } catch { }
                return new ScanResult { EngineAvailable = true, Message = "扫描已取消", Findings = findings, ScannedFiles = scanned };
            }
            return new ScanResult
            {
                EngineAvailable = true,
                Message = findings.Count == 0 ? "扫描完成，未发现威胁" : string.Concat("发现 ", findings.Count, " 个威胁"),
                Findings = findings,
                ScannedFiles = scanned
            };
        }
        catch (OperationCanceledException)
        {
            return new ScanResult { EngineAvailable = true, Cancelled = true, Message = "扫描已取消", Findings = findings, ScannedFiles = scanned };
        }
        catch (Exception ex)
        {
            _log.Error(string.Concat("ClamAV 扫描失败：", ex.Message));
            return new ScanResult { EngineAvailable = true, Message = string.Concat("扫描失败：", ex.Message), Findings = findings, ScannedFiles = scanned };
        }
    }
}
