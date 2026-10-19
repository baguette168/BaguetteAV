using BaguetteAV.EDR.Core.Models;
using System.Text.Json;

namespace BaguetteAV.EDR.Core.Services;

public sealed class DetectionStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };
    private readonly object _gate = new();
    private readonly LogService _log;

    public DetectionStore(LogService log, string? directory = null)
    {
        _log = log;
        DirectoryPath = directory ?? Path.Combine(SettingsStore.DataDirectory, "detections");
    }

    public string DirectoryPath { get; }

    public void Append(DetectionRecord record)
    {
        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(DirectoryPath);
                var file = Path.Combine(DirectoryPath, string.Concat("detections-", DateTime.Now.ToString("yyyyMMdd"), ".jsonl"));
                File.AppendAllText(file, JsonSerializer.Serialize(record, Options) + Environment.NewLine);
            }
            catch (Exception ex)
            {
                _log.Warn(string.Concat("告警写入失败：", ex.Message));
            }
        }
    }

    public List<DetectionRecord> LoadRecent(int max)
    {
        var result = new List<DetectionRecord>(max);
        try
        {
            if (!Directory.Exists(DirectoryPath)) return result;
            var files = new DirectoryInfo(DirectoryPath).GetFiles("detections-*.jsonl")
                .OrderByDescending(f => f.Name).Take(7).ToList();
            foreach (var file in files)
            {
                var lines = File.ReadLines(file.FullName).Reverse();
                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var record = JsonSerializer.Deserialize<DetectionRecord>(line, Options);
                        if (record is not null && !record.RuleId.StartsWith("DEMO-", StringComparison.OrdinalIgnoreCase))
                            result.Add(record);
                    }
                    catch { }
                    if (result.Count >= max) return result;
                }
            }
        }
        catch (Exception ex)
        {
            _log.Warn(string.Concat("告警读取失败：", ex.Message));
        }
        return result;
    }

    public void Trim(DateTime cutoffUtc)
    {
        try
        {
            if (!Directory.Exists(DirectoryPath)) return;
            foreach (var file in new DirectoryInfo(DirectoryPath).GetFiles("detections-*.jsonl"))
            {
                if (file.LastWriteTimeUtc < cutoffUtc) file.Delete();
            }
        }
        catch { }
    }
}
