using BaguetteAV.EDR.Core.Models;
using System.Text.Json;

namespace BaguetteAV.EDR.Core.Services;

public sealed class QuarantineService
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = false };
    private readonly object _gate = new();
    private readonly LogService _log;
    private readonly Func<string> _directory;

    public QuarantineService(LogService log, Func<string> directory)
    {
        _log = log;
        _directory = directory;
    }

    public string DirectoryPath => _directory();
    public string ManifestPath => Path.Combine(DirectoryPath, "quarantine.jsonl");

    public QuarantineEntry? Quarantine(string originalPath, string sha256, string ruleName)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(originalPath) || !File.Exists(originalPath)) return null;
            Directory.CreateDirectory(DirectoryPath);
            var info = new FileInfo(originalPath);
            var safeName = string.Concat(DateTime.Now.ToString("yyyyMMdd-HHmmss"), "-", Guid.NewGuid().ToString("N").Substring(0, 8), "-",
                Sanitize(info.Name), ".qtn");
            var stored = Path.Combine(DirectoryPath, safeName);
            for (var attempt = 0; attempt < 3; attempt++)
            {
                try
                {
                    File.Copy(originalPath, stored, false);
                    break;
                }
                catch when (attempt < 2) { Thread.Sleep(200); }
            }
            if (!File.Exists(stored)) return null;

            var removed = false;
            for (var attempt = 0; attempt < 3 && !removed; attempt++)
            {
                try { File.Delete(originalPath); removed = true; }
                catch { Thread.Sleep(200); }
            }

            var entry = new QuarantineEntry
            {
                OriginalPath = originalPath,
                StoredPath = stored,
                Sha256 = sha256,
                RuleName = ruleName,
                Size = info.Length,
                OriginalRemoved = removed
            };
            Append(entry);
            _log.Warn(string.Concat("已隔离 ", originalPath));
            return entry;
        }
        catch (Exception ex)
        {
            _log.Error(string.Concat("隔离失败：", ex.Message));
            return null;
        }
    }

    public IReadOnlyList<QuarantineEntry> List()
    {
        var entries = new Dictionary<Guid, QuarantineEntry>();
        try
        {
            if (!File.Exists(ManifestPath)) return Array.Empty<QuarantineEntry>();
            foreach (var line in File.ReadLines(ManifestPath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try
                {
                    var entry = JsonSerializer.Deserialize<QuarantineEntry>(line, Options);
                    if (entry is not null) entries[entry.Id] = entry;
                }
                catch { }
            }
        }
        catch (Exception ex)
        {
            _log.Warn(string.Concat("隔离区索引读取失败：", ex.Message));
        }
        return entries.Values.Where(e => !e.Deleted).OrderByDescending(e => e.QuarantinedAt).ToList();
    }

    public string? Restore(QuarantineEntry entry)
    {
        try
        {
            if (!File.Exists(entry.StoredPath)) return null;
            var target = entry.OriginalPath;
            if (File.Exists(target))
            {
                var downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
                Directory.CreateDirectory(downloads);
                target = Path.Combine(downloads, string.Concat(Path.GetFileNameWithoutExtension(entry.FileName), "-restored", Path.GetExtension(entry.FileName)));
            }
            Directory.CreateDirectory(Path.GetDirectoryName(target) ?? DirectoryPath);
            File.Copy(entry.StoredPath, target, true);
            _log.Info(string.Concat("已恢复 ", target));
            return target;
        }
        catch (Exception ex)
        {
            _log.Error(string.Concat("恢复失败：", ex.Message));
            return null;
        }
    }

    public bool Delete(QuarantineEntry entry)
    {
        try
        {
            if (File.Exists(entry.StoredPath)) File.Delete(entry.StoredPath);
            Append(new QuarantineEntry
            {
                Id = entry.Id,
                QuarantinedAt = entry.QuarantinedAt,
                OriginalPath = entry.OriginalPath,
                StoredPath = entry.StoredPath,
                Sha256 = entry.Sha256,
                RuleName = entry.RuleName,
                Size = entry.Size,
                OriginalRemoved = entry.OriginalRemoved,
                Deleted = true
            });
            return true;
        }
        catch (Exception ex)
        {
            _log.Error(string.Concat("隔离区删除失败：", ex.Message));
            return false;
        }
    }

    private void Append(QuarantineEntry entry)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(DirectoryPath);
            File.AppendAllText(ManifestPath, JsonSerializer.Serialize(entry, Options) + Environment.NewLine);
        }
    }

    private static string Sanitize(string name)
    {
        foreach (var ch in Path.GetInvalidFileNameChars()) name = name.Replace(ch, '_');
        return name;
    }
}
