using System.Security.Cryptography;
using System.Text.Json;
using BaguetteAV.EDR.Core.Rules;

namespace BaguetteAV.EDR.Core.Policy;

public sealed class PolicyRepository
{
    private readonly object _gate = new();
    private readonly string _root;

    public PolicyRepository(string? root = null)
    {
        _root = root ?? Path.Combine(Services.SettingsStore.DataDirectory, "policies");
    }

    public string Root => _root;
    public string InstalledDirectory => Path.Combine(_root, "installed");
    public string StatePath => Path.Combine(_root, "state.json");
    public string AuditPath => Path.Combine(_root, "audit.jsonl");

    public PolicyImportResult InstallFromFile(string sourcePath, bool activate = true)
    {
        try
        {
            var info = new FileInfo(sourcePath);
            if (!info.Exists) return new PolicyImportResult(false, "策略文件不存在", null, null);
            if (info.Length > PolicyValidator.MaxPolicyBytes)
                return new PolicyImportResult(false, "策略文件超过 2 MB 限制", null, null);
            return Install(File.ReadAllText(sourcePath), sourcePath, activate);
        }
        catch (Exception ex)
        {
            return new PolicyImportResult(false, string.Concat("读取策略失败：", ex.Message), null, null);
        }
    }

    public PolicyImportResult Install(string json, string sourceName, bool activate = true)
    {
        var validation = PolicyValidator.ValidateJson(json, out var pack);
        if (pack is null || !validation.IsValid)
            return new PolicyImportResult(false, "策略校验失败", null, validation);

        lock (_gate)
        {
            try
            {
                var hash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(json))).ToLowerInvariant();
                var folder = Path.Combine(InstalledDirectory, pack.Id, pack.Version);
                var policyPath = Path.Combine(folder, "policy.json");
                if (File.Exists(policyPath))
                {
                    var existingHash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(policyPath))).ToLowerInvariant();
                    if (!string.Equals(existingHash, hash, StringComparison.OrdinalIgnoreCase))
                    {
                        validation.Error("version", "同一策略 ID/版本已安装且内容不同；请提升版本号后再导入");
                        return new PolicyImportResult(false, "策略版本内容不可变，请提升版本号", null, validation);
                    }
                }
                var conflicts = FindRuleConflicts(pack);
                if (conflicts.Count > 0)
                {
                    foreach (var conflict in conflicts)
                        validation.Error("rules", conflict);
                    return new PolicyImportResult(false, "策略规则 ID 冲突", null, validation);
                }
                Directory.CreateDirectory(folder);
                AtomicWrite(policyPath, json);
                var meta = new PolicyMeta
                {
                    Id = pack.Id,
                    Name = pack.Name,
                    Version = pack.Version,
                    Author = pack.Author,
                    Description = pack.Description,
                    RuleCount = pack.Rules.Count,
                    Sha256 = hash,
                    Source = sourceName,
                    ImportedAt = DateTime.Now
                };
                AtomicWrite(Path.Combine(folder, "meta.json"), JsonSerializer.Serialize(meta, PolicyJson.Options));

                var state = LoadState();
                if (!state.Packs.TryGetValue(pack.Id, out var entry))
                    state.Packs[pack.Id] = entry = new PolicyStateEntry();
                if (activate)
                {
                    if (!string.IsNullOrWhiteSpace(entry.Active) && entry.Active != pack.Version)
                        entry.Previous = entry.Active;
                    entry.Active = pack.Version;
                    SaveState(state);
                }
                Audit("install", pack.Id, pack.Version, hash);

                var installed = new InstalledPolicy
                {
                    Id = pack.Id,
                    Name = pack.Name,
                    Version = pack.Version,
                    Author = pack.Author,
                    Description = pack.Description,
                    RuleCount = pack.Rules.Count,
                    Active = activate || string.Equals(entry.Active, pack.Version, StringComparison.OrdinalIgnoreCase),
                    ImportedAt = meta.ImportedAt,
                    Sha256 = hash,
                    Path = folder
                };
                return new PolicyImportResult(true, activate ? "策略已导入并启用" : "策略已导入", installed, validation);
            }
            catch (Exception ex)
            {
                return new PolicyImportResult(false, string.Concat("导入策略失败：", ex.Message), null, validation);
            }
        }
    }

    public IReadOnlyList<InstalledPolicy> List()
    {
        lock (_gate)
        {
            var state = LoadState();
            var result = new List<InstalledPolicy>();
            if (!Directory.Exists(InstalledDirectory)) return result;
            foreach (var packDir in Directory.EnumerateDirectories(InstalledDirectory))
            {
                foreach (var versionDir in Directory.EnumerateDirectories(packDir))
                {
                    try
                    {
                        var metaPath = Path.Combine(versionDir, "meta.json");
                        var packPath = Path.Combine(versionDir, "policy.json");
                        if (!File.Exists(metaPath) || !File.Exists(packPath)) continue;
                        var meta = JsonSerializer.Deserialize<PolicyMeta>(File.ReadAllText(metaPath), PolicyJson.Options);
                        if (meta is null) continue;
                        state.Packs.TryGetValue(meta.Id, out var entry);
                        result.Add(new InstalledPolicy
                        {
                            Id = meta.Id,
                            Name = meta.Name,
                            Version = meta.Version,
                            Author = meta.Author,
                            Description = meta.Description,
                            RuleCount = meta.RuleCount,
                            Active = string.Equals(entry?.Active, meta.Version, StringComparison.OrdinalIgnoreCase),
                            CanRollback = string.Equals(entry?.Active, meta.Version, StringComparison.OrdinalIgnoreCase) &&
                                          !string.IsNullOrWhiteSpace(entry?.Previous),
                            ImportedAt = meta.ImportedAt,
                            Sha256 = meta.Sha256,
                            Path = versionDir
                        });
                    }
                    catch { }
                }
            }
            return result.OrderBy(p => p.Name).ThenByDescending(p => p.ImportedAt).ToList();
        }
    }

    public bool SetActive(string id, string? version)
    {
        lock (_gate)
        {
            var state = LoadState();
            if (!state.Packs.TryGetValue(id, out var entry)) return false;
            if (string.IsNullOrWhiteSpace(version))
            {
                entry.Previous = entry.Active;
                entry.Active = null;
            }
            else
            {
                if (!TryGetVersionDirectory(id, version, out var folder) || !Directory.Exists(folder)) return false;
                if (!string.Equals(entry.Active, version, StringComparison.OrdinalIgnoreCase))
                    entry.Previous = entry.Active;
                entry.Active = version;
            }
            SaveState(state);
            Audit(string.IsNullOrWhiteSpace(version) ? "deactivate" : "activate", id, version ?? string.Empty);
            return true;
        }
    }

    public bool Rollback(string id)
    {
        lock (_gate)
        {
            var state = LoadState();
            if (!state.Packs.TryGetValue(id, out var entry) || string.IsNullOrWhiteSpace(entry.Previous)) return false;
            var target = entry.Previous;
            if (!TryGetVersionDirectory(id, target, out var folder) || !Directory.Exists(folder)) return false;
            entry.Previous = entry.Active;
            entry.Active = target;
            SaveState(state);
            Audit("rollback", id, target);
            return true;
        }
    }

    public bool Remove(string id, string version)
    {
        lock (_gate)
        {
            var state = LoadState();
            if (state.Packs.TryGetValue(id, out var entry) &&
                string.Equals(entry.Active, version, StringComparison.OrdinalIgnoreCase))
                return false;
            if (!TryGetVersionDirectory(id, version, out var folder) || !Directory.Exists(folder)) return false;
            Directory.Delete(folder, true);
            if (Directory.Exists(Path.Combine(InstalledDirectory, id)) &&
                !Directory.EnumerateFileSystemEntries(Path.Combine(InstalledDirectory, id)).Any())
                Directory.Delete(Path.Combine(InstalledDirectory, id));
            Audit("remove", id, version);
            return true;
        }
    }

    public PolicyBundle LoadActive()
    {
        var bundle = new PolicyBundle();
        lock (_gate)
        {
            var state = LoadState();
            foreach (var pair in state.Packs)
            {
                if (string.IsNullOrWhiteSpace(pair.Value.Active)) continue;
                var version = pair.Value.Active;
                if (!TryGetVersionDirectory(pair.Key, version, out var folder))
                {
                    bundle.Errors.Add(new PolicyLoadError(pair.Key, "活动策略路径无效，拒绝加载"));
                    continue;
                }
                var path = Path.Combine(folder, "policy.json");
                var metaPath = Path.Combine(folder, "meta.json");
                try
                {
                    if (!File.Exists(path))
                    {
                        bundle.Errors.Add(new PolicyLoadError(pair.Key, "策略文件缺失"));
                        continue;
                    }
                    if (!File.Exists(metaPath))
                    {
                        bundle.Errors.Add(new PolicyLoadError(pair.Key, "策略元数据缺失，拒绝加载"));
                        continue;
                    }
                    var meta = JsonSerializer.Deserialize<PolicyMeta>(File.ReadAllText(metaPath), PolicyJson.Options);
                    if (meta is null ||
                        !string.Equals(meta.Id, pair.Key, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(meta.Version, version, StringComparison.OrdinalIgnoreCase))
                    {
                        bundle.Errors.Add(new PolicyLoadError(pair.Key, "策略元数据与活动版本不匹配，拒绝加载"));
                        continue;
                    }
                    var bytes = File.ReadAllBytes(path);
                    var actualHash = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
                    if (string.IsNullOrWhiteSpace(meta.Sha256) ||
                        !string.Equals(actualHash, meta.Sha256, StringComparison.OrdinalIgnoreCase))
                    {
                        bundle.Errors.Add(new PolicyLoadError(pair.Key, "策略文件完整性校验失败，拒绝加载"));
                        continue;
                    }
                    var pack = JsonSerializer.Deserialize<PolicyPack>(System.Text.Encoding.UTF8.GetString(bytes), PolicyJson.Options);
                    if (pack is null)
                    {
                        bundle.Errors.Add(new PolicyLoadError(pair.Key, "策略文件格式无效"));
                        continue;
                    }
                    if (!string.Equals(pack.Id, pair.Key, StringComparison.OrdinalIgnoreCase) ||
                        !string.Equals(pack.Version, version, StringComparison.OrdinalIgnoreCase))
                    {
                        bundle.Errors.Add(new PolicyLoadError(pair.Key, "策略内容 ID 或版本与安装目录不匹配，拒绝加载"));
                        continue;
                    }
                    var validation = PolicyValidator.Validate(pack);
                    if (!validation.IsValid)
                    {
                        foreach (var error in validation.Errors)
                            bundle.Errors.Add(new PolicyLoadError(pack.Id, error));
                        continue;
                    }
                    bundle.Packs.Add(pack);
                }
                catch (Exception ex)
                {
                    bundle.Errors.Add(new PolicyLoadError(pair.Key, ex.Message));
                }
            }
        }
        return bundle;
    }

    private List<string> FindRuleConflicts(PolicyPack pack)
    {
        var owners = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in RuleCatalog.CreateDefault())
            owners[rule.Id] = "内置规则";
        foreach (var installed in LoadInstalledPacks(pack.Id))
        foreach (var rule in installed.Rules)
            owners.TryAdd(rule.Id, installed.Id);
        return pack.Rules
            .Where(rule => owners.ContainsKey(rule.Id))
            .Select(rule => string.Concat("规则 ID ", rule.Id, " 与 ", owners[rule.Id], " 冲突"))
            .ToList();
    }

    private IEnumerable<PolicyPack> LoadInstalledPacks(string excludeId)
    {
        if (!Directory.Exists(InstalledDirectory)) yield break;
        foreach (var packDir in Directory.EnumerateDirectories(InstalledDirectory))
        {
            var id = Path.GetFileName(packDir);
            if (string.Equals(id, excludeId, StringComparison.OrdinalIgnoreCase)) continue;
            foreach (var versionDir in Directory.EnumerateDirectories(packDir))
            {
                var path = Path.Combine(versionDir, "policy.json");
                if (!File.Exists(path)) continue;
                PolicyPack? pack = null;
                try
                {
                    pack = JsonSerializer.Deserialize<PolicyPack>(File.ReadAllText(path), PolicyJson.Options);
                }
                catch { }
                if (pack is not null) yield return pack;
            }
        }
    }

    private void Audit(string action, string id, string version, string sha256 = "")
    {
        try
        {
            Directory.CreateDirectory(_root);
            var entry = new
            {
                timestamp = DateTimeOffset.Now.ToString("O"),
                action,
                policyId = id,
                version,
                sha256,
                user = Environment.UserName,
                machine = Environment.MachineName
            };
            File.AppendAllText(AuditPath,
                string.Concat(JsonSerializer.Serialize(entry), Environment.NewLine),
                new System.Text.UTF8Encoding(false));
        }
        catch { }
    }

    private PolicyState LoadState()
    {
        try
        {
            if (File.Exists(StatePath))
            {
                var state = JsonSerializer.Deserialize<PolicyState>(File.ReadAllText(StatePath), PolicyJson.Options);
                if (state is not null) return state;
            }
        }
        catch { }
        return new PolicyState();
    }

    private void SaveState(PolicyState state) => AtomicWrite(StatePath, JsonSerializer.Serialize(state, PolicyJson.Options));

    private bool TryGetVersionDirectory(string id, string version, out string folder)
    {
        folder = string.Empty;
        if (!IsSafeSegment(id) || !IsSafeSegment(version)) return false;
        var root = Path.GetFullPath(InstalledDirectory);
        var candidate = Path.GetFullPath(Path.Combine(root, id, version));
        var prefix = root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        if (!candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return false;
        folder = candidate;
        return true;
    }

    private static bool IsSafeSegment(string value) =>
        !string.IsNullOrWhiteSpace(value) && value != "." && value != ".." &&
        value.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;

    private static void AtomicWrite(string path, string content)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path) ?? ".");
        var temp = string.Concat(path, ".tmp");
        File.WriteAllText(temp, content, new System.Text.UTF8Encoding(false));
        File.Move(temp, path, true);
    }

    private sealed class PolicyState
    {
        public int SchemaVersion { get; set; } = 1;
        public Dictionary<string, PolicyStateEntry> Packs { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private sealed class PolicyStateEntry
    {
        public string? Active { get; set; }
        public string? Previous { get; set; }
    }

    private sealed class PolicyMeta
    {
        public string Id { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Author { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public int RuleCount { get; set; }
        public string Sha256 { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public DateTime ImportedAt { get; set; }
    }
}
