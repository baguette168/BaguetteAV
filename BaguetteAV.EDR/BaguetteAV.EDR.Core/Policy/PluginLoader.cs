using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using BaguetteAV.EDR.Core.Rules;
using BaguetteAV.EDR.Core.Services;

namespace BaguetteAV.EDR.Core.Policy;

public sealed class PluginLoader
{
    private readonly object _gate = new();
    private readonly string _root;
    private PluginLoadResult? _cached;

    public PluginLoader(string? root = null)
    {
        _root = root ?? Path.Combine(SettingsStore.DataDirectory, "plugins");
    }

    public string Root => _root;
    public string TrustPath => Path.Combine(_root, "trusted.json");

    public PluginLoadResult Load()
    {
        lock (_gate)
        {
            return _cached ??= LoadCore();
        }
    }

    public PluginLoadResult Reload()
    {
        lock (_gate)
        {
            _cached = null;
            return _cached = LoadCore();
        }
    }

    public string ComputeHash(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    public bool Trust(string path)
    {
        try
        {
            var full = Path.GetFullPath(path);
            if (!File.Exists(full)) return false;
            var trust = LoadTrust();
            var name = Path.GetFileName(full);
            var entry = trust.Plugins.FirstOrDefault(p => string.Equals(p.File, name, StringComparison.OrdinalIgnoreCase));
            if (entry is null)
            {
                entry = new TrustedPlugin { File = name };
                trust.Plugins.Add(entry);
            }
            entry.Sha256 = ComputeHash(full);
            Directory.CreateDirectory(_root);
            File.WriteAllText(TrustPath, JsonSerializer.Serialize(trust, PolicyJson.Options));
            _cached = null;
            return true;
        }
        catch { return false; }
    }

    private PluginLoadResult LoadCore()
    {
        var result = new PluginLoadResult();
        if (!Directory.Exists(_root)) return result;
        var trust = LoadTrust();
        var trusted = trust.Plugins
            .Where(p => !string.IsNullOrWhiteSpace(p.File) && !string.IsNullOrWhiteSpace(p.Sha256))
            .ToDictionary(p => p.File, p => p.Sha256, StringComparer.OrdinalIgnoreCase);
        var pluginIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in Directory.EnumerateFiles(_root, "*.dll", SearchOption.TopDirectoryOnly))
        {
            var name = Path.GetFileName(file);
            try
            {
                var hash = ComputeHash(file);
                if (!trusted.TryGetValue(name, out var expected) ||
                    !string.Equals(hash, expected, StringComparison.OrdinalIgnoreCase))
                {
                    result.Errors.Add(new PolicyLoadError(name, "插件未在 trusted.json 中登记或 SHA256 不匹配"));
                    continue;
                }

                var assembly = Assembly.LoadFrom(file);
                var types = assembly.GetTypes().Where(t => !t.IsAbstract && typeof(IEdrPlugin).IsAssignableFrom(t)).ToArray();
                if (types.Length == 0)
                {
                    result.Errors.Add(new PolicyLoadError(name, "程序集中没有 IEdrPlugin 实现"));
                    continue;
                }
                foreach (var type in types)
                {
                    var plugin = (IEdrPlugin?)Activator.CreateInstance(type);
                    if (plugin is null) continue;
                    if (!pluginIds.Add(plugin.Id))
                    {
                        result.Errors.Add(new PolicyLoadError(plugin.Id, "插件 ID 重复"));
                        continue;
                    }
                    var packs = plugin.GetPolicyPacks().ToList();
                    var rules = plugin.GetRules().ToList();
                    var validPacks = 0;
                    foreach (var pack in packs)
                    {
                        var validation = PolicyValidator.Validate(pack);
                        if (!validation.IsValid)
                        {
                            foreach (var error in validation.Errors)
                                result.Errors.Add(new PolicyLoadError(plugin.Id, error));
                            continue;
                        }
                        result.Packs.Add(pack);
                        validPacks++;
                    }
                    result.Plugins.Add(plugin);
                    result.Rules.AddRange(rules);
                    result.Descriptors.Add(new PluginDescriptor(plugin.Id, plugin.Name, plugin.Version, file, hash, validPacks, rules.Count));
                }
            }
            catch (Exception ex)
            {
                result.Errors.Add(new PolicyLoadError(name, string.Concat("加载失败：", ex.Message)));
            }
        }
        return result;
    }

    private TrustDocument LoadTrust()
    {
        try
        {
            if (File.Exists(TrustPath))
                return JsonSerializer.Deserialize<TrustDocument>(File.ReadAllText(TrustPath), PolicyJson.Options) ?? new TrustDocument();
        }
        catch { }
        return new TrustDocument();
    }

    private sealed class TrustDocument
    {
        public int SchemaVersion { get; set; } = 1;
        public List<TrustedPlugin> Plugins { get; set; } = new();
    }

    private sealed class TrustedPlugin
    {
        public string File { get; set; } = string.Empty;
        public string Sha256 { get; set; } = string.Empty;
    }
}
