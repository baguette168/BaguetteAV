using BaguetteAV.EDR.Core.Models;
using System.Text.Json;

namespace BaguetteAV.EDR.Core.Services;

public sealed class SettingsStore
{
    private static readonly JsonSerializerOptions Options = new() { WriteIndented = true, PropertyNameCaseInsensitive = true };
    private readonly object _gate = new();

    public static string DataDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "BaguetteAV", "EDR");

    public string SettingsPath => Path.Combine(DataDirectory, "settings.json");

    public EdrSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                var loaded = JsonSerializer.Deserialize<EdrSettings>(json, Options);
                if (loaded is not null) return Normalize(loaded);
            }
        }
        catch
        {
            // Corrupt settings fall back to safe defaults instead of blocking startup.
        }
        return Normalize(new EdrSettings());
    }

    public bool Save(EdrSettings settings)
    {
        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(DataDirectory);
                var temp = SettingsPath + ".tmp";
                File.WriteAllText(temp, JsonSerializer.Serialize(settings, Options));
                File.Move(temp, SettingsPath, true);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }

    private static EdrSettings Normalize(EdrSettings settings)
    {
        if (string.IsNullOrWhiteSpace(settings.QuarantinePath))
            settings.QuarantinePath = Path.Combine(DataDirectory, "quarantine");
        if (string.IsNullOrWhiteSpace(settings.ScanPath))
            settings.ScanPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (settings.MonitoredPorts.Count == 0) settings.MonitoredPorts.Add(8443);
        if (settings.IocHashes.Count == 0)
        {
            settings.IocHashes.AddRange(new[]
            {
                "89e0db48c954dc3d55c4f318300cc0d0c91347225533970b819384a050d0d338",
                "e23390bfe34149308fb70b25469e8136b165d8da7a01e186ca4ad345ad8d2e5e",
                "2e63c4dfcad8d9bb8745938cbe4fd751f251db1e8fb29ec5cf960294b1c1dbf2",
                "c31155a60478cddeb5ee07ac015a11e974c573294348f4157edf1b6d50ba2a62"
            });
        }
        return settings;
    }
}
