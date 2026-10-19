using System.Text.Json;
using BaguetteAV.EDR.Core.Models;

namespace BaguetteAV.EDR.Core.Policy;

public sealed class PolicyFixtureSample
{
    public TelemetryEvent Event { get; set; } = new();
    public ProcessContext Process { get; set; } = new();
}

public sealed class PolicyFixtureDocument
{
    public int SchemaVersion { get; set; } = 1;
    public DateTime CapturedAt { get; set; } = DateTime.Now;
    public string Source { get; set; } = "B-EDR";
    public List<PolicyFixtureSample> Samples { get; set; } = new();
}

public sealed record PolicyFixtureLoadResult(bool Success, string Message, IReadOnlyList<PolicyFixtureSample> Samples);

public static class PolicyFixtures
{
    public const int MaxBytes = 16 * 1024 * 1024;
    public const int MaxSamples = 10000;

    public static PolicyFixtureLoadResult Load(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return new PolicyFixtureLoadResult(false, "样本文件不存在", Array.Empty<PolicyFixtureSample>());
            if (info.Length > MaxBytes) return new PolicyFixtureLoadResult(false, "样本文件超过 16 MB 限制", Array.Empty<PolicyFixtureSample>());
            return Parse(File.ReadAllText(path));
        }
        catch (Exception ex)
        {
            return new PolicyFixtureLoadResult(false, string.Concat("读取样本失败：", ex.Message), Array.Empty<PolicyFixtureSample>());
        }
    }

    public static PolicyFixtureLoadResult Parse(string json)
    {
        try
        {
            var samples = Deserialize(json);
            if (samples.Count > MaxSamples)
                return new PolicyFixtureLoadResult(false, string.Concat("样本数量不能超过 ", MaxSamples), Array.Empty<PolicyFixtureSample>());
            return new PolicyFixtureLoadResult(true, string.Concat("已加载 ", samples.Count, " 个样本"), samples);
        }
        catch (Exception ex)
        {
            return new PolicyFixtureLoadResult(false, string.Concat("样本格式无效：", ex.Message), Array.Empty<PolicyFixtureSample>());
        }
    }

    public static string Serialize(IEnumerable<PolicyFixtureSample> samples, string source = "B-EDR")
    {
        var document = new PolicyFixtureDocument
        {
            CapturedAt = DateTime.Now,
            Source = source,
            Samples = samples.ToList()
        };
        return JsonSerializer.Serialize(document, PolicyJson.Options);
    }

    public static bool Save(string path, IEnumerable<PolicyFixtureSample> samples, string source = "B-EDR")
    {
        try
        {
            var full = Path.GetFullPath(path);
            Directory.CreateDirectory(Path.GetDirectoryName(full) ?? ".");
            var temp = string.Concat(full, ".tmp");
            File.WriteAllText(temp, Serialize(samples, source), new System.Text.UTF8Encoding(false));
            File.Move(temp, full, true);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static List<PolicyFixtureSample> Deserialize(string json)
    {
        using var document = JsonDocument.Parse(json, new JsonDocumentOptions
        {
            AllowTrailingCommas = true,
            CommentHandling = JsonCommentHandling.Skip,
            MaxDepth = 64
        });
        if (document.RootElement.ValueKind == JsonValueKind.Array)
            return JsonSerializer.Deserialize<List<PolicyFixtureSample>>(json, PolicyJson.Options) ?? new List<PolicyFixtureSample>();
        var fixture = JsonSerializer.Deserialize<PolicyFixtureDocument>(json, PolicyJson.Options);
        return fixture?.Samples ?? new List<PolicyFixtureSample>();
    }
}
