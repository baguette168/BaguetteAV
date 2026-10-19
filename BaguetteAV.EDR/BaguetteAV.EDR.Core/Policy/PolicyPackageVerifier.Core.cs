using System.IO.Compression;
using System.Text;
using System.Text.Json;

namespace BaguetteAV.EDR.Core.Policy;

public static partial class PolicyPackageVerifier
{
    private static PolicyPackageInspection VerifyCore(
        byte[] packageBytes,
        PolicyTrustStore trustStore,
        bool allowUntrusted)
    {
        var contents = ReadPackage(packageBytes, out var error);
        if (contents is null) return Fail(error);
        return Inspect(contents, trustStore, allowUntrusted);
    }

    private static PackageContents? ReadPackage(byte[] packageBytes, out string error)
    {
        error = string.Empty;
        using var archive = new ZipArchive(new MemoryStream(packageBytes, false), ZipArchiveMode.Read);
        var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name))
            {
                error = "策略包不允许目录条目";
                return null;
            }
            if (!IsSafeFileName(entry.Name) || !string.Equals(entry.FullName, entry.Name, StringComparison.Ordinal))
            {
                error = string.Concat("策略包包含非法路径：", entry.FullName);
                return null;
            }
            if (!entries.TryAdd(entry.Name, entry))
            {
                error = string.Concat("策略包包含重复文件：", entry.Name);
                return null;
            }
        }
        if (entries.Count > PolicyPackageConstants.MaxFiles + 2)
        {
            error = "策略包文件数量超过限制";
            return null;
        }

        var manifestBytes = ReadEntry(entries, PolicyPackageConstants.ManifestEntry,
            PolicyPackageConstants.MaxManifestBytes, out error);
        if (manifestBytes is null) return null;
        var signatureBytes = ReadEntry(entries, PolicyPackageConstants.SignatureEntry, 1024, out error);
        if (signatureBytes is null) return null;

        var manifestJson = new UTF8Encoding(false).GetString(manifestBytes);
        var manifest = JsonSerializer.Deserialize<PolicyPackageManifest>(manifestJson, PolicyJson.Options);
        if (manifest is null)
        {
            error = "策略包清单无效";
            return null;
        }
        manifest.Publisher ??= new PolicyPackagePublisher();
        manifest.QualityGate ??= new PolicyPackageQualityGate();
        manifest.Files ??= new List<PolicyPackageFile>();
        error = ValidateManifest(manifest) ?? string.Empty;
        if (error.Length > 0) return null;

        var expected = manifest.Files
            .Select(file => file.Path)
            .Append(PolicyPackageConstants.ManifestEntry)
            .Append(PolicyPackageConstants.SignatureEntry)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (expected.Count != entries.Count || entries.Keys.Any(name => !expected.Contains(name)))
        {
            error = "策略包包含清单外文件";
            return null;
        }

        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        long expandedBytes = manifestBytes.Length + signatureBytes.Length;
        foreach (var file in manifest.Files)
        {
            var bytes = ReadEntry(entries, file.Path, PolicyPackageConstants.MaxExpandedBytes, out error);
            if (bytes is null) return null;
            if (bytes.Length != file.Size)
            {
                error = string.Concat("文件大小不匹配：", file.Path);
                return null;
            }
            if (!string.Equals(PolicyPackageQuality.ComputeSha256(bytes), file.Sha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                error = string.Concat("文件哈希不匹配：", file.Path);
                return null;
            }
            expandedBytes += bytes.Length;
            if (expandedBytes > PolicyPackageConstants.MaxExpandedBytes)
            {
                error = "策略包解压后超过16MB";
                return null;
            }
            files[file.Path] = bytes;
        }

        var policyFile = manifest.Files.SingleOrDefault(file =>
            string.Equals(file.Role, "policy", StringComparison.OrdinalIgnoreCase));
        var testsFile = manifest.Files.SingleOrDefault(file =>
            string.Equals(file.Role, "tests", StringComparison.OrdinalIgnoreCase));
        if (policyFile is null || testsFile is null)
        {
            error = "策略包必须包含policy和tests";
            return null;
        }
        if (!string.Equals(policyFile.Path, manifest.PolicyFile, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(testsFile.Path, manifest.TestsFile, StringComparison.OrdinalIgnoreCase))
        {
            error = "策略包清单文件指向不一致";
            return null;
        }

        return new PackageContents
        {
            Manifest = manifest,
            ManifestJson = manifestJson,
            ManifestBytes = manifestBytes,
            SignatureText = Encoding.ASCII.GetString(signatureBytes).Trim(),
            PolicyBytes = files[policyFile.Path],
            TestsBytes = files[testsFile.Path],
            TestSuiteSha256 = testsFile.Sha256,
            PackageSha256 = PolicyPackageQuality.ComputeSha256(packageBytes),
            ManifestSha256 = PolicyPackageQuality.ComputeSha256(manifestBytes)
        };
    }

    private sealed class PackageContents
    {
        public PolicyPackageManifest Manifest { get; init; } = new();
        public string ManifestJson { get; init; } = string.Empty;
        public byte[] ManifestBytes { get; init; } = Array.Empty<byte>();
        public string SignatureText { get; init; } = string.Empty;
        public byte[] PolicyBytes { get; init; } = Array.Empty<byte>();
        public byte[] TestsBytes { get; init; } = Array.Empty<byte>();
        public string TestSuiteSha256 { get; init; } = string.Empty;
        public string PackageSha256 { get; init; } = string.Empty;
        public string ManifestSha256 { get; init; } = string.Empty;
    }
}
