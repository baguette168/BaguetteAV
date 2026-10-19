namespace BaguetteAV.EDR.Core.Policy;

public static partial class PolicyPackageVerifier
{
    private static readonly HashSet<string> AllowedRoles = new(StringComparer.OrdinalIgnoreCase)
    {
        "policy", "tests", "fixtures", "readme"
    };

    private static string? ValidateManifest(PolicyPackageManifest manifest)
    {
        if (manifest.SchemaVersion != PolicyPackageConstants.SchemaVersion)
            return "策略包schemaVersion无效";
        if (string.IsNullOrWhiteSpace(manifest.PackageId) ||
            string.IsNullOrWhiteSpace(manifest.PolicyId) ||
            string.IsNullOrWhiteSpace(manifest.PolicyVersion))
            return "策略包标识不完整";
        if (string.IsNullOrWhiteSpace(manifest.Publisher.Name) ||
            string.IsNullOrWhiteSpace(manifest.Publisher.KeyId) ||
            !IsSha256(manifest.Publisher.KeyId))
            return "发布者标识无效";
        if (!string.Equals(manifest.Publisher.Algorithm, PolicyPackageConstants.Algorithm,
                StringComparison.Ordinal))
            return "发布者签名算法无效";
        if (manifest.Files.Count < 2 || manifest.Files.Count > PolicyPackageConstants.MaxFiles)
            return "策略包文件数量无效";

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var file in manifest.Files)
        {
            if (!IsSafeFileName(file.Path) ||
                string.Equals(file.Path, PolicyPackageConstants.ManifestEntry, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(file.Path, PolicyPackageConstants.SignatureEntry, StringComparison.OrdinalIgnoreCase))
                return "策略包文件路径无效";
            if (!names.Add(file.Path)) return "策略包文件路径重复";
            if (!AllowedRoles.Contains(file.Role))
                return string.Concat("策略包文件角色无效：", file.Role);
            if (!IsSha256(file.Sha256))
                return string.Concat("策略包文件哈希无效：", file.Path);
            if (file.Size < 0 || file.Size > PolicyPackageConstants.MaxExpandedBytes)
                return string.Concat("策略包文件大小无效：", file.Path);
        }
        return null;
    }
}
