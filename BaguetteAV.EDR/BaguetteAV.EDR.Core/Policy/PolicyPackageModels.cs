using System.Security.Cryptography;
using System.Text.Json;

namespace BaguetteAV.EDR.Core.Policy;

public static class PolicyPackageConstants
{
    public const int SchemaVersion = 1;
    public const long MaxPackageBytes = 8L * 1024 * 1024;
    public const long MaxExpandedBytes = 16L * 1024 * 1024;
    public const long MaxManifestBytes = 256L * 1024;
    public const int MaxFiles = 32;
    public const string ManifestEntry = "manifest.json";
    public const string SignatureEntry = "manifest.sig";
    public const string Algorithm = "ECDSA-P256-SHA256";
}

public sealed class PolicyPackageManifest
{
    public int SchemaVersion { get; set; } = PolicyPackageConstants.SchemaVersion;
    public string PackageId { get; set; } = string.Empty;
    public string PolicyId { get; set; } = string.Empty;
    public string PolicyVersion { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public PolicyPackagePublisher Publisher { get; set; } = new();
    public string PolicyFile { get; set; } = "policy.json";
    public string TestsFile { get; set; } = "tests.json";
    public PolicyPackageQualityGate QualityGate { get; set; } = new();
    public List<PolicyPackageFile> Files { get; set; } = new();
}

public sealed class PolicyPackagePublisher
{
    public string Name { get; set; } = string.Empty;
    public string KeyId { get; set; } = string.Empty;
    public string Algorithm { get; set; } = PolicyPackageConstants.Algorithm;
}

public sealed class PolicyPackageQualityGate
{
    public bool RequireTests { get; set; } = true;
    public bool RequireAllEnabledRulesCovered { get; set; } = true;
    public bool RequireNegativeCase { get; set; } = true;
}

public sealed class PolicyPackageFile
{
    public string Path { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public string Sha256 { get; set; } = string.Empty;
    public long Size { get; set; }
}

public sealed class PolicyPackageInspection
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public string PackageSha256 { get; init; } = string.Empty;
    public string ManifestSha256 { get; init; } = string.Empty;
    public string TestSuiteSha256 { get; init; } = string.Empty;
    public string PublisherName { get; init; } = string.Empty;
    public string PublisherKeyId { get; init; } = string.Empty;
    public string PublisherAlgorithm { get; init; } = string.Empty;
    public bool SignatureValid { get; init; }
    public bool PublisherTrusted { get; init; }
    public PolicyPack? Pack { get; init; }
    public PolicyTestSuite? Tests { get; init; }
    public PolicyTestRunResult? TestResult { get; init; }
    public PolicyValidationResult? Validation { get; init; }
    public int CoveredEnabledRuleCount { get; init; }
    public int EnabledRuleCount { get; init; }
    public List<string> UncoveredRuleIds { get; init; } = new();
    public List<string> Capabilities { get; init; } = new();
    public string RiskLevel { get; init; } = "Standard";
    public List<string> Warnings { get; init; } = new();
    public string PolicyJson { get; init; } = string.Empty;
    public string TestsJson { get; init; } = string.Empty;
    public string ManifestJson { get; init; } = string.Empty;
    public string SignatureText { get; init; } = string.Empty;
}

public sealed record PolicyPackageBuildResult(bool Success, string Message, string? Path);

public sealed record PolicyTrustKeyResult(bool Success, string Message, TrustedPublisher? Publisher);

public sealed class TrustedPublisher
{
    public string Name { get; set; } = string.Empty;
    public string KeyId { get; set; } = string.Empty;
    public string Algorithm { get; set; } = PolicyPackageConstants.Algorithm;
    public string PublicKeyPem { get; set; } = string.Empty;
    public DateTimeOffset TrustedAt { get; set; }
}

public static class PolicyPackageQuality
{
    public static HashSet<string> GetUncoveredEnabledRuleIds(
        PolicyPack pack, PolicyTestSuite suite)
    {
        var expected = suite.Cases
            .SelectMany(testCase => testCase.Expect ?? new List<string>())
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        return pack.Rules
            .Where(rule => rule.Enabled && !expected.Contains(rule.Id))
            .Select(rule => rule.Id)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public static bool HasNegativeCase(PolicyTestSuite suite)
    {
        return suite.Strict || suite.Cases.Any(testCase =>
            testCase.Strict == true ||
            ((testCase.Expect?.Count ?? 0) == 0 &&
             (testCase.Forbid?.Count ?? 0) > 0));
    }

    public static List<string> GetCapabilities(PolicyPack pack)
    {
        var capabilities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var rule in pack.Rules.Where(rule => rule.Enabled))
        {
            foreach (var kind in rule.EventKinds)
            {
                capabilities.Add(kind switch
                {
                    "FileCreate" => "file",
                    "DriverLoad" => "driver",
                    "NetworkConnect" => "network",
                    "WmiFilter" or "WmiConsumer" or "WmiBinding" => "wmi",
                    "ProcessAccess" => "process-access",
                    "RemoteThread" => "remote-thread",
                    _ => kind
                });
            }

            var response = (rule.Response ?? string.Empty).ToLowerInvariant();
            if (response is not "" and not "inherit" and not "alert")
            {
                capabilities.Add("active-response");
                if (response is "terminate" or "terminate_process") capabilities.Add("terminate-process");
                if (response is "quarantine" or "quarantine_file") capabilities.Add("quarantine");
                if (response is "block" or "block_destination") capabilities.Add("network-block");
                if (response == "contain") capabilities.Add("contain");
            }
        }
        return capabilities.OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static string GetRiskLevel(PolicyPack pack, IEnumerable<string> capabilities)
    {
        var values = capabilities.ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (values.Contains("driver") && pack.Rules.Any(rule =>
                string.Equals(rule.Severity, "Critical", StringComparison.OrdinalIgnoreCase)))
            return "KernelSensitive";
        if (values.Contains("active-response")) return "ActiveResponse";
        if (values.Contains("driver") || values.Contains("process-access") || values.Contains("remote-thread"))
            return "HighVisibility";
        return "DetectionOnly";
    }

    public static string ComputeSha256(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    public static string SerializeManifest(PolicyPackageManifest manifest) =>
        JsonSerializer.Serialize(manifest, PolicyJson.Options);
}
