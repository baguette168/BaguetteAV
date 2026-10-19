using System.Security.Cryptography;
using System.Text;

namespace BaguetteAV.EDR.Core.Policy;

public static partial class PolicyPackageVerifier
{
    private static PolicyPackageInspection Inspect(
        PackageContents contents,
        PolicyTrustStore trustStore,
        bool allowUntrusted)
    {
        byte[] signature;
        try { signature = Convert.FromBase64String(contents.SignatureText); }
        catch { return Fail("策略包签名编码无效"); }

        var manifest = contents.Manifest;
        var trusted = trustStore.TryGetPublisher(
            manifest.Publisher.KeyId,
            manifest.Publisher.Algorithm,
            out var publisher,
            out var trustError);
        if (!trusted && !allowUntrusted) return Fail(trustError);

        var warnings = new List<string>();
        var signatureValid = false;
        if (trusted && publisher is not null)
        {
            try
            {
                using var key = ECDsa.Create();
                key.ImportFromPem(publisher.PublicKeyPem);
                if (!string.Equals(PolicyTrustStore.ComputeKeyId(key), manifest.Publisher.KeyId,
                        StringComparison.OrdinalIgnoreCase))
                    return Fail("发布者公钥指纹不匹配");
                signatureValid = key.VerifyData(
                    contents.ManifestBytes,
                    signature,
                    HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            }
            catch (Exception ex)
            {
                return Fail(string.Concat("签名校验失败：", ex.Message));
            }
            if (!signatureValid) return Fail("策略包签名无效");
        }
        else
        {
            warnings.Add("发布者未在本机信任清单中，仅完成结构检查");
        }

        var policyJson = new UTF8Encoding(false).GetString(contents.PolicyBytes);
        var testsJson = new UTF8Encoding(false).GetString(contents.TestsBytes);
        var validation = PolicyValidator.ValidateJson(policyJson, out var pack);
        if (pack is null || !validation.IsValid)
            return Fail("策略内容校验失败", validation);
        if (!string.Equals(pack.Id, manifest.PolicyId, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(pack.Version, manifest.PolicyVersion, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(pack.Id, manifest.PackageId, StringComparison.OrdinalIgnoreCase))
            return Fail("策略ID或版本与清单不一致", validation);

        var loaded = PolicyTestSuiteLoader.Parse(testsJson);
        if (!loaded.Success || loaded.Suite is null)
            return Fail(loaded.Message, validation);
        var suite = loaded.Suite;
        var uncovered = PolicyPackageQuality.GetUncoveredEnabledRuleIds(pack, suite);
        if (manifest.QualityGate.RequireAllEnabledRulesCovered && uncovered.Count > 0)
            return Fail(string.Concat("启用规则缺少正样本：", string.Join(",", uncovered)), validation);
        if (manifest.QualityGate.RequireNegativeCase && !PolicyPackageQuality.HasNegativeCase(suite))
            return Fail("回归集缺少严格负样本", validation);
        var testResult = PolicyTestRunner.Run(pack, suite);
        if (!testResult.Success)
            return Fail("策略包回归测试失败", validation);

        var capabilities = PolicyPackageQuality.GetCapabilities(pack);
        var enabledRuleCount = pack.Rules.Count(rule => rule.Enabled);
        return new PolicyPackageInspection
        {
            Success = true,
            Message = string.Concat("策略包校验通过：", pack.Name, " v", pack.Version),
            PackageSha256 = contents.PackageSha256,
            ManifestSha256 = contents.ManifestSha256,
            TestSuiteSha256 = contents.TestSuiteSha256,
            PublisherName = manifest.Publisher.Name,
            PublisherKeyId = manifest.Publisher.KeyId,
            PublisherAlgorithm = manifest.Publisher.Algorithm,
            SignatureValid = signatureValid,
            PublisherTrusted = trusted,
            Pack = pack,
            Tests = suite,
            TestResult = testResult,
            Validation = validation,
            CoveredEnabledRuleCount = enabledRuleCount - uncovered.Count,
            EnabledRuleCount = enabledRuleCount,
            UncoveredRuleIds = uncovered.OrderBy(id => id, StringComparer.OrdinalIgnoreCase).ToList(),
            Capabilities = capabilities,
            RiskLevel = PolicyPackageQuality.GetRiskLevel(pack, capabilities),
            Warnings = warnings,
            PolicyJson = policyJson,
            TestsJson = testsJson,
            ManifestJson = contents.ManifestJson,
            SignatureText = contents.SignatureText
        };
    }
}
