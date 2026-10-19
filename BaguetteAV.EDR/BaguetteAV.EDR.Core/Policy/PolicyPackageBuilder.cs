using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace BaguetteAV.EDR.Core.Policy;

public static class PolicyPackageBuilder
{
    public static PolicyPackageBuildResult Build(
        string policyPath,
        string testsPath,
        string? fixturesPath,
        string? readmePath,
        string privateKeyPath,
        string publisherName,
        string outputPath,
        bool requireAllRulesCovered = true,
        bool requireNegativeCase = true)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(publisherName))
                return new(false, "发布者名称不能为空", null);
            if (!File.Exists(policyPath)) return new(false, "策略文件不存在", null);
            if (!File.Exists(testsPath)) return new(false, "回归测试文件不存在", null);
            if (!File.Exists(privateKeyPath)) return new(false, "私钥文件不存在", null);

            var policyBytes = File.ReadAllBytes(policyPath);
            var policyJson = new UTF8Encoding(false).GetString(policyBytes);
            var validation = PolicyValidator.ValidateJson(policyJson, out var pack);
            if (pack is null || !validation.IsValid)
                return new(false, string.Concat("策略校验失败：", string.Join("；", validation.Errors.Take(4))), null);

            var testsBytes = File.ReadAllBytes(testsPath);
            var testsJson = new UTF8Encoding(false).GetString(testsBytes);
            var loaded = PolicyTestSuiteLoader.Parse(testsJson);
            if (!loaded.Success || loaded.Suite is null)
                return new(false, loaded.Message, null);

            var suite = loaded.Suite;
            if (requireAllRulesCovered)
            {
                var uncovered = PolicyPackageQuality.GetUncoveredEnabledRuleIds(pack, suite);
                if (uncovered.Count > 0)
                    return new(false, string.Concat("启用规则缺少正样本：", string.Join(",", uncovered)), null);
            }
            if (requireNegativeCase && !PolicyPackageQuality.HasNegativeCase(suite))
                return new(false, "回归集缺少严格负样本", null);
            var testResult = PolicyTestRunner.Run(pack, suite);
            if (!testResult.Success)
            {
                var problems = testResult.Cases
                    .Where(testCase => !testCase.Passed)
                    .SelectMany(testCase => testCase.Problems.Select(problem => string.Concat(testCase.Name, "：", problem)));
                return new(false, string.Concat("回归测试失败：", string.Join("；", problems.Take(4))), null);
            }

            using var key = ECDsa.Create();
            key.ImportFromPem(File.ReadAllText(privateKeyPath, Encoding.UTF8));
            if (key.KeySize != 256) return new(false, "仅支持P-256ECDSA私钥", null);
            var keyId = PolicyTrustStore.ComputeKeyId(key);

            var files = new List<PolicyPackageFile>
            {
                CreateFile("policy.json", "policy", policyBytes)
            };
            AddSourceFile(files, "tests.json", "tests", testsPath);
            AddSourceFile(files, "fixtures.json", "fixtures", fixturesPath);
            AddSourceFile(files, "README.md", "readme", readmePath);
            if (files.Select(file => file.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != files.Count)
                return new(false, "策略包文件角色冲突", null);
            if (files.Sum(file => file.Size) > PolicyPackageConstants.MaxExpandedBytes)
                return new(false, "策略包解压后超过16MB", null);

            var manifest = new PolicyPackageManifest
            {
                PackageId = pack.Id,
                PolicyId = pack.Id,
                PolicyVersion = pack.Version,
                CreatedAt = DateTimeOffset.Now,
                Publisher = new PolicyPackagePublisher
                {
                    Name = publisherName.Trim(),
                    KeyId = keyId,
                    Algorithm = PolicyPackageConstants.Algorithm
                },
                PolicyFile = "policy.json",
                TestsFile = "tests.json",
                QualityGate = new PolicyPackageQualityGate
                {
                    RequireTests = true,
                    RequireAllEnabledRulesCovered = requireAllRulesCovered,
                    RequireNegativeCase = requireNegativeCase
                },
                Files = files
            };
            var manifestJson = PolicyPackageQuality.SerializeManifest(manifest);
            var manifestBytes = new UTF8Encoding(false).GetBytes(manifestJson);
            var signature = key.SignData(
                manifestBytes,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            var signatureText = Convert.ToBase64String(signature);

            var outputFullPath = System.IO.Path.GetFullPath(outputPath);
            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(outputFullPath) ?? ".");
            var temporary = string.Concat(outputFullPath, ".tmp");
            using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var archive = new ZipArchive(stream, ZipArchiveMode.Create))
            {
                AddEntry(archive, PolicyPackageConstants.ManifestEntry, manifestBytes);
                AddEntry(archive, PolicyPackageConstants.SignatureEntry, Encoding.ASCII.GetBytes(signatureText));
                foreach (var file in files)
                {
                    var bytes = file.Role switch
                    {
                        "policy" => policyBytes,
                        "tests" => testsBytes,
                        "fixtures" => File.ReadAllBytes(fixturesPath!),
                        "readme" => File.ReadAllBytes(readmePath!),
                        _ => Array.Empty<byte>()
                    };
                    AddEntry(archive, file.Path, bytes);
                }
            }
            File.Move(temporary, outputFullPath, true);
            return new(true, string.Concat("策略包已生成：", outputFullPath), outputFullPath);
        }
        catch (Exception ex)
        {
            return new(false, string.Concat("生成策略包失败：", ex.Message), null);
        }
    }

    private static void AddSourceFile(
        List<PolicyPackageFile> files,
        string targetName,
        string role,
        string? sourcePath)
    {
        if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath)) return;
        files.Add(CreateFile(targetName, role, File.ReadAllBytes(sourcePath)));
    }

    private static PolicyPackageFile CreateFile(string name, string role, byte[] bytes) => new()
    {
        Path = name,
        Role = role,
        Sha256 = PolicyPackageQuality.ComputeSha256(bytes),
        Size = bytes.Length
    };

    private static void AddEntry(ZipArchive archive, string name, byte[] bytes)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using var stream = entry.Open();
        stream.Write(bytes);
    }
}
