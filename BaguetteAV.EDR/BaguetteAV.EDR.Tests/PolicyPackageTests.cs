using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using BaguetteAV.EDR.Core.Policy;

namespace BaguetteAV.EDR.Tests;

public sealed class PolicyPackageTests : IDisposable
{
    private readonly string _root = Path.Combine(
        Path.GetTempPath(), "b-edr-package-tests", Guid.NewGuid().ToString("N"));

    private const string PolicyJson = """
    {
      "schemaVersion": 1,
      "id": "research.package.test",
      "name": "签名策略包测试",
      "version": "1.0.0",
      "author": "B-EDR Lab",
      "description": "验证签名导入、回归门禁和热加载复验",
      "minEngineVersion": "2.0.0",
      "tags": ["package", "research"],
      "rules": [
        {
          "id": "PKG-FILE-001",
          "name": "用户目录驱动落地",
          "description": "用户可写目录出现sys文件",
          "mitre": "T1014",
          "severity": "High",
          "score": 24,
          "eventKinds": ["FileCreate"],
          "condition": {
            "all": [
              { "field": "file.path", "op": "endswith", "value": ".sys" },
              { "field": "process.userwritable", "op": "eq", "value": "true" }
            ]
          }
        },
        {
          "id": "PKG-NET-001",
          "name": "研究C2外联",
          "description": "连接8443端口",
          "mitre": "T1071",
          "severity": "Critical",
          "score": 30,
          "response": "block_destination",
          "eventKinds": ["NetworkConnect"],
          "condition": {
            "field": "network.destination.port",
            "op": "eq",
            "value": 8443
          }
        }
      ]
    }
    """;

    private const string TestsJson = """
    {
      "schemaVersion": 1,
      "name": "签名策略包回归测试",
      "strict": false,
      "cases": [
        {
          "name": "驱动落地正样本",
          "expect": ["PKG-FILE-001"],
          "event": {
            "kind": "FileCreate",
            "processId": 4100,
            "filePath": "C:\\Users\\Public\\variantF.sys"
          },
          "process": {
            "processId": 4100,
            "imagePath": "C:\\Users\\Public\\loader.exe",
            "isUserWritable": true
          }
        },
        {
          "name": "C2外联正样本",
          "expect": ["PKG-NET-001"],
          "event": {
            "kind": "NetworkConnect",
            "processId": 4100,
            "destinationIp": "192.168.127.100",
            "destinationPort": 8443
          },
          "process": {
            "processId": 4100,
            "imagePath": "C:\\Users\\Public\\np_rce.exe",
            "isUserWritable": true
          }
        },
        {
          "name": "正常系统文件静默",
          "expect": [],
          "strict": true,
          "event": {
            "kind": "FileCreate",
            "processId": 4,
            "filePath": "C:\\Windows\\System32\\drivers\\disk.sys"
          },
          "process": {
            "processId": 4,
            "imagePath": "C:\\Windows\\System32\\drivers\\disk.sys",
            "isUserWritable": false,
            "isSigned": true
          }
        }
      ]
    }
    """;

    [Fact]
    public void SignedPackageVerifiesInstallsAndReloads()
    {
        var trustStore = CreateTrustedPackage(out var packagePath);
        var inspection = PolicyPackageVerifier.Verify(packagePath, trustStore);
        Assert.True(inspection.Success, inspection.Message);
        Assert.True(inspection.SignatureValid);
        Assert.True(inspection.PublisherTrusted);
        Assert.Equal(3, inspection.TestResult!.PassedCount);
        Assert.Equal(2, inspection.CoveredEnabledRuleCount);

        var repository = new PolicyRepository(Path.Combine(_root, "policies"));
        var result = repository.InstallPackageFromFile(packagePath);
        Assert.True(result.Success, result.Message);
        Assert.True(result.Policy!.SignatureVerified);
        Assert.Equal(3, result.Policy.TestPassedCount);
        Assert.Equal("lab", result.Policy.Publisher);

        var active = repository.LoadActive();
        Assert.Empty(active.Errors);
        Assert.Single(active.Packs);
        Assert.Equal("research.package.test", active.Packs[0].Id);
    }

    [Fact]
    public void UnknownPublisherIsRejected()
    {
        CreateTrustedPackage(out var packagePath);
        var untrusted = new PolicyTrustStore(Path.Combine(_root, "untrusted-policies"));
        var inspection = PolicyPackageVerifier.Verify(packagePath, untrusted);
        Assert.False(inspection.Success);
        Assert.Contains("信任清单", inspection.Message);
    }

    [Fact]
    public void TamperedPackageFileIsRejected()
    {
        var trustStore = CreateTrustedPackage(out var packagePath);
        ReplaceZipEntry(packagePath, "policy.json",
            Encoding.UTF8.GetBytes(string.Concat(PolicyJson, Environment.NewLine)));
        var inspection = PolicyPackageVerifier.Verify(packagePath, trustStore);
        Assert.False(inspection.Success);
        Assert.Contains("不匹配", inspection.Message);
    }

    [Fact]
    public void InstalledPackageIsReverifiedDuringReload()
    {
        var repository = new PolicyRepository(Path.Combine(_root, "policies"));
        CreateTrustedPackage(out var packagePath, repository.Root);
        Assert.True(repository.InstallPackageFromFile(packagePath).Success);
        var installedPackage = Path.Combine(
            repository.InstalledDirectory,
            "research.package.test",
            "1.0.0",
            "package.bedrpack");
        ReplaceZipEntry(installedPackage, "policy.json",
            Encoding.UTF8.GetBytes(string.Concat(PolicyJson, Environment.NewLine)));

        var active = repository.LoadActive();
        Assert.Empty(active.Packs);
        Assert.Contains(active.Errors,
            error => error.Message.Contains("复验失败"));
    }

    [Fact]
    public void RevokingPublisherFailsClosedOnReloadAndReimport()
    {
        var repository = new PolicyRepository(Path.Combine(_root, "policies"));
        var trustStore = CreateTrustedPackage(out var packagePath, repository.Root);
        Assert.True(repository.InstallPackageFromFile(packagePath).Success);
        var publisher = Assert.Single(trustStore.List(out var listError));
        Assert.Equal(string.Empty, listError);

        var revoked = trustStore.RemovePublisher(publisher.KeyId);

        Assert.True(revoked.Success, revoked.Message);
        Assert.Empty(trustStore.List(out _));
        var active = repository.LoadActive();
        Assert.Empty(active.Packs);
        Assert.Contains(active.Errors, error =>
            error.Message.Contains("复验失败") && error.Message.Contains("信任清单"));
        var listed = Assert.Single(repository.List());
        Assert.True(listed.Active);
        Assert.False(listed.EffectiveActive);
        Assert.Contains("信任清单", listed.LoadError);
        var reimport = repository.InstallPackageFromFile(packagePath);
        Assert.False(reimport.Success);
        Assert.Contains("信任清单", reimport.Message);
        var audit = File.ReadAllText(trustStore.AuditPath);
        Assert.Contains("\"action\":\"trust\"", audit);
        Assert.Contains("\"action\":\"revoke\"", audit);
    }

    [Fact]
    public void TrustChangeFailsClosedWhenAuditTrailIsNotWritable()
    {
        var root = Path.Combine(_root, "audit-import");
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(Path.Combine(root, "trust-audit.jsonl"));
        var publicKey = Path.Combine(Path.GetDirectoryName(CreateKey())!, "public.pem");
        var store = new PolicyTrustStore(root);

        var result = store.ImportPublicKey(publicKey, "lab");

        Assert.False(result.Success);
        Assert.Contains("审计", result.Message);
        Assert.Empty(store.List(out var listError));
        Assert.Equal(string.Empty, listError);
    }

    [Fact]
    public void RevokeFailsClosedWhenAuditTrailIsNotWritable()
    {
        var root = Path.Combine(_root, "audit-revoke");
        var publicKey = Path.Combine(Path.GetDirectoryName(CreateKey())!, "public.pem");
        var store = new PolicyTrustStore(root);
        Assert.True(store.ImportPublicKey(publicKey, "lab").Success);
        var publisher = Assert.Single(store.List(out _));
        File.Delete(store.AuditPath);
        Directory.CreateDirectory(store.AuditPath);

        var revoked = store.RemovePublisher(publisher.KeyId);

        Assert.False(revoked.Success);
        Assert.Contains("审计", revoked.Message);
        Assert.Single(store.List(out _));
    }

    [Fact]
    public void PackageInstallCommitsCompleteVersionAndCleansStaging()
    {
        var repository = new PolicyRepository(Path.Combine(_root, "policies"));
        CreateTrustedPackage(out var packagePath, repository.Root);

        var result = repository.InstallPackageFromFile(packagePath);

        Assert.True(result.Success, result.Message);
        var versionDirectory = Path.Combine(
            repository.InstalledDirectory, "research.package.test", "1.0.0");
        foreach (var name in new[]
                 {
                     "policy.json", "tests.json", "manifest.json", "manifest.sig",
                     "meta.json", "package.bedrpack"
                 })
            Assert.True(File.Exists(Path.Combine(versionDirectory, name)), name);
        Assert.False(Directory.Exists(Path.Combine(repository.Root, ".staging")));

        var repeated = repository.InstallPackageFromFile(packagePath);

        Assert.True(repeated.Success, repeated.Message);
        Assert.False(Directory.Exists(Path.Combine(repository.Root, ".staging")));
    }

    [Fact]
    public void BuilderRejectsFailingRegressionCase()
    {
        var files = CreateSourceFiles();
        File.WriteAllText(files.Tests,
            TestsJson.Replace("\"PKG-FILE-001\"", "\"PKG-FILE-999\""),
            new UTF8Encoding(false));
        var keyPath = CreateKey();
        var result = PolicyPackageBuilder.Build(
            files.Policy,
            files.Tests,
            null,
            null,
            keyPath,
            "lab",
            Path.Combine(_root, "bad.bedrpack"));
        Assert.False(result.Success);
        Assert.Contains("正样本", result.Message);
    }

    private PolicyTrustStore CreateTrustedPackage(
        out string packagePath,
        string? policyRoot = null)
    {
        var policyDirectory = policyRoot ?? Path.Combine(_root, "policies");
        var files = CreateSourceFiles();
        var keyPath = CreateKey();
        packagePath = Path.Combine(_root, "research.package.test.bedrpack");
        var build = PolicyPackageBuilder.Build(
            files.Policy,
            files.Tests,
            files.Fixtures,
            null,
            keyPath,
            "lab",
            packagePath);
        Assert.True(build.Success, build.Message);
        var trustStore = new PolicyTrustStore(policyDirectory);
        var publicKey = Path.Combine(Path.GetDirectoryName(keyPath)!, "public.pem");
        var trust = trustStore.ImportPublicKey(publicKey, "lab");
        Assert.True(trust.Success, trust.Message);
        return trustStore;
    }

    private (string Policy, string Tests, string Fixtures) CreateSourceFiles()
    {
        var dir = Path.Combine(_root, "source");
        Directory.CreateDirectory(dir);
        var policy = Path.Combine(dir, "policy.json");
        var tests = Path.Combine(dir, "tests.json");
        var fixtures = Path.Combine(dir, "fixtures.json");
        File.WriteAllText(policy, PolicyJson, new UTF8Encoding(false));
        File.WriteAllText(tests, TestsJson, new UTF8Encoding(false));
        File.WriteAllText(fixtures,
            """{"schemaVersion":1,"source":"test","samples":[]}""",
            new UTF8Encoding(false));
        return (policy, tests, fixtures);
    }

    private string CreateKey()
    {
        var dir = Path.Combine(_root, "keys");
        Directory.CreateDirectory(dir);
        var privateKey = Path.Combine(dir, "private.pem");
        var publicKey = Path.Combine(dir, "public.pem");
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        File.WriteAllText(privateKey, key.ExportPkcs8PrivateKeyPem(), new UTF8Encoding(false));
        File.WriteAllText(publicKey, key.ExportSubjectPublicKeyInfoPem(), new UTF8Encoding(false));
        return privateKey;
    }

    private static void ReplaceZipEntry(string path, string entryName, byte[] bytes)
    {
        using var archive = ZipFile.Open(path, ZipArchiveMode.Update);
        archive.GetEntry(entryName)?.Delete();
        var entry = archive.CreateEntry(entryName);
        using var stream = entry.Open();
        stream.Write(bytes);
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_root)) Directory.Delete(_root, true); } catch { }
    }
}
