using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace BaguetteAV.EDR.Core.Policy;

public sealed class PolicyTrustStore
{
    private readonly object _gate = new();
    private readonly string _root;

    public PolicyTrustStore(string root) => _root = root;

    public string Path => System.IO.Path.Combine(_root, "trusted-publishers.json");
    public string AuditPath => System.IO.Path.Combine(_root, "trust-audit.jsonl");

    public IReadOnlyList<TrustedPublisher> List(out string error)
    {
        lock (_gate)
        {
            if (!TryLoad(out var document, out error)) return Array.Empty<TrustedPublisher>();
            return document.Publishers.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }
    }

    public PolicyTrustKeyResult ImportPublicKey(string path, string? displayName = null)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists) return new(false, "公钥文件不存在", null);
            if (info.Length > 65536) return new(false, "公钥文件超过64KB", null);
            return ImportPublicKeyPem(File.ReadAllText(path, Encoding.UTF8), displayName);
        }
        catch (Exception ex)
        {
            return new(false, ex.Message, null);
        }
    }

    public PolicyTrustKeyResult ImportPublicKeyPem(string pem, string? displayName = null)
    {
        lock (_gate)
        {
            try
            {
                using var key = ECDsa.Create();
                key.ImportFromPem(pem);
                if (key.KeySize != 256) return new(false, "仅支持P-256ECDSA发布者公钥", null);
                var keyId = ComputeKeyId(key);
                if (!TryLoad(out var document, out var loadError))
                    return new(false, string.Concat("信任清单不可用：", loadError), null);
                var publisher = document.Publishers.FirstOrDefault(item =>
                    string.Equals(item.KeyId, keyId, StringComparison.OrdinalIgnoreCase));
                if (publisher is null)
                {
                    publisher = new TrustedPublisher { KeyId = keyId };
                    document.Publishers.Add(publisher);
                }
                if (!string.IsNullOrWhiteSpace(displayName)) publisher.Name = displayName.Trim();
                if (string.IsNullOrWhiteSpace(publisher.Name)) publisher.Name = keyId[..12];
                publisher.Algorithm = PolicyPackageConstants.Algorithm;
                publisher.PublicKeyPem = key.ExportSubjectPublicKeyInfoPem();
                publisher.TrustedAt = DateTimeOffset.Now;
                Directory.CreateDirectory(_root);
                if (!TryCaptureFile(Path, out var previous))
                    return new(false, "无法读取现有信任清单，拒绝修改", null);
                AtomicWrite(Path, JsonSerializer.Serialize(document, PolicyJson.Options));
                var auditError = TryAppendAudit("trust", publisher);
                if (auditError.Length > 0)
                {
                    var rollbackError = RestoreFile(Path, previous);
                    return new(false, rollbackError.Length == 0
                        ? string.Concat("信任审计不可写，已回滚信任变更：", auditError)
                        : string.Concat("信任审计不可写，信任回滚失败：", auditError, "；", rollbackError), null);
                }
                return new(true, string.Concat("已信任发布者：", publisher.Name), publisher);
            }
            catch (Exception ex)
            {
                return new(false, ex.Message, null);
            }
        }
    }

    public PolicyTrustKeyResult RemovePublisher(string keyId)
    {
        lock (_gate)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(keyId) || keyId.Length != 64)
                    return new(false, "发布者 KeyId 无效", null);
                if (!TryLoad(out var document, out var loadError))
                    return new(false, string.Concat("信任清单不可用：", loadError), null);
                var publisher = document.Publishers.FirstOrDefault(item =>
                    string.Equals(item.KeyId, keyId, StringComparison.OrdinalIgnoreCase));
                if (publisher is null) return new(false, "发布者不在本机信任清单中", null);
                if (!TryCaptureFile(Path, out var previous))
                    return new(false, "无法读取现有信任清单，拒绝修改", null);
                document.Publishers.Remove(publisher);
                AtomicWrite(Path, JsonSerializer.Serialize(document, PolicyJson.Options));
                var auditError = TryAppendAudit("revoke", publisher);
                if (auditError.Length > 0)
                {
                    var rollbackError = RestoreFile(Path, previous);
                    return new(false, rollbackError.Length == 0
                        ? string.Concat("信任审计不可写，已回滚撤销操作：", auditError)
                        : string.Concat("信任审计不可写，信任回滚失败：", auditError, "；", rollbackError), null);
                }
                return new(true, string.Concat("已撤销发布者信任：", publisher.Name), publisher);
            }
            catch (Exception ex)
            {
                return new(false, string.Concat("撤销发布者失败：", ex.Message), null);
            }
        }
    }

    public bool TryGetPublisher(string keyId, string algorithm,
        out TrustedPublisher? publisher, out string error)
    {
        lock (_gate)
        {
            publisher = null;
            if (!TryLoad(out var document, out error)) return false;
            if (!string.Equals(algorithm, PolicyPackageConstants.Algorithm, StringComparison.Ordinal))
            {
                error = string.Concat("不支持的签名算法：", algorithm);
                return false;
            }
            publisher = document.Publishers.FirstOrDefault(item =>
                string.Equals(item.KeyId, keyId, StringComparison.OrdinalIgnoreCase));
            if (publisher is null)
            {
                error = "发布者公钥不在本机信任清单中";
                return false;
            }
            if (!string.Equals(publisher.Algorithm, PolicyPackageConstants.Algorithm, StringComparison.Ordinal))
            {
                error = "信任清单中的发布者算法无效";
                publisher = null;
                return false;
            }
            return true;
        }
    }

    public static string ComputeKeyId(ECDsa key) =>
        Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo())).ToLowerInvariant();

    private bool TryLoad(out TrustDocument document, out string error)
    {
        document = new TrustDocument();
        error = string.Empty;
        if (!File.Exists(Path)) return true;
        try
        {
            if (new FileInfo(Path).Length > 2 * 1024 * 1024)
            {
                error = "信任清单超过2MB";
                return false;
            }
            var loaded = JsonSerializer.Deserialize<TrustDocument>(
                File.ReadAllText(Path, Encoding.UTF8), PolicyJson.Options);
            if (loaded is null || loaded.SchemaVersion != 1)
            {
                error = "信任清单格式或版本无效";
                return false;
            }
            loaded.Publishers ??= new List<TrustedPublisher>();
            if (loaded.Publishers.Count > 256)
            {
                error = "信任清单公钥数量超过256";
                return false;
            }
            if (loaded.Publishers.Any(p => string.IsNullOrWhiteSpace(p.KeyId) ||
                    string.IsNullOrWhiteSpace(p.PublicKeyPem) ||
                    !string.Equals(p.Algorithm, PolicyPackageConstants.Algorithm, StringComparison.Ordinal)))
            {
                error = "信任清单包含无效发布者条目";
                return false;
            }
            document = loaded;
            return true;
        }
        catch (Exception ex)
        {
            error = string.Concat("读取信任清单失败：", ex.Message);
            return false;
        }
    }

    private static void AtomicWrite(string path, string content)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path) ?? ".");
        var temporary = string.Concat(path, ".tmp");
        File.WriteAllText(temporary, content, new UTF8Encoding(false));
        File.Move(temporary, path, true);
    }

    private static bool TryCaptureFile(string path, out byte[]? content)
    {
        content = null;
        if (!File.Exists(path)) return true;
        try
        {
            content = File.ReadAllBytes(path);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string RestoreFile(string path, byte[]? content)
    {
        try
        {
            if (content is null)
            {
                if (File.Exists(path)) File.Delete(path);
            }
            else
            {
                var temporary = string.Concat(path, ".restore");
                File.WriteAllBytes(temporary, content);
                File.Move(temporary, path, true);
            }
            return string.Empty;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    private string TryAppendAudit(string action, TrustedPublisher publisher)
    {
        try
        {
            Directory.CreateDirectory(_root);
            var entry = new
            {
                timestamp = DateTimeOffset.Now.ToString("O"),
                action,
                publisher = publisher.Name,
                keyId = publisher.KeyId,
                algorithm = publisher.Algorithm,
                user = Environment.UserName,
                machine = Environment.MachineName
            };
            File.AppendAllText(
                AuditPath,
                string.Concat(JsonSerializer.Serialize(entry), Environment.NewLine),
                new UTF8Encoding(false));
            return string.Empty;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    private sealed class TrustDocument
    {
        public int SchemaVersion { get; set; } = 1;
        public List<TrustedPublisher> Publishers { get; set; } = new();
    }
}
