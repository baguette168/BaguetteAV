using System.IO.Compression;

namespace BaguetteAV.EDR.Core.Policy;

public static partial class PolicyPackageVerifier
{
    public static PolicyPackageInspection Verify(
        string packagePath,
        PolicyTrustStore trustStore,
        bool allowUntrusted = false)
    {
        try
        {
            var info = new FileInfo(packagePath);
            if (!info.Exists) return Fail("策略包不存在");
            if (info.Length > PolicyPackageConstants.MaxPackageBytes)
                return Fail("策略包超过8MB");
            return Verify(File.ReadAllBytes(packagePath), packagePath, trustStore, allowUntrusted);
        }
        catch (Exception ex)
        {
            return Fail(string.Concat("读取策略包失败：", ex.Message));
        }
    }

    public static PolicyPackageInspection Verify(
        byte[] packageBytes,
        string sourceName,
        PolicyTrustStore trustStore,
        bool allowUntrusted = false)
    {
        try
        {
            if (packageBytes.Length == 0) return Fail("策略包为空");
            if (packageBytes.Length > PolicyPackageConstants.MaxPackageBytes)
                return Fail("策略包超过8MB");
            return VerifyCore(packageBytes, trustStore, allowUntrusted);
        }
        catch (Exception ex)
        {
            return Fail(string.Concat("校验策略包失败：", ex.Message));
        }
    }

    private static PolicyPackageInspection Fail(
        string message,
        PolicyValidationResult? validation = null) => new()
    {
        Success = false,
        Message = message,
        Validation = validation
    };

    private static bool IsSafeFileName(string name) =>
        !string.IsNullOrWhiteSpace(name) &&
        name.Length <= 128 &&
        name is not "." and not ".." &&
        name.IndexOfAny(new[] { '/', '\\', ':' }) < 0 &&
        name.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) < 0;

    private static bool IsSha256(string value) =>
        value.Length == 64 && value.All(character =>
            (character >= '0' && character <= '9') ||
            (character >= 'a' && character <= 'f') ||
            (character >= 'A' && character <= 'F'));

    private static byte[]? ReadEntry(
        IReadOnlyDictionary<string, ZipArchiveEntry> entries,
        string name,
        long maxBytes,
        out string error)
    {
        error = string.Empty;
        if (!entries.TryGetValue(name, out var entry))
        {
            error = string.Concat("策略包缺少文件：", name);
            return null;
        }
        try
        {
            using var input = entry.Open();
            using var output = new MemoryStream();
            var buffer = new byte[81920];
            long total = 0;
            while (true)
            {
                var read = input.Read(buffer, 0, buffer.Length);
                if (read <= 0) break;
                total += read;
                if (total > maxBytes)
                {
                    error = string.Concat("文件超过解压上限：", name);
                    return null;
                }
                output.Write(buffer, 0, read);
            }
            return output.ToArray();
        }
        catch (Exception ex)
        {
            error = string.Concat("读取文件失败：", name, "，", ex.Message);
            return null;
        }
    }
}
