using BaguetteAV.EDR.Core.Interop;
using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Rules;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace BaguetteAV.EDR.Core.Services;

public sealed class ProcessInspector
{
    private readonly Dictionary<string, (DateTime Stamp, bool Signed)> _signatureCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (DateTime Stamp, string Hash)> _hashCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _cacheLock = new();

    public IReadOnlyList<ProcessInfo> Snapshot()
    {
        var list = new List<ProcessInfo>(256);
        var snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == new IntPtr(-1)) return list;
        try
        {
            var entry = new NativeMethods.PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<NativeMethods.PROCESSENTRY32W>() };
            if (!NativeMethods.Process32FirstW(snapshot, ref entry)) return list;
            do
            {
                list.Add(new ProcessInfo
                {
                    ProcessId = (int)entry.th32ProcessID,
                    ParentProcessId = (int)entry.th32ParentProcessID,
                    Name = entry.szExeFile ?? string.Empty
                });
            }
            while (NativeMethods.Process32NextW(snapshot, ref entry));
        }
        finally
        {
            NativeMethods.CloseHandle(snapshot);
        }

        var names = list.GroupBy(p => p.ProcessId).ToDictionary(g => g.Key, g => g.First().Name);
        for (var i = 0; i < list.Count; i++)
        {
            var item = list[i];
            names.TryGetValue(item.ParentProcessId, out var parentName);
            list[i] = new ProcessInfo
            {
                ProcessId = item.ProcessId,
                ParentProcessId = item.ParentProcessId,
                Name = item.Name,
                ParentName = parentName ?? string.Empty
            };
        }
        return list;
    }

    public string TryGetImagePath(int processId)
    {
        if (processId <= 0) return string.Empty;
        var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (handle == IntPtr.Zero) return string.Empty;
        try
        {
            var buffer = new StringBuilder(1024);
            var size = buffer.Capacity;
            return NativeMethods.QueryFullProcessImageNameW(handle, 0, buffer, ref size) ? buffer.ToString() : string.Empty;
        }
        finally
        {
            NativeMethods.CloseHandle(handle);
        }
    }

    public ProcessContext BuildContext(TelemetryEvent telemetry, string? parentImage = null)
    {
        var path = !string.IsNullOrWhiteSpace(telemetry.Image) ? telemetry.Image : TryGetImagePath(telemetry.ProcessId);
        var exists = !string.IsNullOrWhiteSpace(path) && File.Exists(path);
        var signed = exists && IsSigned(path);
        var hash = ParseSha256(telemetry.Hashes);
        if (string.IsNullOrEmpty(hash) && exists) hash = TryHash(path);
        var parent = !string.IsNullOrWhiteSpace(telemetry.ParentImage) ? telemetry.ParentImage : parentImage ?? string.Empty;
        return new ProcessContext
        {
            ProcessId = telemetry.ProcessId,
            ParentProcessId = telemetry.ParentProcessId,
            Image = telemetry.Image,
            ImagePath = path,
            ParentImage = parent,
            CommandLine = telemetry.CommandLine,
            User = telemetry.User,
            Sha256 = hash,
            IsSigned = signed,
            IsUserWritable = RuleContext.IsUserWritable(path),
            FileExists = exists
        };
    }

    public bool IsSigned(string path)
    {
        try
        {
            var stamp = File.GetLastWriteTimeUtc(path);
            lock (_cacheLock)
            {
                if (_signatureCache.TryGetValue(path, out var cached) && cached.Stamp == stamp) return cached.Signed;
            }
            var signed = VerifyTrust(path);
            lock (_cacheLock) _signatureCache[path] = (stamp, signed);
            return signed;
        }
        catch
        {
            return false;
        }
    }

    public string TryHash(string path)
    {
        try
        {
            var info = new FileInfo(path);
            if (!info.Exists || info.Length > 256L * 1024 * 1024) return string.Empty;
            lock (_cacheLock)
            {
                if (_hashCache.TryGetValue(path, out var cached) && cached.Stamp == info.LastWriteTimeUtc) return cached.Hash;
            }
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var sha = SHA256.Create();
            var hash = Convert.ToHexString(sha.ComputeHash(stream));
            lock (_cacheLock) _hashCache[path] = (info.LastWriteTimeUtc, hash);
            return hash;
        }
        catch
        {
            return string.Empty;
        }
    }

    public static string ParseSha256(string hashes)
    {
        if (string.IsNullOrWhiteSpace(hashes)) return string.Empty;
        foreach (var part in hashes.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = part.Trim();
            if (trimmed.StartsWith("SHA256=", StringComparison.OrdinalIgnoreCase))
                return trimmed.Substring(7).Trim();
        }
        return string.Empty;
    }

    private static bool VerifyTrust(string path)
    {
        var fileInfo = new NativeMethods.WINTRUST_FILE_INFO
        {
            cbStruct = Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>(),
            pcwszFilePath = path
        };
        var filePtr = Marshal.AllocHGlobal(fileInfo.cbStruct);
        try
        {
            Marshal.StructureToPtr(fileInfo, filePtr, false);
            var data = new NativeMethods.WINTRUST_DATA
            {
                cbStruct = Marshal.SizeOf<NativeMethods.WINTRUST_DATA>(),
                dwUIChoice = 2,
                fdwRevocationChecks = 0,
                dwUnionChoice = 1,
                pFile = filePtr,
                dwStateAction = 1,
                dwProvFlags = 0x100
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
            var result = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            data.dwStateAction = 2;
            NativeMethods.WinVerifyTrust(IntPtr.Zero, ref action, ref data);
            return result == 0;
        }
        finally
        {
            Marshal.FreeHGlobal(filePtr);
        }
    }
}
