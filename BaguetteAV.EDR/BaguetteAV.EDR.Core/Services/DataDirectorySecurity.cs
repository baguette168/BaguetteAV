using System.Security.AccessControl;
using System.Security.Principal;

namespace BaguetteAV.EDR.Core.Services;

/// <summary>
/// Keeps the LocalSystem service data directory writable only by administrators.
/// Policy packs and plugin DLLs are loaded by the service, so an inherited
/// ProgramData ACL that lets BUILTIN\Users write there would be a local
/// privilege-escalation path.
/// </summary>
public static class DataDirectorySecurity
{
    private static readonly SecurityIdentifier SystemSid =
        new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid =
        new(WellKnownSidType.BuiltinAdministratorsSid, null);

    public static bool TryHarden(string directory, out string error)
    {
        error = string.Empty;
        try
        {
            Directory.CreateDirectory(directory);
            ApplyDirectoryAcl(directory);
            foreach (var child in Directory.EnumerateDirectories(directory, "*", SearchOption.AllDirectories))
                ApplyDirectoryAcl(child);
            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
                ApplyFileAcl(file);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static void ApplyDirectoryAcl(string path)
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            SystemSid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            AdministratorsSid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    private static void ApplyFileAcl(string path)
    {
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(
            SystemSid, FileSystemRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            AdministratorsSid, FileSystemRights.FullControl, AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }
}
