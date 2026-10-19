using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Rules;

namespace BaguetteAV.EDR.Core.Policy;

public static class PolicyFields
{
    public static string? Resolve(string field, TelemetryEvent e, ProcessContext ctx)
    {
        var key = (field ?? string.Empty).Trim();
        if (key.StartsWith("field.", StringComparison.OrdinalIgnoreCase))
        {
            var name = key[6..];
            return e.Fields.TryGetValue(name, out var custom) ? custom : null;
        }

        return key.ToLowerInvariant() switch
        {
            "kind" or "event.kind" => e.Kind.ToString(),
            "eventid" or "event.id" => e.EventId.ToString(),
            "timestamp" or "event.timestamp" => e.Timestamp.ToString("O"),
            "pid" or "process.pid" or "event.pid" => e.ProcessId.ToString(),
            "parentpid" or "parent.pid" => e.ParentProcessId.ToString(),
            "image" or "process.image" => e.Image,
            "parentimage" or "parent.image" => e.ParentImage,
            "commandline" or "process.commandline" => e.CommandLine,
            "user" or "process.user" => e.User,
            "integritylevel" => e.IntegrityLevel,
            "hashes" or "process.hashes" => e.Hashes,
            "targetpid" or "target.pid" => e.TargetProcessId.ToString(),
            "targetimage" or "target.image" => e.TargetImage,
            "grantedaccess" or "target.access" => e.GrantedAccess,
            "source" or "event.source" => e.Source,
            "destinationip" or "network.destination.ip" => e.DestinationIp,
            "destinationport" or "network.destination.port" => e.DestinationPort.ToString(),
            "destinationhost" or "network.destination.host" => e.DestinationHost,
            "protocol" or "network.protocol" => e.Protocol,
            "filepath" or "file.path" => e.FilePath,
            "file.userwritable" => RuleContext.IsUserWritable(e.FilePath).ToString(),
            "driverpath" or "driver.path" => e.DriverPath,
            "driver.userwritable" => RuleContext.IsUserWritable(e.DriverPath).ToString(),
            "driver.signed" => e.Fields.TryGetValue("Signed", out var signed) ? signed
                : e.Fields.TryGetValue("SignatureStatus", out var status) ? (status.Equals("Valid", StringComparison.OrdinalIgnoreCase) ? "true" : "false")
                : null,
            "driver.signature" => e.Fields.TryGetValue("Signature", out var signature) ? signature : null,
            "driver.signaturestatus" => e.Fields.TryGetValue("SignatureStatus", out var signatureStatus) ? signatureStatus : null,
            "effectivefile" or "file.effective" => e.EffectiveFile,
            "wminame" or "wmi.name" => e.WmiName,
            "wmiquery" or "wmi.query" => e.WmiQuery,
            "wmiconsumertype" or "wmi.consumer.type" => e.WmiConsumerType,
            "wmidestination" or "wmi.destination" => e.WmiDestination,
            "process.name" => ctx.FileName,
            "process.path" or "process.imagepath" => ctx.ImagePath,
            "process.parentpath" or "parent.path" => ctx.ParentImage,
            "process.sha256" => ctx.Sha256,
            "process.signed" => ctx.IsSigned.ToString(),
            "process.userwritable" => ctx.IsUserWritable.ToString(),
            "process.signer" => ctx.Signer,
            "process.fileexists" => ctx.FileExists.ToString(),
            "process.cmdline" => ctx.CommandLine,
            _ => null
        };
    }

    public static IReadOnlyList<string> KnownFields { get; } = new[]
    {
        "kind", "event.id", "event.timestamp", "event.pid", "event.source",
        "process.pid", "process.image", "process.name", "process.path", "process.commandline",
        "process.user", "process.sha256", "process.signed", "process.userwritable", "process.signer",
        "process.fileexists", "parent.pid", "parent.image", "parent.path",
        "target.pid", "target.image", "target.access",
        "network.destination.ip", "network.destination.port", "network.destination.host", "network.protocol",
        "file.path", "file.effective", "file.userwritable", "driver.path", "driver.userwritable", "driver.signed", "driver.signature", "driver.signaturestatus",
        "wmi.name", "wmi.query", "wmi.consumer.type", "wmi.destination",
        "field.<name>"
    };
}
