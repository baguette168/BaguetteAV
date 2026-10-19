using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;
using BaguetteAV.EDR.Core.Services;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace BaguetteAV.EDR.Service;

public sealed class ControlPipeServer : IDisposable
{
    private readonly EdrRuntime _runtime;
    private readonly CancellationTokenSource _cts = new();

    public ControlPipeServer(EdrRuntime runtime) => _runtime = runtime;

    public async Task RunAsync(CancellationToken stoppingToken)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken, _cts.Token);
        while (!linked.IsCancellationRequested)
        {
            NamedPipeServerStream? pipe = null;
            try
            {
                pipe = NamedPipeServerStreamAcl.Create(EdrIpc.PipeName, PipeDirection.InOut, 8,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous | PipeOptions.WriteThrough,
                    0, 0, CreateSecurity());
                await pipe.WaitForConnectionAsync(linked.Token).ConfigureAwait(false);
                _ = HandleClientAsync(pipe, linked.Token);
            }
            catch (OperationCanceledException)
            {
                pipe?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                pipe?.Dispose();
                _runtime.Log.Warn(string.Concat("控制管道异常：", ex.Message));
                try { await Task.Delay(1000, linked.Token).ConfigureAwait(false); } catch { break; }
            }
        }
    }

    private async Task HandleClientAsync(NamedPipeServerStream pipe, CancellationToken token)
    {
        using (pipe)
        using (var reader = new StreamReader(pipe, new UTF8Encoding(false), leaveOpen: true))
        using (var writer = new StreamWriter(pipe, new UTF8Encoding(false), leaveOpen: true) { AutoFlush = true })
        {
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token);
                timeout.CancelAfter(TimeSpan.FromSeconds(30));
                var line = await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(line) || Encoding.UTF8.GetByteCount(line) > EdrIpc.MaxMessageBytes)
                    return;
                var request = JsonSerializer.Deserialize<ControlRequest>(line, EdrIpc.Json);
                if (request is null) return;
                var response = Handle(request);
                await writer.WriteLineAsync(JsonSerializer.Serialize(response, EdrIpc.Json)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                try
                {
                    await writer.WriteLineAsync(JsonSerializer.Serialize(new ControlResponse { Ok = false, Error = ex.Message }, EdrIpc.Json)).ConfigureAwait(false);
                }
                catch { }
            }
        }
    }

    private ControlResponse Handle(ControlRequest request)
    {
        switch (request.Command)
        {
            case "status":
                return Ok(BuildStatus());
            case "ping":
                return Ok(new { service = "B-EDR", version = "2.0.0" });
            case "setProtection":
            {
                if (request.Payload is null) return Error("缺少 payload");
                var payload = request.Payload.Value.Deserialize<SetProtectionRequest>(EdrIpc.Json);
                if (payload is null) return Error("payload 无效");
                _runtime.SetProtection(payload.Enabled);
                return Ok(BuildStatus());
            }
            case "applySettings":
            {
                if (request.Payload is null) return Error("缺少 payload");
                var settings = request.Payload.Value.Deserialize<EdrSettings>(EdrIpc.Json);
                if (settings is null) return Error("settings 无效");
                _runtime.ApplySettings(settings);
                return Ok(BuildStatus());
            }
            case "reloadPolicies":
                _runtime.ReloadPolicies();
                return Ok(BuildStatus());
            case "appendDetection":
            {
                if (request.Payload is null) return Error("缺少 payload");
                var detection = request.Payload.Value.Deserialize<DetectionRecord>(EdrIpc.Json);
                if (detection is null) return Error("detection 无效");
                _runtime.UpdateDetection(detection);
                return Ok(new { id = detection.Id });
            }
            case "processes":
                return Ok(_runtime.RefreshProcesses());
            case "exportSamples":
            {
                if (request.Payload is null) return Error("缺少 payload");
                var export = request.Payload.Value.Deserialize<ExportSamplesRequest>(EdrIpc.Json);
                if (export is null || string.IsNullOrWhiteSpace(export.Path)) return Error("导出路径无效");
                var ok = _runtime.ExportRecentSamples(export.Path, export.Max);
                return ok ? Ok(new { path = export.Path }) : Error("没有可导出的遥测样本或写入失败");
            }
            default:
                return Error(string.Concat("未知命令：", request.Command));
        }
    }

    private EdrServiceStatus BuildStatus() => new()
    {
        ServiceAvailable = true,
        IsRunning = _runtime.IsRunning,
        ProtectionEnabled = _runtime.Settings.ProtectionEnabled,
        SysmonStatus = _runtime.SysmonStatus,
        EventCount = _runtime.EventCount,
        BlockedCount = _runtime.BlockedCount,
        ProcessCount = _runtime.ProcessCount,
        RecentSampleCount = _runtime.RecentSamples.Count,
        RecentDetections = _runtime.RecentDetections.Take(200).ToList(),
        PolicyErrors = _runtime.PolicyErrors.ToList(),
        RecentLogs = _runtime.Log.Recent.TakeLast(300).ToList()
    };

    private static PipeSecurity CreateSecurity()
    {
        var security = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        security.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        security.AddAccessRule(new PipeAccessRule(administrators, PipeAccessRights.FullControl, AccessControlType.Allow));
        if (string.Equals(Environment.GetEnvironmentVariable("BEDR_PIPE_ALLOW_CURRENT_USER"), "1", StringComparison.Ordinal))
        {
            var current = WindowsIdentity.GetCurrent().User;
            if (current is not null)
                security.AddAccessRule(new PipeAccessRule(current, PipeAccessRights.FullControl, AccessControlType.Allow));
        }
        return security;
    }

    private static ControlResponse Ok(object data) => new()
    {
        Ok = true,
        Data = JsonSerializer.SerializeToElement(data, EdrIpc.Json)
    };

    private static ControlResponse Error(string message) => new() { Ok = false, Error = message };

    private sealed class SetProtectionRequest
    {
        public bool Enabled { get; set; }
    }

    private sealed class ExportSamplesRequest
    {
        public string Path { get; set; } = string.Empty;
        public int Max { get; set; } = 200;
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        _cts.Dispose();
    }
}
