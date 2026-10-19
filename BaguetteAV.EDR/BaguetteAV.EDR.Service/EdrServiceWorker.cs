using BaguetteAV.EDR.Core.Services;
using Microsoft.Extensions.Hosting;

namespace BaguetteAV.EDR.Service;

public sealed class EdrServiceWorker : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var runtime = new EdrRuntime();
        if (runtime.Settings.ProtectionEnabled) runtime.Start();
        using var server = new ControlPipeServer(runtime);
        runtime.Log.Info("B-EDR 保护服务已启动");
        await server.RunAsync(stoppingToken);
        runtime.Log.Info("B-EDR 保护服务已停止");
    }
}
