using BaguetteAV.EDR.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

if (args.Contains("--install", StringComparer.OrdinalIgnoreCase))
    return ServiceInstaller.Install();
if (args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase))
    return ServiceInstaller.Uninstall();

var builder = Host.CreateDefaultBuilder(args)
    .UseWindowsService(options => options.ServiceName = ServiceInstaller.ServiceName);
builder.ConfigureServices(services => services.AddHostedService<EdrServiceWorker>());
await builder.Build().RunAsync();
return 0;
