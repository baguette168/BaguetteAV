using System.Diagnostics;

namespace BaguetteAV.EDR.Service;

public static class ServiceInstaller
{
    public const string ServiceName = "B-EDR Protection";

    public static int Install()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable)) return Fail("无法确定服务程序路径");
        if (RunSc("create", ServiceName, "binPath=", string.Concat("\"", executable, "\""),
                "start=", "auto", "DisplayName=", ServiceName, "obj=", "LocalSystem") != 0)
            return Fail("服务创建失败，请以管理员身份运行");
        RunSc("description", ServiceName, "B-EDR single-host endpoint protection service");
        RunSc("failure", ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000");
        if (RunSc("start", ServiceName) != 0) return Fail("服务已安装，但启动失败");
        Console.WriteLine("B-EDR 保护服务已安装并启动。GUI 现在可以连接本机服务。");
        return 0;
    }

    public static int Uninstall()
    {
        RunSc("stop", ServiceName);
        if (RunSc("delete", ServiceName) != 0) return Fail("服务删除失败，请以管理员身份运行");
        Console.WriteLine("B-EDR 保护服务已删除。");
        return 0;
    }

    private static int RunSc(params string[] arguments)
    {
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "sc.exe"),
                UseShellExecute = false,
                CreateNoWindow = true
            };
            foreach (var argument in arguments) info.ArgumentList.Add(argument);
            using var process = Process.Start(info);
            if (process is null) return -1;
            process.WaitForExit(30000);
            return process.ExitCode;
        }
        catch
        {
            return -1;
        }
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 2;
    }
}
