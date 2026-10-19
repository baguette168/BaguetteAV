using System.Diagnostics;

namespace BaguetteAV.EDR.Service;

public static class ServiceInstaller
{
    public const string ServiceName = "B-EDR Protection";

    public static int Install()
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable)) return Fail("无法确定服务程序路径");
        var created = false;
        var quotedExecutable = string.Concat("\"", executable, "\"");
        if (RunSc("query", ServiceName) != 0)
        {
            if (RunSc("create", ServiceName, "binPath=", quotedExecutable,
                    "start=", "auto", "DisplayName=", ServiceName, "obj=", "LocalSystem") != 0)
                return Fail("服务创建失败，请以管理员身份运行");
            created = true;
        }
        else if (RunSc("config", ServiceName, "binPath=", quotedExecutable, "start=", "auto", "obj=", "LocalSystem") != 0)
        {
            return Fail("服务已存在，但更新启动配置失败，请以管理员身份运行");
        }
        if (RunSc("description", ServiceName, "B-EDR single-host endpoint protection service") != 0 ||
            RunSc("failure", ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/60000") != 0 ||
            RunSc("failureflag", ServiceName, "1") != 0)
        {
            if (created) RunSc("delete", ServiceName);
            return Fail("服务已创建，但失败恢复配置写入失败；请以管理员身份重试");
        }
        var startResult = RunSc("start", ServiceName);
        if ((startResult != 0 && !IsRunning()) || !WaitForRunning(30))
        {
            if (created) RunSc("delete", ServiceName);
            return Fail("服务已安装，但未能在30秒内进入RUNNING状态");
        }
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

    private static bool IsRunning()
    {
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "sc.exe"),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            info.ArgumentList.Add("query");
            info.ArgumentList.Add(ServiceName);
            using var process = Process.Start(info);
            if (process is null) return false;
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(10000);
            return output.Contains("RUNNING", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool WaitForRunning(int timeoutSeconds)
    {
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);
        while (DateTime.UtcNow < deadline)
        {
            if (IsRunning()) return true;
            Thread.Sleep(750);
        }
        return false;
    }

    private static int Fail(string message)
    {
        Console.Error.WriteLine(message);
        return 2;
    }
}
