using BaguetteAV.EDR.App.ViewModels;
using BaguetteAV.EDR.Core.Services;
using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Threading;
using WinForms = System.Windows.Forms;

namespace BaguetteAV.EDR.App;

public partial class App : System.Windows.Application
{
    private Mutex? _mutex;
    private IEdrBackend? _backend;
    private MainViewModel? _viewModel;
    private WinForms.NotifyIcon? _tray;
    private SplashWindow? _splash;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var preview = e.Args.Any(a => string.Equals(a, "--preview", StringComparison.OrdinalIgnoreCase));
        var localOnly = preview || e.Args.Any(a => string.Equals(a, "--local", StringComparison.OrdinalIgnoreCase));
        var requireService = e.Args.Any(a => string.Equals(a, "--service", StringComparison.OrdinalIgnoreCase));
        if (!preview)
        {
            _mutex = new Mutex(true, "BaguetteAV.EDR.SingleInstance", out var created);
            if (!created)
            {
                System.Windows.MessageBox.Show("B-EDR 已在运行", "B-EDR",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                Shutdown();
                return;
            }
        }

        DispatcherUnhandledException += (_, args) =>
        {
            WriteCrash(args.Exception.ToString());
            args.Handled = true;
        };
        AppDomain.CurrentDomain.UnhandledException += (_, args) => WriteCrash(args.ExceptionObject?.ToString() ?? "unknown");

        _splash = new SplashWindow();
        _splash.Show();
        var page = GetArgument(e.Args, "--page");

        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1400) };
        timer.Tick += (_, _) =>
        {
            timer.Stop();
            if (!localOnly)
            {
                _backend = ServiceEdrBackend.TryCreate(out var serviceError);
                if (_backend is null && requireService)
                {
                    System.Windows.MessageBox.Show(
                        string.Concat(serviceError, Environment.NewLine, Environment.NewLine,
                            "请先以管理员身份运行：BaguetteAV.EDR.Service.exe --install"),
                        "B-EDR", MessageBoxButton.OK, MessageBoxImage.Error);
                    timer.Stop();
                    _splash?.Close();
                    Shutdown();
                    return;
                }
                if (_backend is null)
                {
                    System.Windows.MessageBox.Show(
                        string.Concat(serviceError, Environment.NewLine, Environment.NewLine,
                            "将以本地直连模式启动。该模式关闭界面即停止防护，仅用于开发调试；",
                            "正式演示请安装 B-EDR 保护服务。"),
                        "B-EDR", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            if (_backend is null)
            {
                _backend = new LocalEdrBackend(new EdrRuntime());
                if (!preview && _backend.Settings.ProtectionEnabled) _backend.Start();
            }
            _viewModel = new MainViewModel(_backend);
            if (!string.IsNullOrWhiteSpace(page)) _viewModel.NavigateTo(page);
            var window = new MainWindow(_viewModel);
            MainWindow = window;
            window.Show();
            SetupTray(window);
            _splash?.Close();
            _splash = null;
        };
        timer.Start();
    }

    private void SetupTray(Window window)
    {
        try
        {
            var icon = System.Drawing.Icon.ExtractAssociatedIcon(Environment.ProcessPath ?? string.Empty);
            _tray = new WinForms.NotifyIcon
            {
                Icon = icon,
                Text = "B-EDR",
                Visible = true
            };
            var menu = new WinForms.ContextMenuStrip();
            menu.Items.Add("打开主界面", null, (_, _) =>
            {
                window.Show();
                window.WindowState = WindowState.Normal;
                window.Activate();
            });
            menu.Items.Add("开启 / 暂停防护", null, (_, _) => _viewModel?.ToggleProtectionCommand.Execute(null));
            menu.Items.Add(new WinForms.ToolStripSeparator());
            menu.Items.Add("退出", null, (_, _) => Shutdown());
            _tray.ContextMenuStrip = menu;
            _tray.DoubleClick += (_, _) =>
            {
                window.Show();
                window.WindowState = WindowState.Normal;
                window.Activate();
            };
        }
        catch { }
    }

    private static void WriteCrash(string text)
    {
        try
        {
            Directory.CreateDirectory(SettingsStore.DataDirectory);
            File.AppendAllText(Path.Combine(SettingsStore.DataDirectory, "crash.log"),
                string.Concat(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), " ", text, Environment.NewLine));
        }
        catch { }
    }

    private static string? GetArgument(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        return null;
    }

    protected override void OnExit(ExitEventArgs e)
    {
        if (_tray is not null)
        {
            _tray.Visible = false;
            _tray.Dispose();
        }
        _viewModel?.Dispose();
        _backend?.Dispose();
        try { _mutex?.ReleaseMutex(); } catch { }
        _mutex?.Dispose();
        base.OnExit(e);
    }
}
