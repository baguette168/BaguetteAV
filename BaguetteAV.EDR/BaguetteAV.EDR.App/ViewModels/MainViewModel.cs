using BaguetteAV.EDR.Core.Models;
using BaguetteAV.EDR.Core.Policy;
using BaguetteAV.EDR.Core.Rules;
using BaguetteAV.EDR.Core.Services;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using Forms = System.Windows.Forms;

namespace BaguetteAV.EDR.App.ViewModels;

public sealed class RuleToggle : ObservableObject
{
    private bool _enabled;
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public string Mitre { get; init; } = string.Empty;
    public bool Enabled { get => _enabled; set => SetProperty(ref _enabled, value); }
}

public sealed class NavItem
{
    public string Key { get; init; } = string.Empty;
    public string Title { get; init; } = string.Empty;
    public string Glyph { get; init; } = string.Empty;
}

public sealed class PolicyPackItem : ObservableObject
{
    private bool _active;
    public string Id { get; init; } = string.Empty;
    public string Name { get; init; } = string.Empty;
    public string Version { get; init; } = string.Empty;
    public string Author { get; init; } = string.Empty;
    public string Description { get; init; } = string.Empty;
    public int RuleCount { get; init; }
    public string Sha256Short { get; init; } = string.Empty;
    public string ImportedAtText { get; init; } = string.Empty;
    public bool Active
    {
        get => _active;
        set
        {
            if (!SetProperty(ref _active, value)) return;
            OnPropertyChanged(nameof(StatusText));
            OnPropertyChanged(nameof(ActionText));
        }
    }
    public string StatusText => Active ? "已启用" : "未启用";
    public string ActionText => Active ? "停用" : "启用";
    public bool CanRollback { get; init; }
}

public sealed class MainViewModel : ObservableObject, IDisposable
{
    private readonly IEdrBackend _runtime;
    private readonly Dispatcher _dispatcher;
    private readonly DispatcherTimer _statsTimer;
    private string _currentPage = "dashboard";
    private NavItem? _selectedNavItem;
    private string _pageTitle = "概览";
    private string _statusMessage = "就绪";
    private bool _isProtected;
    private string _severityFilter = "全部";
    private string _detectionSearch = string.Empty;
    private DetectionRecord? _selectedDetection;
    private ProcessInfo? _selectedProcess;
    private QuarantineEntry? _selectedQuarantine;
    private string _scanPath = string.Empty;
    private string _scanSummary = "尚未执行扫描";
    private bool _isScanning;
    private bool _isRootkitScanning;
    private string _rootkitStatus = "尚未检查";
    private string _settingsSavedText = string.Empty;
    private string _policyStatusText = "尚未加载策略包";
    private string _policySimulationText = "尚未执行离线演练";
    private string _policyCoverageText = "尚未分析策略覆盖";
    private string _policyTestText = "尚未运行策略回归测试";
    private int _recentSampleCount;
    private string _clamAvStatus = "未配置";
    private CancellationTokenSource? _scanCts;
    private bool _autoContain;
    private bool _autoQuarantine;
    private bool _blockC2;
    private bool _monitorNetwork;
    private bool _monitorDrivers;
    private bool _monitorWmi;
    private bool _monitorFileCreation;
    private int _retentionDays;
    private int _maxDetections;
    private string _quarantinePath = string.Empty;
    private string _clamAvPath = string.Empty;

    public MainViewModel(IEdrBackend runtime)
    {
        _runtime = runtime;
        _dispatcher = Dispatcher.CurrentDispatcher;
        NavItems = new ObservableCollection<NavItem>
        {
            new() { Key = "dashboard", Title = "概览", Glyph = "\uE80F" },
            new() { Key = "detections", Title = "威胁检测", Glyph = "\uE7BA" },
            new() { Key = "policies", Title = "策略研究", Glyph = "\uE8F1" },
            new() { Key = "processes", Title = "进程监控", Glyph = "\uE9D9" },
            new() { Key = "scan", Title = "扫描查杀", Glyph = "\uE721" },
            new() { Key = "quarantine", Title = "隔离区", Glyph = "\uE74D" },
            new() { Key = "logs", Title = "日志", Glyph = "\uE9D5" },
            new() { Key = "settings", Title = "设置", Glyph = "\uE713" }
        };
        DetectionsView = CollectionViewSource.GetDefaultView(Detections);
        DetectionsView.Filter = FilterDetection;
        LoadSettings();
        _runtime.DetectionRaised += OnDetectionRaised;
        _runtime.StateChanged += OnStateChanged;
        _runtime.StatusChanged += OnStatusChanged;
        _runtime.Log.LineWritten += OnLogLine;
        foreach (var record in _runtime.RecentDetections) Detections.Add(record);
        foreach (var line in _runtime.Log.Recent) LogLines.Add(line);
        _statsTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _statsTimer.Tick += (_, _) => RefreshStats();
        _statsTimer.Start();
        IsElevated = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
        InitializeCommands();
        Navigate("dashboard");
        RefreshStats();
    }

    public ObservableCollection<NavItem> NavItems { get; }
    public ObservableCollection<DetectionRecord> Detections { get; } = new();
    public ICollectionView DetectionsView { get; }
    public ObservableCollection<ProcessInfo> Processes { get; } = new();
    public ObservableCollection<QuarantineEntry> QuarantineItems { get; } = new();
    public ObservableCollection<RuleToggle> Rules { get; } = new();
    public ObservableCollection<string> LogLines { get; } = new();
    public ObservableCollection<ScanFinding> ScanFindings { get; } = new();
    public ObservableCollection<RootkitFinding> RootkitFindings { get; } = new();
    public ObservableCollection<PolicyPackItem> PolicyPacks { get; } = new();
    public IReadOnlyList<string> SeverityOptions { get; } = new[] { "全部", "严重", "高危", "中危", "低危" };

    public RelayCommand NavigateCommand { get; private set; } = null!;
    public RelayCommand ToggleProtectionCommand { get; private set; } = null!;
    public RelayCommand ClearDetectionsCommand { get; private set; } = null!;
    public RelayCommand MarkFalsePositiveCommand { get; private set; } = null!;
    public RelayCommand ExportDetectionsCommand { get; private set; } = null!;
    public AsyncRelayCommand KillDetectionProcessCommand { get; private set; } = null!;
    public AsyncRelayCommand QuarantineDetectionCommand { get; private set; } = null!;
    public AsyncRelayCommand RefreshProcessesCommand { get; private set; } = null!;
    public AsyncRelayCommand KillSelectedProcessCommand { get; private set; } = null!;
    public AsyncRelayCommand QuarantineSelectedProcessCommand { get; private set; } = null!;
    public RelayCommand BrowseScanPathCommand { get; private set; } = null!;
    public RelayCommand BrowseQuarantinePathCommand { get; private set; } = null!;
    public RelayCommand BrowseClamAvPathCommand { get; private set; } = null!;
    public AsyncRelayCommand StartScanCommand { get; private set; } = null!;
    public RelayCommand CancelScanCommand { get; private set; } = null!;
    public AsyncRelayCommand RunRootkitCommand { get; private set; } = null!;
    public AsyncRelayCommand RestoreQuarantineCommand { get; private set; } = null!;
    public AsyncRelayCommand DeleteQuarantineCommand { get; private set; } = null!;
    public RelayCommand SaveSettingsCommand { get; private set; } = null!;
    public RelayCommand OpenLogFolderCommand { get; private set; } = null!;
    public RelayCommand QuickScanCommand { get; private set; } = null!;
    public RelayCommand ImportPolicyCommand { get; private set; } = null!;
    public RelayCommand RefreshPoliciesCommand { get; private set; } = null!;
    public RelayCommand TogglePolicyCommand { get; private set; } = null!;
    public RelayCommand RollbackPolicyCommand { get; private set; } = null!;
    public RelayCommand OpenPolicyFolderCommand { get; private set; } = null!;
    public RelayCommand SimulatePolicyCommand { get; private set; } = null!;
    public RelayCommand ExportSamplesCommand { get; private set; } = null!;
    public RelayCommand RunPolicyTestsCommand { get; private set; } = null!;
    public RelayCommand ExportCoverageCommand { get; private set; } = null!;

    public string CurrentPage
    {
        get => _currentPage;
        private set
        {
            if (!SetProperty(ref _currentPage, value)) return;
            OnPropertyChanged(nameof(IsDashboard));
            OnPropertyChanged(nameof(IsDetections));
            OnPropertyChanged(nameof(IsPolicies));
            OnPropertyChanged(nameof(IsProcesses));
            OnPropertyChanged(nameof(IsScan));
            OnPropertyChanged(nameof(IsQuarantine));
            OnPropertyChanged(nameof(IsLogs));
            OnPropertyChanged(nameof(IsSettings));
            OnPropertyChanged(nameof(SelectedNavKey));
        }
    }

    public bool IsDashboard => CurrentPage == "dashboard";
    public bool IsDetections => CurrentPage == "detections";
    public bool IsPolicies => CurrentPage == "policies";
    public bool IsProcesses => CurrentPage == "processes";
    public bool IsScan => CurrentPage == "scan";
    public bool IsQuarantine => CurrentPage == "quarantine";
    public bool IsLogs => CurrentPage == "logs";
    public bool IsSettings => CurrentPage == "settings";
    public string SelectedNavKey
    {
        get => CurrentPage;
        set { if (!string.IsNullOrWhiteSpace(value)) Navigate(value); }
    }

    public NavItem? SelectedNavItem
    {
        get => _selectedNavItem;
        set
        {
            if (!SetProperty(ref _selectedNavItem, value)) return;
            if (value is not null && value.Key != CurrentPage) Navigate(value.Key);
        }
    }

    public string PageTitle { get => _pageTitle; private set => SetProperty(ref _pageTitle, value); }
    public string StatusMessage { get => _statusMessage; private set => SetProperty(ref _statusMessage, value); }
    public bool IsProtected { get => _isProtected; private set => SetProperty(ref _isProtected, value); }
    public bool IsElevated { get; }
    public string ProtectionText => IsProtected ? "防护已开启" : "防护已暂停";
    public string ProtectionActionText => IsProtected ? "暂停防护" : "开启防护";
    public string SysmonStatus => _runtime.SysmonStatus;
    public string ClamAvStatus { get => _clamAvStatus; private set => SetProperty(ref _clamAvStatus, value); }
    public string VersionText => "B-EDR 2.0";

    public int ThreatCount => Detections.Count(d => !d.IsFalsePositive);
    public long EventCount => _runtime.EventCount;
    public long BlockedCount => _runtime.BlockedCount;
    public int ProcessCount => _runtime.ProcessCount;
    public int RuleCount => Rules.Count(r => r.Enabled);
    public string EventCountText => EventCount.ToString("N0");
    public string BlockedCountText => BlockedCount.ToString("N0");
    public string ProcessCountText => ProcessCount.ToString("N0");
    public string RuleCountText => string.Concat(RuleCount, " / ", Rules.Count);
    public IEnumerable<DetectionRecord> RecentDetections => Detections.Take(5).ToList();

    public string SeverityFilter
    {
        get => _severityFilter;
        set { if (SetProperty(ref _severityFilter, value)) DetectionsView.Refresh(); }
    }

    public string DetectionSearch
    {
        get => _detectionSearch;
        set { if (SetProperty(ref _detectionSearch, value)) DetectionsView.Refresh(); }
    }

    public DetectionRecord? SelectedDetection
    {
        get => _selectedDetection;
        set => SetProperty(ref _selectedDetection, value);
    }

    public ProcessInfo? SelectedProcess
    {
        get => _selectedProcess;
        set => SetProperty(ref _selectedProcess, value);
    }

    public QuarantineEntry? SelectedQuarantine
    {
        get => _selectedQuarantine;
        set => SetProperty(ref _selectedQuarantine, value);
    }

    public string ScanPath { get => _scanPath; set => SetProperty(ref _scanPath, value); }
    public string ScanSummary { get => _scanSummary; private set => SetProperty(ref _scanSummary, value); }
    public bool IsScanning { get => _isScanning; private set => SetProperty(ref _isScanning, value); }
    public bool IsRootkitScanning { get => _isRootkitScanning; private set => SetProperty(ref _isRootkitScanning, value); }
    public string RootkitStatus { get => _rootkitStatus; private set => SetProperty(ref _rootkitStatus, value); }
    public string SettingsSavedText { get => _settingsSavedText; private set => SetProperty(ref _settingsSavedText, value); }
    public string PolicyStatusText { get => _policyStatusText; private set => SetProperty(ref _policyStatusText, value); }
    public string PolicySimulationText { get => _policySimulationText; private set => SetProperty(ref _policySimulationText, value); }
    public string PolicyCoverageText { get => _policyCoverageText; private set => SetProperty(ref _policyCoverageText, value); }
    public string PolicyTestText { get => _policyTestText; private set => SetProperty(ref _policyTestText, value); }
    public int RecentSampleCount { get => _recentSampleCount; private set => SetProperty(ref _recentSampleCount, value); }
    public int ActivePolicyCount => PolicyPacks.Count(p => p.Active);
    public int ActivePolicyRuleCount => PolicyPacks.Where(p => p.Active).Sum(p => p.RuleCount);
    public bool AutoContain { get => _autoContain; set => SetProperty(ref _autoContain, value); }
    public bool AutoQuarantine { get => _autoQuarantine; set => SetProperty(ref _autoQuarantine, value); }
    public bool BlockC2 { get => _blockC2; set => SetProperty(ref _blockC2, value); }
    public bool MonitorNetwork { get => _monitorNetwork; set => SetProperty(ref _monitorNetwork, value); }
    public bool MonitorDrivers { get => _monitorDrivers; set => SetProperty(ref _monitorDrivers, value); }
    public bool MonitorWmi { get => _monitorWmi; set => SetProperty(ref _monitorWmi, value); }
    public bool MonitorFileCreation { get => _monitorFileCreation; set => SetProperty(ref _monitorFileCreation, value); }
    public int RetentionDays { get => _retentionDays; set => SetProperty(ref _retentionDays, value); }
    public int MaxDetections { get => _maxDetections; set => SetProperty(ref _maxDetections, value); }
    public string QuarantinePath { get => _quarantinePath; set => SetProperty(ref _quarantinePath, value); }
    public string ClamAvPath { get => _clamAvPath; set => SetProperty(ref _clamAvPath, value); }
    public int ResponseModeIndex
    {
        get => AutoContain ? 1 : 0;
        set
        {
            if (AutoContain == (value == 1)) return;
            AutoContain = value == 1;
            OnPropertyChanged();
        }
    }

    private void InitializeCommands()
    {
        NavigateCommand = new RelayCommand(p => Navigate(p));
        ToggleProtectionCommand = new RelayCommand(_ =>
        {
            _runtime.SetProtection(!IsProtected);
            IsProtected = _runtime.IsRunning;
            OnPropertyChanged(nameof(ProtectionText));
            OnPropertyChanged(nameof(ProtectionActionText));
            RefreshStats();
        });
        ClearDetectionsCommand = new RelayCommand(_ => { Detections.Clear(); RefreshStats(); });
        MarkFalsePositiveCommand = new RelayCommand(_ =>
        {
            if (SelectedDetection is null) return;
            SelectedDetection.IsFalsePositive = true;
            _runtime.AppendDetection(SelectedDetection);
            DetectionsView.Refresh();
            RefreshStats();
        }, _ => SelectedDetection is not null);
        ExportDetectionsCommand = new RelayCommand(_ => ExportDetections());
        KillDetectionProcessCommand = new AsyncRelayCommand(async _ => await KillDetectionAsync(), _ => SelectedDetection is not null);
        QuarantineDetectionCommand = new AsyncRelayCommand(async _ => await QuarantineDetectionAsync(), _ => SelectedDetection is not null);
        RefreshProcessesCommand = new AsyncRelayCommand(async _ => await RefreshProcessesAsync());
        KillSelectedProcessCommand = new AsyncRelayCommand(async _ => await KillProcessAsync(SelectedProcess?.ProcessId ?? 0), _ => SelectedProcess is not null);
        QuarantineSelectedProcessCommand = new AsyncRelayCommand(async _ => await QuarantineProcessAsync(SelectedProcess), _ => SelectedProcess is not null);
        BrowseScanPathCommand = new RelayCommand(_ => BrowseFolder(path => ScanPath = path));
        BrowseQuarantinePathCommand = new RelayCommand(_ => BrowseFolder(path => QuarantinePath = path));
        BrowseClamAvPathCommand = new RelayCommand(_ => BrowseFile(path => ClamAvPath = path));
        StartScanCommand = new AsyncRelayCommand(async p => await RunScanAsync(p as string ?? "custom"), _ => !IsScanning);
        CancelScanCommand = new RelayCommand(_ => _scanCts?.Cancel(), _ => IsScanning);
        RunRootkitCommand = new AsyncRelayCommand(async _ => await RunRootkitAsync(), _ => !IsRootkitScanning);
        RestoreQuarantineCommand = new AsyncRelayCommand(async _ => await RestoreQuarantineAsync(), _ => SelectedQuarantine is not null);
        DeleteQuarantineCommand = new AsyncRelayCommand(async _ => await DeleteQuarantineAsync(), _ => SelectedQuarantine is not null);
        SaveSettingsCommand = new RelayCommand(_ => SaveSettings());
        OpenLogFolderCommand = new RelayCommand(_ => OpenFolder(SettingsStore.DataDirectory));
        QuickScanCommand = new RelayCommand(_ => { Navigate("scan"); _ = RunScanAsync("quick"); });
        ImportPolicyCommand = new RelayCommand(_ => ImportPolicy());
        RefreshPoliciesCommand = new RelayCommand(_ => { RefreshPolicies(); RefreshRuleList(); });
        TogglePolicyCommand = new RelayCommand(p => TogglePolicy(p as PolicyPackItem));
        RollbackPolicyCommand = new RelayCommand(p => RollbackPolicy(p as PolicyPackItem));
        OpenPolicyFolderCommand = new RelayCommand(_ =>
        {
            Directory.CreateDirectory(_runtime.Policies.Root);
            OpenFolder(_runtime.Policies.Root);
        });
        SimulatePolicyCommand = new RelayCommand(_ => SimulatePolicy());
        ExportSamplesCommand = new RelayCommand(_ => ExportSamples());
        RunPolicyTestsCommand = new RelayCommand(_ => RunPolicyTests());
        ExportCoverageCommand = new RelayCommand(_ => ExportCoverage());
    }

    private void ImportPolicy()
    {
        using var dialog = new Forms.OpenFileDialog
        {
            Title = "导入 B-EDR 策略包",
            Filter = "B-EDR 策略包|*.json|JSON 文件|*.json",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
        if (!DataDirectorySecurity.TryHarden(SettingsStore.DataDirectory, out var aclError))
        {
            var text = string.Concat("数据目录权限加固失败，拒绝导入策略：", aclError);
            PolicyStatusText = text;
            System.Windows.MessageBox.Show(text, "策略导入失败", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var result = _runtime.Policies.InstallFromFile(dialog.FileName, activate: true);
        if (!result.Success)
        {
            var details = result.Validation?.Errors.Take(6).ToArray() ?? Array.Empty<string>();
            var text = details.Length == 0 ? result.Message : string.Concat(result.Message, Environment.NewLine, Environment.NewLine, string.Join(Environment.NewLine, details));
            PolicyStatusText = result.Message;
            System.Windows.MessageBox.Show(text, "策略导入失败", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        _runtime.ReloadPolicies();
        RefreshRuleList();
        RefreshPolicies();
        PolicyStatusText = result.Message;
        StatusMessage = result.Message;
    }

    private void RefreshPolicies()
    {
        PolicyPacks.Clear();
        foreach (var policy in _runtime.Policies.List())
        {
            PolicyPacks.Add(new PolicyPackItem
            {
                Id = policy.Id,
                Name = policy.Name,
                Version = policy.Version,
                Author = policy.Author,
                Description = policy.Description,
                RuleCount = policy.RuleCount,
                Active = policy.Active,
                CanRollback = policy.CanRollback,
                Sha256Short = policy.Sha256.Length > 12 ? policy.Sha256[..12] : policy.Sha256,
                ImportedAtText = policy.ImportedAt.ToString("yyyy-MM-dd HH:mm")
            });
        }
        var active = PolicyPacks.Count(p => p.Active);
        var errors = _runtime.PolicyErrors.Count;
        OnPropertyChanged(nameof(ActivePolicyCount));
        OnPropertyChanged(nameof(ActivePolicyRuleCount));
        PolicyStatusText = string.Concat("已安装 ", PolicyPacks.Count, " 个策略包，", active, " 个已启用");
        if (errors > 0) PolicyStatusText = string.Concat(PolicyStatusText, "，", errors, " 个加载错误");
        var bundle = _runtime.Policies.LoadActive();
        var coverage = PolicyCoverageAnalyzer.Analyze(
            bundle.Packs, bundle.Errors);
        PolicyCoverageText = coverage.Summary;
    }

    private void TogglePolicy(PolicyPackItem? item)
    {
        if (item is null) return;
        var ok = _runtime.Policies.SetActive(item.Id, item.Active ? null : item.Version);
        if (!ok)
        {
            PolicyStatusText = "策略状态更新失败";
            return;
        }
        _runtime.ReloadPolicies();
        RefreshRuleList();
        RefreshPolicies();
        PolicyStatusText = string.Concat(item.Active ? "已停用 " : "已启用 ", item.Name);
        StatusMessage = PolicyStatusText;
    }

    private void RollbackPolicy(PolicyPackItem? item)
    {
        if (item is null) return;
        var ok = _runtime.Policies.Rollback(item.Id);
        PolicyStatusText = ok ? string.Concat("已回滚 ", item.Name) : "回滚失败：没有可用的历史版本";
        if (!ok) return;
        _runtime.ReloadPolicies();
        RefreshRuleList();
        RefreshPolicies();
        StatusMessage = PolicyStatusText;
    }

    private void SimulatePolicy()
    {
        string policyPath;
        using (var dialog = new Forms.OpenFileDialog
        {
            Title = "选择待演练的策略包",
            Filter = "B-EDR 策略包|*.json|JSON 文件|*.json",
            CheckFileExists = true
        })
        {
            if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
            policyPath = dialog.FileName;
        }

        var validation = PolicyValidator.ValidateJson(File.ReadAllText(policyPath), out var pack);
        if (pack is null || !validation.IsValid)
        {
            PolicySimulationText = string.Concat("策略校验失败：", string.Join("；", validation.Errors.Take(4)));
            System.Windows.MessageBox.Show(PolicySimulationText, "策略演练", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        string fixturePath;
        using (var dialog = new Forms.OpenFileDialog
        {
            Title = "选择遥测样本",
            Filter = "B-EDR 遥测样本|*.json|JSON 文件|*.json",
            CheckFileExists = true
        })
        {
            if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
            fixturePath = dialog.FileName;
        }

        var fixture = PolicyFixtures.Load(fixturePath);
        if (!fixture.Success)
        {
            PolicySimulationText = fixture.Message;
            System.Windows.MessageBox.Show(fixture.Message, "策略演练", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var result = PolicySimulator.Simulate(pack, fixture.Samples.Select(s => (s.Event, s.Process)));
        var lines = new List<string>
        {
            string.Concat("样本 ", result.SampleCount, " 个，命中 ", result.Hits.Count, " 次")
        };
        lines.AddRange(result.Hits.Take(12).Select(hit =>
            string.Concat("[", hit.RuleId, "] ", hit.RuleName, " · ", hit.Score, " 分 · ", hit.Detail)));
        if (result.Hits.Count > 12) lines.Add(string.Concat("另有 ", result.Hits.Count - 12, " 次命中未展开"));
        PolicySimulationText = string.Join(Environment.NewLine, lines);
        StatusMessage = string.Concat("策略演练完成：", result.Hits.Count, " 次命中");
    }

    private void RunPolicyTests()
    {
        string policyPath;
        using (var dialog = new Forms.OpenFileDialog
        {
            Title = "选择待回归测试的策略包",
            Filter = "B-EDR 策略包|*.json|JSON 文件|*.json",
            CheckFileExists = true
        })
        {
            if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
            policyPath = dialog.FileName;
        }

        var validation = PolicyValidator.ValidateJson(
            File.ReadAllText(policyPath), out var pack);
        if (pack is null || !validation.IsValid)
        {
            PolicyTestText = string.Concat(
                "策略校验失败：",
                string.Join("；", validation.Errors.Take(4)));
            System.Windows.MessageBox.Show(PolicyTestText,
                "策略回归测试", MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        string suitePath;
        using (var dialog = new Forms.OpenFileDialog
        {
            Title = "选择回归测试用例",
            Filter = "B-EDR 回归测试|*.tests.json|JSON 文件|*.json",
            CheckFileExists = true
        })
        {
            if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
            suitePath = dialog.FileName;
        }

        var loaded = PolicyTestSuiteLoader.Load(suitePath);
        if (!loaded.Success || loaded.Suite is null)
        {
            PolicyTestText = loaded.Message;
            System.Windows.MessageBox.Show(loaded.Message,
                "策略回归测试", MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        var result = PolicyTestRunner.Run(pack, loaded.Suite);
        var lines = new List<string>
        {
            string.Concat("用例 ", result.CaseCount,
                " 个，通过 ", result.PassedCount,
                "，失败 ", result.FailedCount)
        };
        foreach (var testCase in result.Cases)
        {
            var status = testCase.Passed ? "PASS" : "FAIL";
            lines.Add(string.Concat("[", status, "] ",
                testCase.Name));
            foreach (var problem in testCase.Problems)
                lines.Add(string.Concat("    ", problem));
        }
        PolicyTestText = string.Join(Environment.NewLine, lines);
        StatusMessage = result.Success
            ? "策略回归测试通过"
            : "策略回归测试存在失败用例";
        System.Windows.MessageBox.Show(
            string.Concat("回归集：", result.SuiteName,
                Environment.NewLine,
                "通过 ", result.PassedCount,
                " / ", result.CaseCount),
            "策略回归测试", MessageBoxButton.OK,
            result.Success ? MessageBoxImage.Information
                : MessageBoxImage.Warning);
    }

    private void ExportCoverage()
    {
        var bundle = _runtime.Policies.LoadActive();
        var report = PolicyCoverageAnalyzer.Analyze(
            bundle.Packs, bundle.Errors);
        PolicyCoverageText = report.Summary;
        using var dialog = new Forms.SaveFileDialog
        {
            Title = "导出策略覆盖报告",
            Filter = "Markdown|*.md|文本文件|*.txt",
            FileName = string.Concat(
                "B-EDR-策略覆盖-",
                DateTime.Now.ToString("yyyyMMdd-HHmmss"), ".md")
        };
        if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
        File.WriteAllText(dialog.FileName,
            PolicyCoverageAnalyzer.ToMarkdown(report),
            new UTF8Encoding(false));
        StatusMessage = string.Concat(
            "覆盖报告已导出：", dialog.FileName);
        System.Windows.MessageBox.Show(StatusMessage,
            "策略覆盖", MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    private void ExportSamples()
    {
        using var dialog = new Forms.SaveFileDialog
        {
            Title = "导出本机遥测样本",
            Filter = "B-EDR 遥测样本|*.json",
            FileName = string.Concat("bedr-telemetry-", DateTime.Now.ToString("yyyyMMdd-HHmmss"), ".json")
        };
        if (dialog.ShowDialog() != Forms.DialogResult.OK) return;
        var count = _runtime.RecentSampleCount;
        if (count == 0)
        {
            System.Windows.MessageBox.Show("当前没有可导出的遥测。请先开启实时防护并产生系统事件。",
                "导出遥测", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!_runtime.ExportRecentSamples(dialog.FileName, Math.Min(count, 500)))
        {
            System.Windows.MessageBox.Show("遥测样本写入失败。", "导出遥测", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        PolicySimulationText = string.Concat("已导出 ", Math.Min(count, 500), " 个遥测样本：", dialog.FileName);
        StatusMessage = "遥测样本已导出";
    }

    private void RefreshRuleList()
    {
        Rules.Clear();
        foreach (var rule in _runtime.AvailableRules)
        {
            Rules.Add(new RuleToggle
            {
                Id = rule.Id,
                Name = rule.Name,
                Description = rule.Description,
                Mitre = rule.Mitre,
                Enabled = rule.Enabled
            });
        }
        OnPropertyChanged(nameof(RuleCount));
        OnPropertyChanged(nameof(RuleCountText));
    }

    private void Navigate(object? parameter)
    {
        var key = parameter as string ?? (parameter as NavItem)?.Key ?? "dashboard";
        CurrentPage = key;
        _selectedNavItem = NavItems.FirstOrDefault(n => n.Key == key);
        OnPropertyChanged(nameof(SelectedNavItem));
        PageTitle = NavItems.FirstOrDefault(n => n.Key == key)?.Title ?? "概览";
        if (key == "processes") _ = RefreshProcessesAsync();
        if (key == "quarantine") LoadQuarantine();
        if (key == "settings") { RefreshEngineStatus(); RefreshPolicies(); }
        if (key == "policies") RefreshPolicies();
    }

    public void NavigateTo(string key) => Navigate(key);

    private void LoadSettings()
    {
        var settings = _runtime.Settings;
        _autoContain = settings.ResponseMode == ResponseMode.AutoContain;
        _autoQuarantine = settings.AutoQuarantine;
        _blockC2 = settings.BlockC2Endpoint;
        _monitorNetwork = settings.MonitorNetwork;
        _monitorDrivers = settings.MonitorDrivers;
        _monitorWmi = settings.MonitorWmi;
        _monitorFileCreation = settings.MonitorFileCreation;
        _retentionDays = settings.RetentionDays;
        _maxDetections = settings.MaxDetectionsInMemory;
        _scanPath = settings.ScanPath;
        _quarantinePath = settings.QuarantinePath;
        _clamAvPath = settings.ClamAvPath;
        _isProtected = settings.ProtectionEnabled && _runtime.IsRunning;
        RefreshRuleList();
        RefreshEngineStatus();
    }

    private void RefreshEngineStatus()
    {
        var engine = _runtime.ClamAv.FindEngine(ClamAvPath);
        ClamAvStatus = engine is null ? "未检测到 ClamAV" : "ClamAV 就绪";
    }

    private void OnDetectionRaised(DetectionRecord detection) =>
        _dispatcher.BeginInvoke(new Action(() => UpsertDetection(detection)));

    private void OnStateChanged() =>
        _dispatcher.BeginInvoke(new Action(RefreshStats));

    private void OnStatusChanged(string status) =>
        _dispatcher.BeginInvoke(new Action(() => { StatusMessage = status; RefreshStats(); }));

    private void OnLogLine(string line) =>
        _dispatcher.BeginInvoke(new Action(() => AddLog(line)));

    private void UpsertDetection(DetectionRecord detection)
    {
        var existing = Detections.FirstOrDefault(d => d.Id == detection.Id);
        if (existing is null)
        {
            Detections.Insert(0, detection);
        }
        else
        {
            var index = Detections.IndexOf(existing);
            Detections[index] = detection;
        }
        while (Detections.Count > Math.Max(100, MaxDetections)) Detections.RemoveAt(Detections.Count - 1);
        DetectionsView.Refresh();
        OnPropertyChanged(nameof(RecentDetections));
        RefreshStats();
    }

    private void RefreshStats()
    {
        RecentSampleCount = _runtime.RecentSampleCount;
        IsProtected = _runtime.IsRunning && _runtime.Settings.ProtectionEnabled;
        OnPropertyChanged(nameof(ThreatCount));
        OnPropertyChanged(nameof(EventCountText));
        OnPropertyChanged(nameof(BlockedCountText));
        OnPropertyChanged(nameof(ProcessCountText));
        OnPropertyChanged(nameof(RuleCountText));
        OnPropertyChanged(nameof(SysmonStatus));
        OnPropertyChanged(nameof(ProtectionText));
        OnPropertyChanged(nameof(ProtectionActionText));
    }

    private bool FilterDetection(object item)
    {
        if (item is not DetectionRecord detection) return false;
        if (SeverityFilter != "全部" && detection.SeverityText != SeverityFilter) return false;
        if (string.IsNullOrWhiteSpace(DetectionSearch)) return true;
        var query = DetectionSearch.Trim();
        return detection.RuleName.Contains(query, StringComparison.OrdinalIgnoreCase)
            || detection.RuleId.Contains(query, StringComparison.OrdinalIgnoreCase)
            || detection.ProcessName.Contains(query, StringComparison.OrdinalIgnoreCase)
            || detection.ImagePath.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private void AddLog(string line)
    {
        LogLines.Add(line);
        while (LogLines.Count > 1000) LogLines.RemoveAt(0);
    }

    private async Task RefreshProcessesAsync()
    {
        try
        {
            var selectedPid = SelectedProcess?.ProcessId;
            var list = await Task.Run(() => _runtime.RefreshProcesses());
            Processes.Clear();
            foreach (var process in list) Processes.Add(process);
            SelectedProcess = Processes.FirstOrDefault(p => p.ProcessId == selectedPid);
            StatusMessage = string.Concat("已刷新进程列表，共 ", Processes.Count, " 项");
        }
        catch (Exception ex)
        {
            StatusMessage = string.Concat("进程列表刷新失败：", ex.Message);
        }
    }

    private async Task KillProcessAsync(int processId)
    {
        if (processId <= 4) return;
        var ok = await _runtime.Response.TryKillAsync(processId, CancellationToken.None);
        StatusMessage = ok ? string.Concat("已终止进程 PID ", processId) : string.Concat("无法终止 PID ", processId, "，可能受系统保护");
        await RefreshProcessesAsync();
    }

    private async Task QuarantineProcessAsync(ProcessInfo? process)
    {
        if (process is null || string.IsNullOrWhiteSpace(process.ImagePath)) return;
        var entry = await Task.Run(() => _runtime.Quarantine.Quarantine(process.ImagePath, process.Sha256, "手动隔离"));
        StatusMessage = entry is null ? "隔离失败" : string.Concat("已隔离 ", process.Name);
        LoadQuarantine();
    }

    private async Task KillDetectionAsync()
    {
        var detection = SelectedDetection;
        if (detection is null || detection.ProcessId <= 4) return;
        var ok = await _runtime.Response.TryKillAsync(detection.ProcessId, CancellationToken.None);
        detection.Action = ok ? "已终止进程" : "终止失败";
        _runtime.AppendDetection(detection);
        DetectionsView.Refresh();
        StatusMessage = detection.Action;
    }

    private async Task QuarantineDetectionAsync()
    {
        var detection = SelectedDetection;
        if (detection is null || string.IsNullOrWhiteSpace(detection.ImagePath)) return;
        var entry = await Task.Run(() => _runtime.Quarantine.Quarantine(detection.ImagePath, detection.Sha256, detection.RuleName));
        detection.Action = entry is null ? "隔离失败" : "已隔离";
        _runtime.AppendDetection(detection);
        DetectionsView.Refresh();
        StatusMessage = detection.Action;
        LoadQuarantine();
    }

    private async Task RunScanAsync(string mode)
    {
        if (IsScanning) return;
        var target = mode switch
        {
            "quick" => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
            "full" => Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "Users"),
            _ => ScanPath
        };
        if (!Directory.Exists(target) && !File.Exists(target))
        {
            ScanSummary = "扫描路径不存在，请重新选择";
            return;
        }
        ScanFindings.Clear();
        IsScanning = true;
        ScanSummary = string.Concat("正在扫描 ", target);
        _scanCts = new CancellationTokenSource();
        try
        {
            var progress = new Progress<string>(line =>
            {
                if (!string.IsNullOrWhiteSpace(line))
                    ScanSummary = line.Length > 120 ? line.Substring(0, 120) : line;
            });
            var result = await _runtime.ClamAv.ScanAsync(target, ClamAvPath, progress, _scanCts.Token);
            foreach (var finding in result.Findings) ScanFindings.Add(finding);
            ScanSummary = result.Message;
            ClamAvStatus = result.EngineAvailable ? "ClamAV 就绪" : "未检测到 ClamAV";
            _runtime.Log.Info(string.Concat("扫描完成：", result.Message));
        }
        catch (Exception ex)
        {
            ScanSummary = string.Concat("扫描失败：", ex.Message);
        }
        finally
        {
            IsScanning = false;
            _scanCts?.Dispose();
            _scanCts = null;
            StartScanCommand.RaiseCanExecuteChanged();
            CancelScanCommand.RaiseCanExecuteChanged();
        }
    }

    private async Task RunRootkitAsync()
    {
        if (IsRootkitScanning) return;
        IsRootkitScanning = true;
        RootkitFindings.Clear();
        RootkitStatus = "正在检查驱动服务、启动项、Hosts 与 WMI 订阅...";
        try
        {
            var progress = new Progress<string>(text => RootkitStatus = text);
            var findings = await _runtime.Rootkit.ScanAsync(progress, CancellationToken.None);
            foreach (var finding in findings) RootkitFindings.Add(finding);
            RootkitStatus = findings.Count == 0 ? "未发现可疑内核组件" : string.Concat("发现 ", findings.Count, " 项可疑项");
        }
        catch (Exception ex)
        {
            RootkitStatus = string.Concat("检查失败：", ex.Message);
        }
        finally
        {
            IsRootkitScanning = false;
            RunRootkitCommand.RaiseCanExecuteChanged();
        }
    }

    private void LoadQuarantine()
    {
        QuarantineItems.Clear();
        foreach (var entry in _runtime.Quarantine.List()) QuarantineItems.Add(entry);
    }

    private async Task RestoreQuarantineAsync()
    {
        var entry = SelectedQuarantine;
        if (entry is null) return;
        var restored = await Task.Run(() => _runtime.Quarantine.Restore(entry));
        StatusMessage = restored is null ? "恢复失败" : string.Concat("已恢复到 ", restored);
        LoadQuarantine();
    }

    private async Task DeleteQuarantineAsync()
    {
        var entry = SelectedQuarantine;
        if (entry is null) return;
        var ok = await Task.Run(() => _runtime.Quarantine.Delete(entry));
        StatusMessage = ok ? "已从隔离区永久删除" : "删除失败";
        LoadQuarantine();
    }

    private void SaveSettings()
    {
        var settings = _runtime.Settings.Clone();
        settings.ResponseMode = AutoContain ? ResponseMode.AutoContain : ResponseMode.AlertOnly;
        settings.AutoQuarantine = AutoQuarantine;
        settings.BlockC2Endpoint = BlockC2;
        settings.MonitorNetwork = MonitorNetwork;
        settings.MonitorDrivers = MonitorDrivers;
        settings.MonitorWmi = MonitorWmi;
        settings.MonitorFileCreation = MonitorFileCreation;
        settings.RetentionDays = Math.Max(1, RetentionDays);
        settings.MaxDetectionsInMemory = Math.Max(100, MaxDetections);
        settings.ScanPath = ScanPath;
        settings.QuarantinePath = QuarantinePath;
        settings.ClamAvPath = ClamAvPath;
        settings.DisabledRuleIds = Rules.Where(r => !r.Enabled).Select(r => r.Id).ToList();
        _runtime.ApplySettings(settings);
        RefreshEngineStatus();
        SettingsSavedText = string.Concat("已保存 ", DateTime.Now.ToString("HH:mm:ss"));
        OnPropertyChanged(nameof(RuleCountText));
    }

    private void ExportDetections()
    {
        try
        {
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var path = Path.Combine(desktop, string.Concat("B-EDR-告警-", DateTime.Now.ToString("yyyyMMdd-HHmmss"), ".csv"));
            using var writer = new StreamWriter(path, false, new UTF8Encoding(true));
            writer.WriteLine("时间,等级,规则编号,规则名称,评分,进程,PID,父进程,镜像路径,处置");
            foreach (var d in Detections)
            {
                writer.WriteLine(string.Join(",", new[]
                {
                    Csv(d.TimeText), Csv(d.SeverityText), Csv(d.RuleId), Csv(d.RuleName), d.Score.ToString(),
                    Csv(d.ProcessName), d.ProcessId.ToString(), Csv(d.ParentName), Csv(d.ImagePath), Csv(d.Action)
                }));
            }
            StatusMessage = string.Concat("已导出 ", path);
        }
        catch (Exception ex)
        {
            StatusMessage = string.Concat("导出失败：", ex.Message);
        }
    }

    private static string Csv(string value) => string.Concat("\"", value.Replace("\"", "\"\""), "\"");

    private static void BrowseFolder(Action<string> apply)
    {
        using var dialog = new Forms.FolderBrowserDialog { ShowNewFolderButton = true };
        if (dialog.ShowDialog() == Forms.DialogResult.OK) apply(dialog.SelectedPath);
    }

    private static void BrowseFile(Action<string> apply)
    {
        using var dialog = new Forms.OpenFileDialog { Filter = "clamscan.exe|clamscan.exe|可执行文件|*.exe", CheckFileExists = true };
        if (dialog.ShowDialog() == Forms.DialogResult.OK) apply(dialog.FileName);
    }

    private static void OpenFolder(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
        }
        catch { }
    }

    public void Dispose()
    {
        _statsTimer.Stop();
        _runtime.DetectionRaised -= OnDetectionRaised;
        _runtime.StateChanged -= OnStateChanged;
        _runtime.StatusChanged -= OnStatusChanged;
        _runtime.Log.LineWritten -= OnLogLine;
    }
}
