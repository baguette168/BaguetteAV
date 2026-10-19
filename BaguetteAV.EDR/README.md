# B-EDR 2.0

B-EDR 是 `BaguetteAV` 的第二代 Windows 单机端点检测与响应项目。它保留原项目的图形化杀毒软件形态，同时把检测、响应、策略管理拆成可研究、可验证、可回滚的工程模块。

策略系统设计见 [POLICY_ARCHITECTURE.md](docs/POLICY_ARCHITECTURE.md)。
面向研究者的最小策略、样本和插件接入示例见 [策略扩展开发指南](docs/策略扩展开发指南.md)。

## 架构

```text
┌──────────────────────────────┐
│ BaguetteAV.EDR.exe (WPF)     │
│ 概览 / 告警 / 策略 / 隔离 / 扫描 │
└──────────────┬───────────────┘
               │ 本机命名管道（仅管理员）
┌──────────────▼───────────────┐
│ BaguetteAV.EDR.Service.exe   │
│ EdrRuntime                   │
│  ├─ Sysmon / TCP 遥测         │
│  ├─ 内置规则 + 导入策略       │
│  ├─ 评分与告警持久化          │
│  └─ 终止 / 隔离 / 防火墙响应   │
└──────────────────────────────┘
```

这是单机杀软的双进程结构：后台服务持续防护，GUI 只是本机控制台。关闭、崩溃或重新打开 GUI 不会停止保护服务。

## 核心能力

- Sysmon EID 1/3/6/8/10/11/19/20/21 与 TCP 表降级采集
- 进程、网络、驱动加载、WMI 订阅、远程线程、LSASS 访问检测
- 用户目录驱动落地、未签名驱动、C2 端口、WMI 持久化、注入链规则
- 告警评分、严重级别、JSONL 持久化、误报标记
- 进程终止、文件隔离、远端地址阻断
- ClamAV 按需扫描与 Rootkit 交叉视图检查
- 声明式 JSON 策略包：校验、SHA256 完整性复核、版本不可变、规则冲突拒绝、原子安装、审计日志、仓库监视自动热加载、停用、回滚
- 实时遥测导出、离线演练、自定义字段和受限响应动作
- 策略回归测试（expect/forbid/strict）与 ATT&CK/遥测覆盖报告
- 受信任代码插件：未登记或 SHA256 不匹配的 DLL 默认拒绝加载

## 自定义策略

策略包示例位于 [samples/policies](samples/policies/kernel-research.policy.json)。策略只描述条件，不允许执行任意代码。

```json
{
  "schemaVersion": 1,
  "id": "research.kernel.c2",
  "name": "C2 外联研究策略",
  "version": "1.0.0",
  "minEngineVersion": "2.0.0",
  "rules": [{
    "id": "RESEARCH-C2-8443",
    "name": "8443 C2 外联",
    "severity": "Critical",
    "score": 30,
    "response": "block_destination",
    "eventKinds": ["NetworkConnect"],
    "condition": { "field": "network.destination.port", "op": "eq", "value": 8443 }
  }]
}
```

支持 `all`、`any`、`not` 条件组合，`eq`、`contains`、`regex`、`in`、数值比较、`exists` 等操作符。响应动作支持 `alert`、`terminate_process`、`quarantine_file`、`block_destination`、`contain`，但只有在设置中开启自动处置后才会执行。

研究工作流：

1. 在 GUI 中开启实时防护并导出真实遥测样本。
2. 编写策略包和事件样本。
3. 使用 GUI“离线演练”或 `bedr-policy simulate` 验证命中与误报。
4. 用 `bedr-policy test` 固定回归用例，用 `coverage` 量化覆盖。
5. 导入策略，后台服务热加载，无需重启。
6. 观察真实告警；用版本回滚恢复上一版策略。

策略加载时会重新核对活动版本、包 ID 和文件 SHA256；被替换或修改的
`policy.json` 会被拒绝，其他内置规则和已校验策略继续运行。SHA256 是安装
完整性标记，不是发布者身份签名，管理员权限仍属于最高信任边界。

数据目录会在服务启动和策略导入前收紧为仅 `SYSTEM` 与 `Administrators`
可写；如果加固失败，服务会禁用外部策略与插件加载。相同策略 ID/版本不允许
覆盖为不同内容，规则 ID 与内置规则或其他已安装策略冲突时整包拒绝。每次
导入、启停、回滚和删除都会写入 `policies/audit.jsonl`。

命令行：

```powershell
dotnet run --project .\BaguetteAV.EDR.PolicyTool -- validate .\samples\policies\kernel-research.policy.json
dotnet run --project .\BaguetteAV.EDR.PolicyTool -- simulate .\samples\policies\kernel-research.policy.json .\samples\policies\kernel-research.events.json
dotnet run --project .\BaguetteAV.EDR.PolicyTool -- test .\samples\policies\kernel-research.policy.json .\samples\policies\kernel-research.tests.json
dotnet run --project .\BaguetteAV.EDR.PolicyTool -- coverage --policy .\samples\policies\kernel-research.policy.json --markdown
dotnet run --project .\BaguetteAV.EDR.PolicyTool -- install .\samples\policies\kernel-research.policy.json
dotnet run --project .\BaguetteAV.EDR.PolicyTool -- list
```

发布包中已包含独立策略工具，可直接运行：

```powershell
.\tool\bedr-policy.exe validate .\policies\kernel-research.policy.json
.\tool\bedr-policy.exe simulate .\policies\kernel-research.policy.json .\policies\kernel-research.events.json
```

## 构建与运行

环境：Windows 10/11、.NET 8 SDK、管理员权限（服务安装与驱动/Sysmon 访问）。

```powershell
dotnet build .\BaguetteAV.EDR.sln
dotnet test .\BaguetteAV.EDR.Tests\BaguetteAV.EDR.Tests.csproj
```

安装后台服务：

```powershell
.\BaguetteAV.EDR.Service.exe --install
```

服务启动后运行 GUI。开发调试可用 `--local` 使用进程内运行时，或 `--preview` 以不启动防护的方式打开界面。

卸载：

```powershell
.\BaguetteAV.EDR.Service.exe --uninstall
```

## 数据目录

默认位置为 `%ProgramData%\BaguetteAV\EDR`：

- `settings.json`：防护与响应设置
- `detections\detections-yyyyMMdd.jsonl`：告警记录
- `policies\`：已安装策略、状态和版本
- `plugins\`：受信任插件与 `trusted.json`
- `quarantine\`：隔离文件
- `edr.log`：运行日志

## 防护边界

用户态 EDR 能覆盖驱动加载前的策略阻断、进程创建、网络外联、WMI 持久化和部分注入行为。已经完成的内核内存篡改、LSTAR/MSR 写入、DKOM 全链表摘除，不能被用户态 API 可靠恢复。完整防御需要 HVCI、WDAC、Microsoft 漏洞驱动阻止列表、内核回调或 hypervisor 级监控。B-EDR 在界面和论文中明确标注这一边界，不把用户态检测宣称为内核级全覆盖。

## 目录

- `BaguetteAV.EDR.Core`：检测引擎、策略、响应、存储
- `BaguetteAV.EDR.App`：WPF 控制台
- `BaguetteAV.EDR.Service`：Windows 单机保护服务与本地 IPC
- `BaguetteAV.EDR.PolicyTool`：策略校验、演练、安装和回滚
- `BaguetteAV.EDR.Tests`：核心单元测试
- `BaguetteAV.EDR.Plugin.Sample`：受信任插件示例
- `samples/policies`：策略包与遥测样本
