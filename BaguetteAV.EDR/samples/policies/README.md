# B-EDR 自定义策略包

策略包是纯 JSON 声明式文件，不执行任意代码。导入前会校验字段、操作符、正则、事件类型和条件复杂度，导入后原子切换并可回滚。

## 命令

```powershell
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- validate .\lab\BaguetteAV\BaguetteAV.EDR\samples\policies\kernel-research.policy.json
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- simulate .\lab\BaguetteAV\BaguetteAV.EDR\samples\policies\kernel-research.policy.json .\lab\BaguetteAV\BaguetteAV.EDR\samples\policies\kernel-research.events.json
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- test .\lab\BaguetteAV\BaguetteAV.EDR\samples\policies\kernel-research.policy.json .\lab\BaguetteAV\BaguetteAV.EDR\samples\policies\kernel-research.tests.json
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- coverage --policy .\lab\BaguetteAV\BaguetteAV.EDR\samples\policies\kernel-research.policy.json --markdown
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- keygen --private .\lab-private.pem --public .\lab-public.pem
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- trust-key .\lab-public.pem --name "B-EDR Lab"
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- pack --policy .\lab\BaguetteAV\BaguetteAV.EDR\samples\policies\kernel-research.policy.json --tests .\lab\BaguetteAV\BaguetteAV.EDR\samples\policies\kernel-research.tests.json --key .\lab-private.pem --publisher "B-EDR Lab" --out .\kernel-research.bedrpack
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- verify-package .\kernel-research.bedrpack
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- install-package .\kernel-research.bedrpack
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- publishers
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- revoke-key <publisher-key-id>
dotnet run --project .\lab\BaguetteAV\BaguetteAV.EDR\BaguetteAV.EDR.PolicyTool -- install .\lab\BaguetteAV\BaguetteAV.EDR\samples\policies\kernel-research.policy.json
```

## 条件

- 组合：`all`、`any`、`not`
- 操作符：`eq`、`ne`、`contains`、`startsWith`、`endsWith`、`regex`、`in`、`notIn`、`gt`、`gte`、`lt`、`lte`、`exists`、`missing`
- 字段：`bedr-policy fields`
- 自定义遥测字段：`field.<name>`

## 响应动作

规则可选 `response`，默认 `inherit`（沿用全局响应设置）：

- `alert`：只记录告警
- `terminate_process`：终止命中进程
- `quarantine_file`：隔离命中文件
- `block_destination`：阻断告警中的远端地址
- `contain`：终止进程、隔离文件并阻断远端地址

响应动作只有在设置中开启“自动处置”后才会执行。策略不能绕过受保护进程和系统目录限制，也不能执行任意命令。

建议新规则先使用 `response: "alert"` 观察误报，确认后再改为受限处置动作并导入新版本。同一策略 ID/版本不允许改写为不同内容；规则 ID 不能与内置规则或其他已安装策略重复。已安装策略在每次热加载时都会核对元数据中的 SHA256，手工修改 `policy.json` 会被拒绝，导入、启停、回滚和删除会追加到 `audit.jsonl`。

## 研究流程

1. 把样本行为整理成 `event/process` 事件样本。
2. 编写策略并用 GUI 的“离线演练”或 `simulate` 命令做离线演练；界面可导出实时遥测作为样本。
3. 用 `test` 或 GUI“运行回归测试”固定正样本命中与负样本静默。
4. `validate` 通过后导入并启用；`coverage` 输出 ATT&CK 与遥测覆盖。
5. 线上命中后根据日志调整阈值；保留上一版本用于 `rollback`。
