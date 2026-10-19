param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
$service = Join-Path $PSScriptRoot "service\BaguetteAV.EDR.Service.exe"
$app = Join-Path $PSScriptRoot "app\BaguetteAV.EDR.exe"
if (-not (Test-Path -LiteralPath $service)) { throw "未找到 $service" }

if ($Uninstall) {
    Start-Process -FilePath $service -ArgumentList "--uninstall" -Verb RunAs -Wait
    Write-Host "B-EDR 保护服务已卸载"
    return
}

Start-Process -FilePath $service -ArgumentList "--install" -Verb RunAs -Wait
if (-not (Test-Path -LiteralPath $app)) { throw "未找到 $app" }
Start-Process -FilePath $app
