param(
    [string]$Configuration = "Release",
    [string]$Version = "2.0.0"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$artifactsRoot = [System.IO.Path]::GetFullPath((Join-Path $root "artifacts"))
$output = [System.IO.Path]::GetFullPath((Join-Path $artifactsRoot "B-EDR-$Version"))
$artifactsPrefix = $artifactsRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
if (-not $output.StartsWith($artifactsPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Publish output must stay inside $artifactsRoot"
}

$appOutput = Join-Path $output "app"
$serviceOutput = Join-Path $output "service"
$toolOutput = Join-Path $output "tool"
if (Test-Path -LiteralPath $output) {
    Remove-Item -LiteralPath $output -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $appOutput, $serviceOutput, $toolOutput | Out-Null

$appProject = Join-Path $root "BaguetteAV.EDR.App\BaguetteAV.EDR.App.csproj"
$serviceProject = Join-Path $root "BaguetteAV.EDR.Service\BaguetteAV.EDR.Service.csproj"
$toolProject = Join-Path $root "BaguetteAV.EDR.PolicyTool\BaguetteAV.EDR.PolicyTool.csproj"

dotnet publish $appProject -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $appOutput
if ($LASTEXITCODE -ne 0) { throw "Application publish failed" }

dotnet publish $serviceProject -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true -o $serviceOutput
if ($LASTEXITCODE -ne 0) { throw "Service publish failed" }

dotnet publish $toolProject -c $Configuration -r win-x64 --self-contained true -p:PublishSingleFile=true -o $toolOutput
if ($LASTEXITCODE -ne 0) { throw "Policy tool publish failed" }

Copy-Item -LiteralPath (Join-Path $root "samples\policies") -Destination (Join-Path $output "policies") -Recurse -Force
Copy-Item -LiteralPath (Join-Path $root "README.md") -Destination $output -Force
Copy-Item -LiteralPath (Join-Path $root "docs") -Destination $output -Recurse -Force
if (Test-Path -LiteralPath (Join-Path $root "scripts")) {
    Copy-Item -LiteralPath (Join-Path $root "scripts") -Destination $output -Recurse -Force
}
$workspaceResearchDoc = Join-Path $root "..\..\..\docs\B-EDR自定义策略架构.md"
if (Test-Path -LiteralPath $workspaceResearchDoc) {
    Copy-Item -LiteralPath $workspaceResearchDoc -Destination (Join-Path $output "docs") -Force
} else {
    Write-Warning "Research architecture document not found: $workspaceResearchDoc"
}
Copy-Item -LiteralPath (Join-Path $root "Install-BEDR.ps1") -Destination $output -Force

$buildInfo = [ordered]@{
    product = "B-EDR"
    version = $Version
    configuration = $Configuration
    runtime = "win-x64"
    publishedAt = (Get-Date).ToString("o")
}
$buildInfo | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $output "BUILD-INFO.json") -Encoding UTF8

Write-Host "Published to $output"
