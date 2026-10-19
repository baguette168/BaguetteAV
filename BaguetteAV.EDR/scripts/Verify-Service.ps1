[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServiceExe,
    [string]$ServiceName = 'B-EDR Protection',
    [string]$OutputPath = ''
)

$ErrorActionPreference = 'Stop'

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'This script must run from an elevated administrator PowerShell.'
    }
}

function Invoke-PipeCommand {
    param([string]$Command)

    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'BEDR.Local.Control', [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $pipe.Connect(5000)
        $encoding = New-Object System.Text.UTF8Encoding($false)
        $writer = New-Object System.IO.StreamWriter($pipe, $encoding, 1024, $true)
        $reader = New-Object System.IO.StreamReader($pipe, $encoding, $false, 1024, $true)
        $writer.AutoFlush = $true
        $writer.WriteLine((@{ command = $Command } | ConvertTo-Json -Compress))
        $line = $reader.ReadLine()
        if ([string]::IsNullOrWhiteSpace($line)) { throw 'Empty control pipe response.' }
        return $line | ConvertFrom-Json
    }
    finally {
        $pipe.Dispose()
    }
}

function Get-ServicePid {
    $output = & sc.exe queryex $ServiceName 2>&1
    $match = [regex]::Match(($output -join "`n"), 'PID\\\\s*:\\\\s*(\\\\d+)')
    if (-not $match.Success) { return 0 }
    return [int]$match.Groups[1].Value
}

function Wait-ServiceRunning {
    param([int]$TimeoutSeconds = 30, [int]$DifferentFromPid = -1)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 750
        $query = & sc.exe query $ServiceName 2>&1
        if (($query -join "`n") -match 'RUNNING') {
            $servicePid = Get-ServicePid
            if ($servicePid -gt 0 -and $servicePid -ne $DifferentFromPid) { return $servicePid }
        }
    }
    return 0
}

Assert-Administrator
if (-not (Test-Path -LiteralPath $ServiceExe)) { throw "Service executable not found: $ServiceExe" }
$ServiceExe = (Resolve-Path -LiteralPath $ServiceExe).Path
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts\\\\service-verification.json'
}

$existing = & sc.exe query $ServiceName 2>&1
if ($LASTEXITCODE -eq 0) {
    throw "Service '$ServiceName' already exists. Refusing to overwrite an existing installation."
}

$result = [ordered]@{
    timestamp = (Get-Date).ToString('o')
    serviceName = $ServiceName
    serviceExe = $ServiceExe
    installed = $false
    startType = ''
    account = ''
    failureActions = ''
    initialPid = 0
    initialQuery = ''
    pipePing = $null
    pipeStatus = $null
    forcedKillPid = 0
    restartedPid = 0
    restartSeconds = $null
    cleanedUp = $false
}

try {
    $installOutput = & $ServiceExe --install 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Service install failed: $($installOutput -join ' ')" }
    $result.installed = $true

    $config = (& sc.exe qc $ServiceName 2>&1) -join "`n"
    $result.initialQuery = $config
    if ($config -match 'START_TYPE\\\\s*:\\\\s*([^\\\\r\\\\n]+)') { $result.startType = $Matches[1].Trim() }
    if ($config -match 'SERVICE_START_NAME\\\\s*:\\\\s*([^\\\\r\\\\n]+)') { $result.account = $Matches[1].Trim() }

    $failure = (& sc.exe qfailure $ServiceName 2>&1) -join "`n"
    $result.failureActions = $failure
    if ($result.startType -notmatch 'AUTO_START') { throw "Unexpected start type: $($result.startType)" }
    if ($result.account -notmatch 'LocalSystem') { throw "Unexpected service account: $($result.account)" }
    if ($failure -notmatch 'RESTART') { throw 'Failure restart actions are missing.' }

    $initialPid = Wait-ServiceRunning -TimeoutSeconds 30
    if ($initialPid -eq 0) { throw 'Service did not reach RUNNING.' }
    $result.initialPid = $initialPid
    $result.pipePing = Invoke-PipeCommand -Command 'ping'
    $result.pipeStatus = Invoke-PipeCommand -Command 'status'

    $killStarted = Get-Date
    & taskkill.exe /F /PID $initialPid | Out-Null
    $result.forcedKillPid = $initialPid
    $restartedPid = Wait-ServiceRunning -TimeoutSeconds 90 -DifferentFromPid $initialPid
    if ($restartedPid -eq 0) { throw 'Service did not restart after forced termination.' }
    $result.restartedPid = $restartedPid
    $result.restartSeconds = [math]::Round(((Get-Date) - $killStarted).TotalSeconds, 1)

    $result.pipePingAfterRestart = Invoke-PipeCommand -Command 'ping'
}
finally {
    & sc.exe stop $ServiceName 2>&1 | Out-Null
    Start-Sleep -Seconds 2
    & sc.exe delete $ServiceName 2>&1 | Out-Null
    $result.cleanedUp = -not ((& sc.exe query $ServiceName 2>&1) -match 'SERVICE_NAME')
    $result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
    Write-Output "Verification log: $OutputPath"
}
