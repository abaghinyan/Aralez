<#
.SYNOPSIS
    Aralez Mass Deployment Script for Windows
    Deploy and execute Aralez on multiple Windows machines via WinRM/PsExec.

.DESCRIPTION
    Deploys the Aralez triage collector to hundreds or thousands of Windows
    machines using PowerShell Remoting (WinRM). Supports parallel execution,
    custom configs, result collection, and multiple authentication methods.

.PARAMETER TargetsFile
    Path to a text file containing one hostname/IP per line.

.PARAMETER Binary
    Path to the aralez.exe binary to deploy.

.PARAMETER Credential
    PSCredential object. If not provided, prompts or uses current user.

.PARAMETER MaxParallel
    Maximum number of parallel deployments (default: 50).

.PARAMETER OutputDest
    Destination for --output flag (e.g., \\fileserver\share or s3://bucket).

.PARAMETER CollectDir
    Local directory to copy result .zip files back to.

.PARAMETER RemoteDir
    Remote working directory (default: C:\Windows\Temp\aralez_deploy).

.PARAMETER UsePsExec
    Use PsExec instead of WinRM for connectivity.

.PARAMETER AralezArgs
    Additional arguments to pass to aralez.exe.

.EXAMPLE
    .\Deploy-Aralez.ps1 -TargetsFile .\targets.txt -Binary .\aralez_x64_windows.exe

.EXAMPLE
    .\Deploy-Aralez.ps1 -TargetsFile .\targets.txt -Binary .\aralez_x64_windows.exe -CollectDir .\results -MaxParallel 100

.EXAMPLE
    $cred = Get-Credential
    .\Deploy-Aralez.ps1 -TargetsFile .\targets.txt -Binary .\aralez_x64_windows.exe -Credential $cred -OutputDest "\\fileserver\forensics"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TargetsFile,

    [Parameter(Mandatory)]
    [string]$Binary,

    [PSCredential]$Credential,

    [int]$MaxParallel = 50,

    [string]$OutputDest = "",

    [string]$CollectDir = "",

    [string]$RemoteDir = 'C:\Windows\Temp\aralez_deploy',

    [switch]$UsePsExec,

    [string]$AralezArgs = "",

    [string]$LogDir = ".\deploy_logs",

    [switch]$DryRun
)

# ── Setup ─────────────────────────────────────────────────────────────────────
$ErrorActionPreference = "Continue"
$StartTime = Get-Date

if (-not (Test-Path $TargetsFile)) {
    Write-Error "Targets file not found: $TargetsFile"
    exit 1
}
if (-not (Test-Path $Binary)) {
    Write-Error "Binary not found: $Binary"
    exit 1
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
if ($CollectDir) {
    New-Item -ItemType Directory -Force -Path $CollectDir | Out-Null
}

$Targets = Get-Content $TargetsFile | Where-Object { $_ -match '\S' -and $_ -notmatch '^\s*#' }
$Total = $Targets.Count

Write-Host ""
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Aralez Mass Deployment — Windows" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Binary:     $Binary"
Write-Host "  Config:     <embedded>"
Write-Host "  Targets:    $Total hosts"
Write-Host "  Parallel:   $MaxParallel"
Write-Host "  Remote Dir: $RemoteDir"
Write-Host "  Method:     $(if($UsePsExec){'PsExec'}else{'WinRM'})"
Write-Host ""

if ($DryRun) {
    Write-Host "[DRY RUN] Would deploy to:" -ForegroundColor Yellow
    $Targets | ForEach-Object { Write-Host "  $_" }
    exit 0
}

# ── WinRM Deployment ──────────────────────────────────────────────────────────
$ScriptBlock = {
    param(
        [string]$HostName,
        [string]$BinaryPath,
        [string]$ConfigPath,
        [string]$RemoteWorkDir,
        [string]$OutputDestination,
        [string]$ExtraArgs,
        [string]$CollectPath,
        [string]$LogPath,
        [PSCredential]$Cred
    )

    $log = @()
    $log += "=== Deployment to $HostName started at $(Get-Date -Format 'o') ==="
    $success = $false

    try {
        # Build session params
        $sessionParams = @{ ComputerName = $HostName }
        if ($Cred) { $sessionParams.Credential = $Cred }

        $session = New-PSSession @sessionParams -ErrorAction Stop
        $log += "[1/5] Connected via WinRM"

        # Create remote directory
        Invoke-Command -Session $session -ScriptBlock {
            param($dir)
            New-Item -ItemType Directory -Force -Path $dir | Out-Null
        } -ArgumentList $RemoteWorkDir
        $log += "[2/5] Created remote directory: $RemoteWorkDir"

        # Upload binary
        Copy-Item -Path $BinaryPath -Destination "$RemoteWorkDir\aralez.exe" -ToSession $session -Force
        $log += "[3/4] Uploaded binary"

        # Execute aralez
        $remoteCmd = "$RemoteWorkDir\aralez.exe"
        if ($OutputDestination) { $remoteCmd += " --output `"$OutputDestination`"" }
        if ($ExtraArgs) { $remoteCmd += " $ExtraArgs" }

        $log += "[4/4] Executing: $remoteCmd"
        $result = Invoke-Command -Session $session -ScriptBlock {
            param($cmd, $workDir)
            Set-Location $workDir
            & cmd /c $cmd 2>&1
        } -ArgumentList $remoteCmd, $RemoteWorkDir

        $log += $result

        # Collect results
        if ($CollectPath) {
            $hostCollectDir = Join-Path $CollectPath $HostName
            New-Item -ItemType Directory -Force -Path $hostCollectDir | Out-Null

            $remoteZips = Invoke-Command -Session $session -ScriptBlock {
                param($dir)
                Get-ChildItem -Path $dir -Filter "*.zip" | Select-Object -ExpandProperty FullName
            } -ArgumentList $RemoteWorkDir

            foreach ($zip in $remoteZips) {
                Copy-Item -Path $zip -Destination $hostCollectDir -FromSession $session -Force
                $log += "      Collected: $zip"
            }
        } else {
            $log += "      Skipping result collection"
        }

        Remove-PSSession $session
        $success = $true

    } catch {
        $log += "ERROR: $($_.Exception.Message)"
    }

    $duration = ((Get-Date) - (Get-Date $log[0].Split('at ')[1].TrimEnd(' ='))).TotalSeconds
    $log += "=== Deployment completed (${duration}s) ==="

    $log | Out-File -FilePath $LogPath -Encoding utf8

    [PSCustomObject]@{
        Host    = $HostName
        Success = $success
        LogFile = $LogPath
    }
}

# ── PsExec Deployment ─────────────────────────────────────────────────────────
$PsExecBlock = {
    param(
        [string]$HostName,
        [string]$BinaryPath,
        [string]$ConfigPath,
        [string]$RemoteWorkDir,
        [string]$OutputDestination,
        [string]$ExtraArgs,
        [string]$LogPath,
        [PSCredential]$Cred
    )

    $log = @()
    $log += "=== PsExec deployment to $HostName at $(Get-Date -Format 'o') ==="
    $success = $false

    try {
        $uncPath = "\\$HostName\C$\Windows\Temp\aralez_deploy"

        # Create directory via UNC
        New-Item -ItemType Directory -Force -Path $uncPath | Out-Null
        $log += "[1/4] Created directory via UNC"

        # Copy binary
        Copy-Item -Path $BinaryPath -Destination "$uncPath\aralez.exe" -Force
        $log += "[2/3] Copied binary"

        # Execute via PsExec
        $psexecArgs = @("\\$HostName", "-accepteula", "-s", "-h")
        if ($Cred) {
            $psexecArgs += "-u", $Cred.UserName
            $psexecArgs += "-p", $Cred.GetNetworkCredential().Password
        }

        $cmd = "$RemoteWorkDir\aralez.exe"
        if ($OutputDestination) { $cmd += " --output `"$OutputDestination`"" }
        if ($ExtraArgs) { $cmd += " $ExtraArgs" }

        $psexecArgs += $cmd

        $log += "[3/3] Running: psexec $($psexecArgs -join ' ')"
        $result = & psexec @psexecArgs 2>&1
        $log += $result

        $log += "      Execution completed"
        $success = $true

    } catch {
        $log += "ERROR: $($_.Exception.Message)"
    }

    $log | Out-File -FilePath $LogPath -Encoding utf8

    [PSCustomObject]@{
        Host    = $HostName
        Success = $success
        LogFile = $LogPath
    }
}

# ── Execute ───────────────────────────────────────────────────────────────────
Write-Host "[TASK] Starting deployment to $Total hosts ($MaxParallel parallel)..." -ForegroundColor Blue
Write-Host ""

$Jobs = @()
$Block = if ($UsePsExec) { $PsExecBlock } else { $ScriptBlock }

foreach ($host in $Targets) {
    # Throttle parallel jobs
    while ((Get-Job -State Running).Count -ge $MaxParallel) {
        Start-Sleep -Milliseconds 500
        Get-Job -State Completed | ForEach-Object {
            $result = Receive-Job $_
            if ($result.Success) {
                Write-Host "  ✓ $($result.Host)" -ForegroundColor Green
            } else {
                Write-Host "  ✗ $($result.Host) — see $($result.LogFile)" -ForegroundColor Red
            }
            Remove-Job $_
        }
    }

    $logFile = Join-Path $LogDir "$host.log"
    $jobParams = @{
        ScriptBlock  = $Block
        ArgumentList = @(
            $host, $Binary, $RemoteDir,
            $OutputDest, $AralezArgs, $CollectDir,
            $logFile, $Credential
        )
    }

    $Jobs += Start-Job @jobParams
}

# Wait for remaining jobs
$Jobs | Wait-Job | ForEach-Object {
    $result = Receive-Job $_
    if ($result.Success) {
        Write-Host "  ✓ $($result.Host)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $($result.Host) — see $($result.LogFile)" -ForegroundColor Red
    }
    Remove-Job $_
}

# ── Summary ───────────────────────────────────────────────────────────────────
$Duration = (Get-Date) - $StartTime
$Succeeded = (Get-ChildItem $LogDir -Filter "*.log" | Where-Object {
    (Get-Content $_.FullName -Raw) -match "completed"
}).Count
$Failed = $Total - $Succeeded

Write-Host ""
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Deployment Summary" -ForegroundColor Cyan
Write-Host "  Total:     $Total"
Write-Host "  Succeeded: $Succeeded" -ForegroundColor Green
Write-Host "  Failed:    $Failed" -ForegroundColor $(if($Failed -gt 0){'Red'}else{'Green'})
Write-Host "  Duration:  $($Duration.ToString('hh\:mm\:ss'))"
Write-Host "  Logs:      $LogDir\"
if ($CollectDir) { Write-Host "  Results:   $CollectDir\" }
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan

exit $(if ($Failed -gt 0) { 1 } else { 0 })
