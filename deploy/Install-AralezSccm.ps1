<#
.SYNOPSIS
    Aralez SCCM / Intune Deployment Script

.DESCRIPTION
    This script is designed to be run by Microsoft Endpoint Configuration Manager (SCCM)
    or Microsoft Intune as an Application or Package installation script.
    
    It executes Aralez forensic collection and uploads the results.
    For SCCM Detection Methods, it creates a registry key upon successful completion.

.PARAMETER OutputDest
    Destination for the triage zip (e.g., \\server\share or s3://bucket).

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File Install-AralezSccm.ps1 -OutputDest "\\corp-fs.corp.local\ForensicEvidence$"
#>

param(
    [string]$OutputDest = "\\fileserver\forensics\incoming"
)

$ErrorActionPreference = "Continue"

# Define paths
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AralezExe = Join-Path $ScriptDir "aralez_x64_windows.exe"

$WorkDir = "C:\Windows\Temp\AralezExecution"
$LogFile = "C:\Windows\Temp\Aralez_SCCM_Install.log"

function Write-Log($Message) {
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Stamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host "$Stamp - $Message"
}

Write-Log "Starting Aralez SCCM Deployment"

if (-not (Test-Path $AralezExe)) {
    Write-Log "ERROR: aralez_x64_windows.exe not found in $ScriptDir"
    exit 1
}

# Ensure working directory exists
if (-not (Test-Path $WorkDir)) {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
}

# Copy files locally to avoid locking issues on the network share
Write-Log "Copying binaries to $WorkDir"
Copy-Item -Path $AralezExe -Destination "$WorkDir\aralez.exe" -Force

# Build Execution Command
$Cmd = "$WorkDir\aralez.exe"
if ($OutputDest) {
    $Cmd += " --output `"$OutputDest`""
}

Write-Log "Executing Aralez: $Cmd"
Set-Location $WorkDir

try {
    # Execute and wait
    $Process = Start-Process -FilePath "$WorkDir\aralez.exe" -ArgumentList "--output `"$OutputDest`"" -Wait -NoNewWindow -PassThru
    $ExitCode = $Process.ExitCode
    
    Write-Log "Aralez execution finished with exit code: $ExitCode"

    if ($ExitCode -eq 0) {
        # Create Registry tag for SCCM Detection Method
        $RegPath = "HKLM:\SOFTWARE\AralezForensics"
        if (-not (Test-Path $RegPath)) {
            New-Item -Path $RegPath -Force | Out-Null
        }
        Set-ItemProperty -Path $RegPath -Name "LastRun" -Value (Get-Date -Format "o")
        Set-ItemProperty -Path $RegPath -Name "Version" -Value "1.0"
        
        Write-Log "Successfully tagged registry for SCCM detection."
    }
} catch {
    Write-Log "Execution exception: $_"
    $ExitCode = 1
}

# Cleanup
Write-Log "Cleaning up working directory."
Set-Location "C:\"
Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Log "Exiting with code $ExitCode"
exit $ExitCode
