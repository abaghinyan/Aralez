<#
.SYNOPSIS
    Aralez BITS (Background Intelligent Transfer Service) Deployment

.DESCRIPTION
    Uses Windows BITS to download the Aralez binary smoothly in the background, 
    utilizing idle network bandwidth.
    Once downloaded, it executes the binary and uses standard Aralez --output 
    to upload the results.
    
    This is highly recommended for constrained network environments (VPNs, slow WAN links).

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File Deploy-AralezBits.ps1 -SourceUri "http://internal-server.corp/aralez" -OutputDest "s3://forensics-bucket/incoming"
#>

param(
    [string]$SourceUri = "http://dfs.corp.local/deploy/aralez",
    [string]$OutputDest = "\\fileserver\forensics\incoming",
    [string]$WorkDir = "C:\Windows\Temp\AralezBits"
)

$ErrorActionPreference = "Stop"
$LogFile = "C:\Windows\Temp\Aralez_BITS.log"

function Write-Log($Message) {
    $Stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Stamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host "$Stamp - $Message"
}

Write-Log "Starting Aralez BITS Deployment"

if (-not (Test-Path $WorkDir)) {
    New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
}

$ExeUrl = "$SourceUri/aralez_x64_windows.exe"

$ExePath = "$WorkDir\aralez.exe"

Write-Log "Initiating BITS transfer for Aralez binary from $ExeUrl"

try {
    # Import BitsTransfer module
    Import-Module BitsTransfer -ErrorAction SilentlyContinue

    # Download Exe via BITS (Background priority)
    Start-BitsTransfer -Source $ExeUrl -Destination $ExePath -Priority Low -Description "Aralez Forensic Triage Module"

    Write-Log "Aralez binary downloaded successfully."

} catch {
    Write-Log "BITS Transfer failed: $_"
    exit 1
}

# Execute
Write-Log "Executing Aralez with output to $OutputDest"
Set-Location $WorkDir

try {
    $Process = Start-Process -FilePath $ExePath -ArgumentList "--output `"$OutputDest`"" -Wait -NoNewWindow -PassThru
    $ExitCode = $Process.ExitCode
    Write-Log "Execution finished with code $ExitCode"
} catch {
    Write-Log "Execution error: $_"
    $ExitCode = 1
}

# Cleanup
Set-Location "C:\"
Remove-Item -Path $WorkDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Log "Deployment script complete."
exit $ExitCode
