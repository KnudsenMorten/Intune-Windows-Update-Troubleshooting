<#
    .NAME
    Windows Client Troubleshooting (

    .SYNOPSIS

    .NOTES
    
    .VERSION
    1.0
    
    .AUTHOR
    Morten Knudsen, Microsoft MVP - https://mortenknudsen.net

    .LICENSE
    Licensed under the MIT license.

    .PROJECTURI
    https://github.com/KnudsenMorten/Intune-Windows-Update-Troubleshooting


    .WARRANTY
    Use at your own risk, no warranty given!
#>

# === CONFIGURATION ===
$CollectCompleteLogs = $false
$CollectWULogsOnly = $false
$RunSystemRepairs = $false
$RunWUReset = $true
$RunPolicySimulation = $true
$RunWUCheck = $true
$RunTelemetryCheck = $true
$RunIMECheck = $true
$RunDSREGCheck = $true
$RunIMERepair = $false


# === SETUP ===
$LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\FeatureUpdateValidation.log"
New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force | Out-Null
Start-Transcript -Path $LogPath -Append


# === ADMIN CHECK ===
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "❌ Please run this script as Administrator."
    Stop-Transcript
    exit 1
}


# === SYSTEM REPAIR SECTION ===
if ($RunSystemRepairs) {
    Write-Host ""
    Write-Host "⚙ Performing system file integrity checks..."
    sfc /scannow
    dism /online /cleanup-image /scanhealth
    DISM /Online /Cleanup-Image /RestoreHealth
    Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
}


# === TELEMETRY & SERVICE CHECKS ===
if ($RunTelemetryCheck) {
    Write-Host ""
    Write-Host "🔍 Checking telemetry and diagnostics settings..."

    function Check-RegistryValue {
        param ([string]$Path, [string]$Name)
        try {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $value.$Name
        } catch {
            return $null
        }
    }

    $diagTrack = Get-Service -Name "DiagTrack" -ErrorAction SilentlyContinue
    Write-Host ""
    if ($diagTrack -and $diagTrack.Status -eq 'Running') {
        Write-Host "✅ DiagTrack service is running."
    } else {
        Write-Host "❌ DiagTrack service is not running."
    }

    $telemetryLevel = Check-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry"
    Write-Host ""
    if ($telemetryLevel -ge 3) {
        Write-Host "✅ Telemetry Level: $telemetryLevel"
    } else {
        Write-Host "❌ Telemetry Level too low: $telemetryLevel (min: 3)"
    }

    $policyTelemetry = Check-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\System" -Name "AllowTelemetry"
    Write-Host ""
    if ($policyTelemetry) {
        Write-Host "✅ PolicyManager Telemetry Level: $policyTelemetry"
    } else {
        Write-Host "❌ PolicyManager Telemetry Level not set."
    }

    $commercialId = Check-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "CommercialId"
    Write-Host ""
    if ($commercialId) {
        Write-Host "✅ Commercial ID set: $commercialId"
    } else {
        Write-Host "❌ Commercial ID not set."
    }

    $safeguardHold = Check-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators" -Name "UpgEx"
    Write-Host ""
    if ($safeguardHold) {
        Write-Host "❌ Safeguard Hold Detected: $safeguardHold"
    } else {
        Write-Host "✅ No Safeguard Holds detected."
    }
}


# === WINDOWS UPDATE CHECK ===
if ($RunWUCheck) {
    Write-Host ""
    Write-Host "🧹 Checking for and removing policy keys that block Windows Update..."

    $pathsToClean = @(
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DoNotConnectToWindowsUpdateInternetLocations" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableWindowsUpdateAccess" },
        @{ Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate" }
    )

    foreach ($item in $pathsToClean) {
        try {
            $property = Get-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction SilentlyContinue
            if ($null -ne $property) {
                Remove-ItemProperty -Path $item.Path -Name $item.Name -ErrorAction SilentlyContinue
                Write-Host "✅ Removed $($item.Name) from $($item.Path)"
            }
        } catch {
            # Do nothing
        }
    }
}




# === WINDOWS UPDATE RESET ===
if ($RunWUReset) {
    Write-Host ""
    Write-Host "🔄 Performing Windows Update Reset..."

    Stop-Service wuauserv -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    Stop-Service bits -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    Stop-Service cryptSvc -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    Stop-Service msiserver -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    Stop-Service uhssvc -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

    $sdPath = "C:\Windows\SoftwareDistribution"
    $catrootPath = "C:\Windows\System32\catroot2"

    if (Test-Path $sdPath) {
        Remove-Item -Path $sdPath -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -Path $sdPath -ItemType Directory -Force | Out-Null
    }

    if (Test-Path $catrootPath) {
        Remove-Item -Path $catrootPath -Recurse -Force -ErrorAction SilentlyContinue
        New-Item -Path $catrootPath -ItemType Directory -Force | Out-Null
    }

    Start-Service wuauserv -ErrorAction SilentlyContinue  -WarningAction SilentlyContinue
    Start-Service bits -ErrorAction SilentlyContinue  -WarningAction SilentlyContinue
    Start-Service cryptSvc -ErrorAction SilentlyContinue  -WarningAction SilentlyContinue
    Start-Service msiserver -ErrorAction SilentlyContinue  -WarningAction SilentlyContinue
    Start-Service uhssvc -ErrorAction SilentlyContinue  -WarningAction SilentlyContinue

    Write-Host ""
    Write-Host "✅ Windows Update services restarted and folders reset."
}


# === DSREG STATUS ===
if ($RunDSREGCheck) {
    Write-Host ""
    Write-Host "🔐 Checking Entra ID Join Status..."
    $aad = dsregcmd /status | Select-String "AzureAdJoined"
    $hybrid = dsregcmd /status | Select-String "DomainJoined"

    Write-Host ""
    if ($aad -match "YES") {
        Write-Host "✅ Device is Enta ID joined."
    } else {
        Write-Host "❌ Not Entra ID joined."
    }

    Write-Host ""
    if ($hybrid -match "YES") {
        Write-Host "✅ Device is Hybrid joined."
    } else {
        Write-Host "❌ Not Hybrid joined."
    }
}


# === INTUNE MANAGEMENT EXTENSION CHECK ===
if ($RunIMECheck) {
    Write-Host ""
    Write-Host "🛠 Restarting Intune Management Extension..."
    Stop-Service IntuneManagementExtension -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
    Start-Service IntuneManagementExtension -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
}

# === INTUNE MANAGEMENT EXTENSION REPAIR ===
if ($RunIMERepair) {
    # Uninstall
    msiexec /x "{1F8496D2-52D3-4DA4-BC6D-48A74D1C42E0}" /quiet /norestart

    # Re-download and reinstall
    Invoke-WebRequest "https://go.microsoft.com/fwlink/?linkid=2156826" -OutFile "$env:TEMP\IME.msi"
    Start-Process msiexec.exe -ArgumentList "/i `"$env:TEMP\IME.msi`" /quiet /norestart" -Wait
}


# === POLICY SIMULATION ===
if ($RunPolicySimulation) {
    Write-Host ""
    Write-Host "🔒 Simulating MDM policy update to trigger MDM policy to refresh..."
    reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "DummyPolicy" /t REG_DWORD /d 1 /f >$null 2>&1
    Start-Sleep -Seconds 3
    reg delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "DummyPolicy" /f >$null 2>&1
    Write-Host ""
    Write-Host "✅ Policy refresh simulated."
}


# === LOG COLLECTION ===
if ($CollectCompleteLogs) {
    Write-Host ""
    Write-Host "📁 Collecting logs..."

    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $tempFolder = "C:\Temp\IntuneLogs_$timestamp"
    $zipPath = "$tempFolder.zip"

    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    wevtutil epl "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" "$tempFolder\MDM_EventLog.evtx"
    wevtutil epl "Microsoft-Windows-WindowsUpdateClient/Operational" "$tempFolder\WU_EventLog.evtx"
    Get-WindowsUpdateLog -LogPath "$tempFolder\WindowsUpdate.log"

    mdmdiagnosticstool.exe -area "DeviceProvisioning;DeviceEnrollment;Autopilot;DeviceManagementEnterprise-Diagnostics-Provider;Accounts;ModernApps;Connectivity;WNS;PushNotifications" -cab "$tempFolder\MDMDiag.cab"
    expand.exe "$tempFolder\MDMDiag.cab" -F:* $tempFolder
    Remove-Item "$tempFolder\MDMDiag.cab" -Force

    Compress-Archive -Path $tempFolder\* -DestinationPath $zipPath -Force

    Write-Host ""
    Write-Host "✅ Logs collected and saved to: $zipPath"
}

if ($CollectWULogsOnly) {
    Write-Host ""
    Write-Host "📤 Building Windows Update Logs ... Please Wait !"
    $timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $tempFolder = "C:\Temp\IntuneLogs_$timestamp"

    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    Get-WindowsUpdateLog -LogPath "$tempFolder\WindowsUpdate.log" -ForceFlush -Confirm:$false
}


# === FORCE COMPATIBILITY DATA SUBMISSION | Touching or updating LastDeviceScanTime can help re-initiate the compatibility assessment pipeline ===
Write-Host ""
Write-Host "📤 Forcing compatibility data submission to Windows Update for Business..."

# This registry key is often touched to ensure data is reprocessed
$null = New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators" `
    -Name "LastDeviceScanTime" -Value ([System.Management.ManagementDateTimeConverter]::ToDmtfDateTime((Get-Date))) `
    -PropertyType String -Force

Start-Process -FilePath "C:\Windows\System32\compattelrunner.exe" -ArgumentList "-maintenance" -NoNewWindow -Wait

Write-Host "✅ Compatibility scan & data submission triggered."


# Scan for updates (recommended method)
write-host "Trigger 'Scan for Updates'"
UsoClient StartScan
wuauclt /detectnow

# UsoClient StartDownload         # Begin downloading available updates
# UsoClient StartInstall          # Install downloaded updates
# UsoClient ScanInstallWait       # Full flow: scan + download + install


# PSWindowsUpdate method
<# 
 Get-WindowsUpdate -MicrosoftUpdate
#>

# COM method
<# 
 $UpdateSession = New-Object -ComObject Microsoft.Update.Session
 $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
 $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
 $SearchResult.Updates | Select-Object Title, IsDownloaded, IsInstalled
#>

Stop-Transcript
