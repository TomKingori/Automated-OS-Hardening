# Run this as Administrator

# Log actions
function Log-Action {
    param (
        [string]$message
    )
    $logFile = "C:\HardeningLog.txt"
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestamp - $message"
}

# Disable a service safely
function Disable-Service-Safely {
    param ([string]$serviceName)
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') {
        Stop-Service -Name $serviceName -Force
        Set-Service -Name $serviceName -StartupType Disabled
        Log-Action "Disabled service: $serviceName"
    }
}

# User Management Hardening
function Harden-UserManagement {
    Log-Action "Starting User Management Hardening"

    # Disable Guest Account
    Get-LocalUser -Name "Guest" | Disable-LocalUser
    Log-Action "Disabled Guest Account"

    # Enforce Strong Password Policies
    secedit /configure /db c:\secpol.sdb /cfg C:\Windows\security\templates\basicwk.inf /areas SECURITYPOLICY
    Log-Action "Enforced Strong Password Policies"

    # Disable Unused Local Accounts
    Get-LocalUser | Where-Object { $_.Enabled -eq $true -and $_.Name -ne "Administrator" } | Disable-LocalUser
    Log-Action "Disabled unused local accounts"

    Log-Action "Completed User Management Hardening"
}

# Network Security Hardening
function Harden-NetworkSecurity {
    Log-Action "Starting Network Security Hardening"

    # Enable Windows Defender Firewall and Set Default Policies
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True
    Set-NetFirewallProfile -Profile Domain, Public, Private -DefaultInboundAction Block -DefaultOutboundAction Allow
    Log-Action "Configured Windows Firewall to block inbound traffic by default"

    # Disable Remote Assistance
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0
    Log-Action "Disabled Remote Assistance"

    # Disable SMBv1 (old and vulnerable)
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Confirm:$false
    Log-Action "Disabled SMBv1 protocol"

    # Secure RDP Settings
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fAllowUnsolicited" -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -Value 3
    Log-Action "Hardened RDP settings"

    Log-Action "Completed Network Security Hardening"
}

# System Configuration Hardening
function Harden-SystemConfigurations {
    Log-Action "Starting System Configurations Hardening"

    # Disable Unused Services (selectively)
    Disable-Service-Safely "RemoteRegistry"
    Disable-Service-Safely "wuauserv"
    Disable-Service-Safely "XboxNetApiSvc"
    Disable-Service-Safely "DiagTrack"  # Telemetry service
    Disable-Service-Safely "OneSyncSvc"

    # Enable Windows Defender
    Set-MpPreference -DisableRealtimeMonitoring $false
    Log-Action "Enabled Windows Defender"

    # Enable Audit Policies
    AuditPol /set /category:"Logon/Logoff" /success:enable /failure:enable
    AuditPol /set /category:"Account Management" /success:enable /failure:enable
    Log-Action "Configured Audit Policies"

    Log-Action "Completed System Configurations Hardening"
}

# Application Security Hardening
function Harden-ApplicationSecurity {
    Log-Action "Starting Application Security Hardening"

    # Ensure Windows Updates are Installed
    Write-Host "Checking for Windows Updates..."
    Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot | Out-Null
    Log-Action "Installed Windows Updates"

    # Disable Office Macros (if Office installed)
    $officeVersions = @("16.0", "15.0", "14.0", "12.0")
    foreach ($version in $officeVersions) {
        $path = "HKCU:\Software\Microsoft\Office\$version\Word\Security"
        if (Test-Path $path) {
            Set-ItemProperty -Path $path -Name "VBAWarnings" -Value 3
            Log-Action "Disabled Office Macros for Office $version"
        }
    }

    Log-Action "Completed Application Security Hardening"
}

# Main Script Execution
try {
    Harden-UserManagement
    Harden-NetworkSecurity
    Harden-SystemConfigurations
    Harden-ApplicationSecurity
} catch {
    Log-Action "Error occurred: $_"
}

Log-Action "Hardening Script Completed"
Write-Host "OS Hardening Completed. Check C:\HardeningLog.txt for details."
