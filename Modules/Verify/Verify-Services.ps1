#Requires -Version 5.1

# Enable Strict Mode
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Verify Services are Disabled

.DESCRIPTION
    Validates that all 37 telemetry and tracking services are disabled.
#>

function Invoke-ServicesChecks {
    <#
    .SYNOPSIS
        Runs all service verification checks
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== SERVICES HARDENING (37 SERVICES DISABLED) ===" -ForegroundColor Yellow
    
    # Telemetry Services
    Test-BaselineCheck -Category "Services" -Name "DiagTrack Service Disabled" -Impact "Critical" `
        -Test { Test-ServiceDisabled "DiagTrack" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "dmwappushservice Disabled" -Impact "Critical" `
        -Test { Test-ServiceDisabled "dmwappushservice" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "RetailDemo Service Disabled" -Impact "High" `
        -Test { Test-ServiceDisabled "RetailDemo" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "WerSvc (Error Reporting) Disabled" -Impact "High" `
        -Test { Test-ServiceDisabled "WerSvc" } `
        -Expected $true
    
    # Remote Services
    Test-BaselineCheck -Category "Services" -Name "RemoteAccess Disabled" -Impact "High" `
        -Test { Test-ServiceDisabled "RemoteAccess" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "RemoteRegistry Disabled" -Impact "Critical" `
        -Test { Test-ServiceDisabled "RemoteRegistry" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "SessionEnv Disabled" -Impact "Medium" `
        -Test { Test-ServiceDisabled "SessionEnv" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "TermService Disabled" -Impact "Medium" `
        -Test { Test-ServiceDisabled "TermService" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "UmRdpService Disabled" -Impact "Medium" `
        -Test { Test-ServiceDisabled "UmRdpService" } `
        -Expected $true
    
    # Sensor & Location Services
    Test-BaselineCheck -Category "Services" -Name "SensrSvc (Sensor) Disabled" -Impact "High" `
        -Test { Test-ServiceDisabled "SensrSvc" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "lfsvc (Geolocation) Disabled" -Impact "Critical" `
        -Test { Test-ServiceDisabled "lfsvc" } `
        -Expected $true
    
    # Xbox Services
    Test-BaselineCheck -Category "Services" -Name "XblAuthManager Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "XblAuthManager" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "XblGameSave Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "XblGameSave" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "XboxGipSvc Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "XboxGipSvc" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "XboxNetApiSvc Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "XboxNetApiSvc" } `
        -Expected $true
    
    # Biometric Services
    Test-BaselineCheck -Category "Services" -Name "WbioSrvc (Biometrics) Disabled" -Impact "Medium" `
        -Test { Test-ServiceDisabled "WbioSrvc" } `
        -Expected $true
    
    # Downloaded Maps Manager
    Test-BaselineCheck -Category "Services" -Name "MapsBroker Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "MapsBroker" } `
        -Expected $true
    
    # Phone Link
    Test-BaselineCheck -Category "Services" -Name "PhoneSvc Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "PhoneSvc" } `
        -Expected $true
    
    # Sync Host
    Test-BaselineCheck -Category "Services" -Name "OneSyncSvc Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "OneSyncSvc" } `
        -Expected $true
    
    # Diagnostics
    Test-BaselineCheck -Category "Services" -Name "DPS (Diagnostic Policy) Disabled" -Impact "Medium" `
        -Test { Test-ServiceDisabled "DPS" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "WdiServiceHost Disabled" -Impact "Medium" `
        -Test { Test-ServiceDisabled "WdiServiceHost" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "WdiSystemHost Disabled" -Impact "Medium" `
        -Test { Test-ServiceDisabled "WdiSystemHost" } `
        -Expected $true
    
    # WAP Push
    Test-BaselineCheck -Category "Services" -Name "dmwappushsvc Disabled" -Impact "High" `
        -Test { Test-ServiceDisabled "dmwappushsvc" } `
        -Expected $true
    
    # Messaging
    Test-BaselineCheck -Category "Services" -Name "MessagingService Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "MessagingService" } `
        -Expected $true
    
    # Clipboard
    Test-BaselineCheck -Category "Services" -Name "cbdhsvc (Clipboard Sync) Disabled" -Impact "Medium" `
        -Test { Test-ServiceDisabled "cbdhsvc" } `
        -Expected $true
    
    # Insider Program
    Test-BaselineCheck -Category "Services" -Name "wisvc (Windows Insider) Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "wisvc" } `
        -Expected $true
    
    # Wi-Fi Sense
    Test-BaselineCheck -Category "Services" -Name "wcncsvc (Wi-Fi Sense) Disabled" -Impact "Medium" `
        -Test { Test-ServiceDisabled "wcncsvc" } `
        -Expected $true
    
    # Shared Experience
    Test-BaselineCheck -Category "Services" -Name "CDPUserSvc (Connected Devices) Disabled" -Impact "Medium" `
        -Test { Test-ServiceDisabled "CDPUserSvc" } `
        -Expected $true
    
    # App Readiness
    Test-BaselineCheck -Category "Services" -Name "AppReadiness Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "AppReadiness" } `
        -Expected $true
    
    # Parental Controls
    Test-BaselineCheck -Category "Services" -Name "WpcMonSvc (Parental Controls) Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "WpcMonSvc" } `
        -Expected $true
    
    # Bluetooth
    Test-BaselineCheck -Category "Services" -Name "BTAGService (Bluetooth Audio) Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "BTAGService" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Services" -Name "bthserv (Bluetooth Support) Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "bthserv" } `
        -Expected $true
    
    # NFC
    Test-BaselineCheck -Category "Services" -Name "SEMgrSvc (NFC/Secure Element) Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "SEMgrSvc" } `
        -Expected $true
    
    # Miracast/Wireless Display
    Test-BaselineCheck -Category "Services" -Name "WFDSConMgrSvc (Wireless Display) Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "WFDSConMgrSvc" } `
        -Expected $true
    
    # Push Notifications
    Test-BaselineCheck -Category "Services" -Name "WpnService (Push Notifications) Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "WpnService" } `
        -Expected $true
    
    # Payments
    Test-BaselineCheck -Category "Services" -Name "WalletService Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "WalletService" } `
        -Expected $true
    
    # Fax
    Test-BaselineCheck -Category "Services" -Name "Fax Service Disabled" -Impact "Low" `
        -Test { Test-ServiceDisabled "Fax" } `
        -Expected $true
}
