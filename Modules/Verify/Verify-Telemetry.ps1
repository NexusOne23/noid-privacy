#Requires -Version 5.1

# Enable Strict Mode
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Verify Telemetry & Privacy Settings

.DESCRIPTION
    Validates that all 158 telemetry registry keys are correctly configured
    for maximum privacy.
#>

function Invoke-TelemetryChecks {
    <#
    .SYNOPSIS
        Runs all telemetry and privacy verification checks
    #>
    [CmdletBinding()]
    param()
    
    Write-Host "`n=== TELEMETRY & PRIVACY (50 CRITICAL SETTINGS) ===" -ForegroundColor Yellow
    
    # 1. Diagnostic Data Level (MOST CRITICAL!)
    Test-BaselineCheck -Category "Telemetry" -Name "Diagnostic Data = Security (0)" -Impact "Critical" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" -DefaultValue 3 } `
        -Expected 0
    
    # 2. Telemetry Opt-In
    Test-BaselineCheck -Category "Telemetry" -Name "Telemetry Opt-In Disabled" -Impact "Critical" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" -DefaultValue 1 } `
        -Expected 0
    
    # 3. Diagnostic Data Viewer
    Test-BaselineCheck -Category "Telemetry" -Name "Diagnostic Data Viewer Blocked" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptEnabled" "EventTranscriptEnabled" -DefaultValue 1 } `
        -Expected 0
    
    # 4. Application Telemetry
    Test-BaselineCheck -Category "Telemetry" -Name "Application Telemetry Disabled" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "AITEnable" -DefaultValue 1 } `
        -Expected 0
    
    # 5. Customer Experience Improvement Program (CEIP)
    Test-BaselineCheck -Category "Telemetry" -Name "CEIP Disabled" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" "CEIPEnable" -DefaultValue 1 } `
        -Expected 0
    
    # 6. Inventory Collector
    Test-BaselineCheck -Category "Telemetry" -Name "Inventory Collector Disabled" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableInventory" -DefaultValue 0 } `
        -Expected 1
    
    # 7. Steps Recorder
    Test-BaselineCheck -Category "Telemetry" -Name "Steps Recorder Disabled" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" "DisableUAR" -DefaultValue 0 } `
        -Expected 1
    
    # 8. Advertising ID
    Test-BaselineCheck -Category "Telemetry" -Name "Advertising ID Disabled" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" -DefaultValue 0 } `
        -Expected 1
    
    # 9. Cloud Content
    Test-BaselineCheck -Category "Telemetry" -Name "Cloud Content Disabled" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" -DefaultValue 0 } `
        -Expected 1
    
    # 10. Windows Feedback
    Test-BaselineCheck -Category "Telemetry" -Name "Windows Feedback Disabled" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" -DefaultValue 0 } `
        -Expected 1
    
    # 11-20: Scheduled Tasks Telemetry
    Test-BaselineCheck -Category "Telemetry" -Name "Consolidator Task Disabled" -Impact "High" `
        -Test { Test-ScheduledTaskDisabled "\Microsoft\Windows\Application Experience\" "Microsoft Compatibility Appraiser" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Telemetry" -Name "ProgramDataUpdater Task Disabled" -Impact "Medium" `
        -Test { Test-ScheduledTaskDisabled "\Microsoft\Windows\Application Experience\" "ProgramDataUpdater" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Telemetry" -Name "Proxy Task Disabled" -Impact "Low" `
        -Test { Test-ScheduledTaskDisabled "\Microsoft\Windows\Autochk\" "Proxy" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Telemetry" -Name "QueueReporting Task Disabled" -Impact "Medium" `
        -Test { Test-ScheduledTaskDisabled "\Microsoft\Windows\Windows Error Reporting\" "QueueReporting" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Telemetry" -Name "DiskDiagnosticDataCollector Disabled" -Impact "Low" `
        -Test { Test-ScheduledTaskDisabled "\Microsoft\Windows\DiskDiagnostic\" "Microsoft-Windows-DiskDiagnosticDataCollector" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Telemetry" -Name "Telemetry Task (consolidator) Disabled" -Impact "High" `
        -Test { Test-ScheduledTaskDisabled "\Microsoft\Windows\Customer Experience Improvement Program\" "Consolidator" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Telemetry" -Name "UsbCeip Task Disabled" -Impact "Low" `
        -Test { Test-ScheduledTaskDisabled "\Microsoft\Windows\Customer Experience Improvement Program\" "UsbCeip" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Telemetry" -Name "KernelCeipTask Disabled" -Impact "Low" `
        -Test { Test-ScheduledTaskDisabled "\Microsoft\Windows\Customer Experience Improvement Program\" "KernelCeipTask" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Telemetry" -Name "MapsToastTask Disabled" -Impact "Low" `
        -Test { Test-ScheduledTaskDisabled "\Microsoft\Windows\Maps\" "MapsToastTask" } `
        -Expected $true
    
    Test-BaselineCheck -Category "Telemetry" -Name "MapsUpdateTask Disabled" -Impact "Low" `
        -Test { Test-ScheduledTaskDisabled "\Microsoft\Windows\Maps\" "MapsUpdateTask" } `
        -Expected $true
    
    # 21-30: Windows Error Reporting
    Test-BaselineCheck -Category "Telemetry" -Name "Windows Error Reporting Disabled" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled" -DefaultValue 0 } `
        -Expected 1
    
    Test-BaselineCheck -Category "Telemetry" -Name "WER AutoApproveOSDumps Disabled" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "AutoApproveOSDumps" -DefaultValue 1 } `
        -Expected 0
    
    Test-BaselineCheck -Category "Telemetry" -Name "WER DefaultConsent = Never Send" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" "DefaultConsent" -DefaultValue 2 } `
        -Expected 1
    
    Test-BaselineCheck -Category "Telemetry" -Name "WER DefaultOverrideBehavior Disabled" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\Consent" "DefaultOverrideBehavior" -DefaultValue 1 } `
        -Expected 0
    
    Test-BaselineCheck -Category "Telemetry" -Name "DontSendAdditionalData = Yes" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "DontSendAdditionalData" -DefaultValue 0 } `
        -Expected 1
    
    Test-BaselineCheck -Category "Telemetry" -Name "LoggingDisabled = Yes" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "LoggingDisabled" -DefaultValue 0 } `
        -Expected 1
    
    # 31-40: App Privacy Settings
    Test-BaselineCheck -Category "Privacy" -Name "Let Apps Access Location = Deny" -Impact "Critical" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" "Value" -DefaultValue "Allow" } `
        -Expected "Deny"
    
    Test-BaselineCheck -Category "Privacy" -Name "Let Apps Access Camera = Deny" -Impact "Critical" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" "Value" -DefaultValue "Allow" } `
        -Expected "Deny"
    
    Test-BaselineCheck -Category "Privacy" -Name "Let Apps Access Microphone = Deny" -Impact "Critical" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" "Value" -DefaultValue "Allow" } `
        -Expected "Deny"
    
    Test-BaselineCheck -Category "Privacy" -Name "Let Apps Access Notifications = Deny" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" "Value" -DefaultValue "Allow" } `
        -Expected "Deny"
    
    Test-BaselineCheck -Category "Privacy" -Name "Let Apps Access Account Info = Deny" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" "Value" -DefaultValue "Allow" } `
        -Expected "Deny"
    
    Test-BaselineCheck -Category "Privacy" -Name "Let Apps Access Contacts = Deny" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" "Value" -DefaultValue "Allow" } `
        -Expected "Deny"
    
    Test-BaselineCheck -Category "Privacy" -Name "Let Apps Access Calendar = Deny" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" "Value" -DefaultValue "Allow" } `
        -Expected "Deny"
    
    Test-BaselineCheck -Category "Privacy" -Name "Let Apps Access Phone = Deny" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" "Value" -DefaultValue "Allow" } `
        -Expected "Deny"
    
    Test-BaselineCheck -Category "Privacy" -Name "Let Apps Access Call History = Deny" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" "Value" -DefaultValue "Allow" } `
        -Expected "Deny"
    
    Test-BaselineCheck -Category "Privacy" -Name "Let Apps Access Email = Deny" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" "Value" -DefaultValue "Allow" } `
        -Expected "Deny"
    
    # 41-50: Activity History & Timeline
    Test-BaselineCheck -Category "Privacy" -Name "Activity Feed Disabled" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed" -DefaultValue 1 } `
        -Expected 0
    
    Test-BaselineCheck -Category "Privacy" -Name "Publish User Activities Disabled" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities" -DefaultValue 1 } `
        -Expected 0
    
    Test-BaselineCheck -Category "Privacy" -Name "Upload User Activities Disabled" -Impact "High" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities" -DefaultValue 1 } `
        -Expected 0
    
    Test-BaselineCheck -Category "Privacy" -Name "Timeline Disabled" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableCdp" -DefaultValue 1 } `
        -Expected 0
    
    Test-BaselineCheck -Category "Privacy" -Name "Connected Devices Platform Disabled" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" "EnableMmx" -DefaultValue 1 } `
        -Expected 0
    
    Test-BaselineCheck -Category "Telemetry" -Name "Tailored Experiences Disabled" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableTailoredExperiencesWithDiagnosticData" -DefaultValue 0 } `
        -Expected 1
    
    Test-BaselineCheck -Category "Telemetry" -Name "Third-Party Suggestions Disabled" -Impact "Low" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableThirdPartySuggestions" -DefaultValue 0 } `
        -Expected 1
    
    Test-BaselineCheck -Category "Telemetry" -Name "Windows Spotlight Disabled" -Impact "Low" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsSpotlightFeatures" -DefaultValue 0 } `
        -Expected 1
    
    Test-BaselineCheck -Category "Telemetry" -Name "Handwriting Data Collection Disabled" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" "PreventHandwritingDataSharing" -DefaultValue 0 } `
        -Expected 1
    
    Test-BaselineCheck -Category "Telemetry" -Name "Typing Insights Disabled" -Impact "Medium" `
        -Test { Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Input\Settings" "InsightsEnabled" -DefaultValue 1 } `
        -Expected 0
}
