# Add 33 HKCU App Permission keys to RegistryChanges-Definition.ps1

$permissions = @(
    "userNotificationListener",
    "userAccountInformation",
    "contacts",
    "appointments",
    "email",
    "phoneCall",
    "phoneCallHistory",
    "chat",
    "userDataTasks",
    "radios",
    "bluetoothSync",
    "documentsLibrary",
    "picturesLibrary",
    "videosLibrary",
    "broadFileSystemAccess",
    "musicLibrary",
    "downloadsFolder",
    "automaticFileDownloads",
    "activity",
    "bluetooth",
    "cellularData",
    "gazeInput",
    "graphicsCaptureProgrammatic",
    "graphicsCaptureWithoutBorder",
    "humanInterfaceDevice",
    "passkeys",
    "passkeysEnumeration",
    "sensors.custom",
    "serialCommunication",
    "systemAIModels",
    "usb",
    "wifiData",
    "wiFiDirect"
)

$descriptions = @{
    "userNotificationListener" = "Apps: Notifications OFF (HKCU)"
    "userAccountInformation" = "Apps: Account Info OFF (HKCU)"
    "contacts" = "Apps: Contacts OFF (HKCU)"
    "appointments" = "Apps: Calendar OFF (HKCU)"
    "email" = "Apps: Email OFF (HKCU)"
    "phoneCall" = "Apps: Phone Calls OFF (HKCU)"
    "phoneCallHistory" = "Apps: Call History OFF (HKCU)"
    "chat" = "Apps: Messaging/SMS OFF (HKCU)"
    "userDataTasks" = "Apps: Tasks OFF (HKCU)"
    "radios" = "Apps: Radios Control OFF (HKCU)"
    "bluetoothSync" = "Apps: Other Devices OFF (HKCU)"
    "documentsLibrary" = "Apps: Documents Library OFF (HKCU)"
    "picturesLibrary" = "Apps: Pictures Library OFF (HKCU)"
    "videosLibrary" = "Apps: Videos Library OFF (HKCU)"
    "broadFileSystemAccess" = "Apps: File System Access OFF (HKCU)"
    "musicLibrary" = "Apps: Music Library OFF (HKCU)"
    "downloadsFolder" = "Apps: Downloads Folder OFF (HKCU)"
    "automaticFileDownloads" = "Apps: Automatic File Downloads OFF (HKCU)"
    "activity" = "Apps: Activity History OFF (HKCU)"
    "bluetooth" = "Apps: Bluetooth OFF (HKCU)"
    "cellularData" = "Apps: Cellular Data OFF (HKCU)"
    "gazeInput" = "Apps: Gaze Input/Eye Tracking OFF (HKCU)"
    "graphicsCaptureProgrammatic" = "Apps: Graphics Capture Programmatic OFF (HKCU)"
    "graphicsCaptureWithoutBorder" = "Apps: Graphics Capture Without Border OFF (HKCU)"
    "humanInterfaceDevice" = "Apps: Human Interface Device OFF (HKCU)"
    "passkeys" = "Apps: Passkeys OFF (HKCU)"
    "passkeysEnumeration" = "Apps: Passkeys Enumeration OFF (HKCU)"
    "sensors.custom" = "Apps: Custom Sensors OFF (HKCU)"
    "serialCommunication" = "Apps: Serial Communication OFF (HKCU)"
    "systemAIModels" = "Apps: System AI Models OFF (HKCU - 25H2)"
    "usb" = "Apps: USB Devices OFF (HKCU)"
    "wifiData" = "Apps: WiFi Data OFF (HKCU)"
    "wiFiDirect" = "Apps: WiFi Direct OFF (HKCU)"
}

# Generate entries
$entries = @()
foreach ($perm in $permissions) {
    $entry = @"
    @{
        Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\$perm'
        Name = 'Value'
        Type = 'String'
        ApplyValue = 'Deny'
        Description = '$($descriptions[$perm])'
        File = 'SecurityBaseline-Telemetry.ps1'
    }
"@
    $entries += $entry
}

# Read file
$file = ".\Modules\RegistryChanges-Definition.ps1"
$content = Get-Content $file -Raw

# Find last entry (before closing )
$insertPoint = $content.LastIndexOf("    }")
if ($insertPoint -eq -1) {
    Write-Host "ERROR: Could not find insertion point!" -ForegroundColor Red
    exit 1
}

# Insert comment and entries
$comment = @"
,
    
    # ===========================
    # HKCU APP PERMISSIONS (USER-SPECIFIC)
    # ===========================
    # These 33 keys are set by SecurityBaseline-Telemetry.ps1 in a loop
    # They control app permissions for the CURRENT USER (HKCU)
    # HKLM keys (above) set defaults for NEW users only
    
"@

$newContent = $content.Substring(0, $insertPoint + 5) + $comment + ($entries -join ",`n    ") + $content.Substring($insertPoint + 5)

# Save
$newContent | Set-Content $file -Encoding UTF8 -NoNewline

Write-Host "✅ Added 33 HKCU App Permission keys!" -ForegroundColor Green
Write-Host "   Location: Before closing )" -ForegroundColor Cyan
