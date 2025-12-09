# NonInteractive Mode - CI/CD & Automation Guide

## Overview

NoID Privacy supports fully automated, non-interactive execution for CI/CD pipelines, group policy deployment, and mass system hardening. This guide explains how to run the framework without any interactive prompts.

---

## Configuration-Based Execution

The framework automatically enters non-interactive mode when all required parameters are pre-configured in `config.json`.

### Required Configuration Keys

#### **1. DNS Module - Provider Selection**

```json
{
  "modules": {
    "DNS": {
      "enabled": true,
      "priority": 3,
      "status": "IMPLEMENTED",
      "description": "Secure DNS with DoH",
      "provider": "Quad9"
    }
  }
}
```

**Valid provider values:**
- `"Quad9"` (default, security-focused, Swiss privacy)
- `"Cloudflare"` (fastest resolver)
- `"AdGuard"` (ad/tracker blocking)

**When provider is set:**
- No interactive DNS provider selection prompt
- Direct application of specified provider

---

#### **2. Privacy Module - Mode Selection**

```json
{
  "modules": {
    "Privacy": {
      "enabled": true,
      "priority": 4,
      "status": "IMPLEMENTED",
      "description": "Privacy hardening",
      "mode": "MSRecommended"
    }
  }
}
```

**Valid mode values:**
- `"MSRecommended"` (default, fully supported, production-ready)
- `"Strict"` (maximum privacy, Teams/Zoom work)
- `"Paranoid"` (hardcore, not recommended for production)

**When mode is set:**
- No interactive privacy mode selection prompt
- Direct application of specified mode with warnings logged

---

#### **3. Global Options - Automation Settings**

```json
{
  "options": {
    "dryRun": false,
    "createBackup": true,
    "verboseLogging": false,
    "autoReboot": false,
    "nonInteractive": true
  }
}
```

**Key options:**
- `nonInteractive`: Explicitly disable all prompts (optional, auto-detected)
- `autoReboot`: Automatically restart after hardening (use with caution)
- `createBackup`: Always create backups (highly recommended)

---

## Command-Line Execution

### **Basic Non-Interactive Execution**

```powershell
# Run all enabled modules from config.json
.\NoIDPrivacy.ps1 -Module All

# Run specific module with provider pre-configured
.\NoIDPrivacy.ps1 -Module DNS

# Run with command-line overrides
.\NoIDPrivacy.ps1 -Module Privacy -DryRun

# Run in verbose mode for logging
.\NoIDPrivacy.ps1 -Module All -VerboseLogging
```

---

### **CI/CD Pipeline Example**

#### **Azure DevOps Pipeline**

```yaml
steps:
  - task: PowerShell@2
    displayName: 'NoID Privacy Hardening'
    inputs:
      targetType: 'filePath'
      filePath: '$(System.DefaultWorkingDirectory)/NoIDPrivacy.ps1'
      arguments: '-Module All -VerboseLogging'
      errorActionPreference: 'stop'
      pwsh: false
    condition: succeededOrFailed()
    
  - task: PublishBuildArtifacts@1
    displayName: 'Publish Hardening Logs'
    inputs:
      PathtoPublish: 'Logs'
      ArtifactName: 'hardening-logs'
```

#### **GitHub Actions Workflow**

```yaml
name: Windows Hardening

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:

jobs:
  harden:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run NoID Privacy
        shell: powershell
        run: |
          .\NoIDPrivacy.ps1 -Module All -VerboseLogging
        
      - name: Upload Logs
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: hardening-logs
          path: Logs/
```

#### **Jenkins Pipeline**

```groovy
pipeline {
    agent { label 'windows' }
    
    stages {
        stage('Hardening') {
            steps {
                powershell '''
                    Set-ExecutionPolicy Bypass -Scope Process -Force
                    .\\NoIDPrivacy.ps1 -Module All -VerboseLogging
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'Logs/**/*', fingerprint: true
        }
    }
}
```

---

## Group Policy Deployment

### **Method 1: Startup Script**

1. Copy NoID Privacy to network share:
   ```
   \\domain.local\NETLOGON\NoIDPrivacy\
   ```

2. Create GPO startup script:
   ```powershell
   # Startup-Hardening.ps1
   $scriptPath = "\\domain.local\NETLOGON\NoIDPrivacy\NoIDPrivacy.ps1"
   
   if (Test-Path $scriptPath) {
       & $scriptPath -Module All -VerboseLogging
   }
   ```

3. Link GPO to target OU
4. Result logged to: `C:\NoIDPrivacy\Logs\`

---

### **Method 2: Scheduled Task (Recommended)**

Deploy via GPO Scheduled Task:

```xml
<!-- Task XML for GPO deployment -->
<Task>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2025-01-01T03:00:00</StartBoundary>
      <ScheduleByWeek>
        <DaysOfWeek><Sunday /></DaysOfWeek>
        <WeeksInterval>1</WeeksInterval>
      </ScheduleByWeek>
    </CalendarTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -File "\\domain.local\NETLOGON\NoIDPrivacy\NoIDPrivacy.ps1" -Module All</Arguments>
    </Exec>
  </Actions>
</Task>
```

---

## Verification Without Interaction

### **Silent Verification**

```powershell
# Run verification and export structured JSON
.\Tools\Verify-Complete-Hardening.ps1 -ExportPath "verification-result.json"

# Parse results programmatically
$verification = Get-Content "verification-result.json" | ConvertFrom-Json

if ($verification.Failed -eq 0) {
    Write-Output "All settings verified successfully"
    exit 0
} else {
    Write-Error "Verification failed: $($verification.Failed) settings did not match expected values"
    exit 1
}
```

---

## Environment Variables (Alternative)

Instead of modifying `config.json`, use environment variables:

```powershell
# Set environment variables
$env:NOIDPRIVACY_DNS_PROVIDER = "Quad9"
$env:NOIDPRIVACY_PRIVACY_MODE = "MSRecommended"
$env:NOIDPRIVACY_NONINTERACTIVE = "true"

# Run framework
.\NoIDPrivacy.ps1 -Module All
```

**Note:** Environment variables require framework support and are currently a roadmap feature (not yet implemented).

---

## Return Codes

**Note:** Exit codes are currently not implemented. Error handling should be done via try/catch blocks and checking the log files.

### **Example: Error Handling in Scripts**

```powershell
try {
    .\NoIDPrivacy.ps1 -Module All -ErrorAction Stop
    Write-Output "Hardening completed successfully"
}
catch {
    Write-Error "Hardening failed: $_"
    # Check logs for details
    $latestLog = Get-ChildItem "Logs" -Filter "NoIDPrivacy-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Get-Content $latestLog.FullName | Select-String "ERROR"
    exit 1
}
```

---

## Best Practices for Automation

### **1. Always Use DryRun First**

```powershell
# Test configuration without applying
.\NoIDPrivacy.ps1 -Module All -DryRun -VerboseLogging

# Review logs before production run
Get-Content "Logs\NoIDPrivacy-*.log" | Select-String "ERROR|WARNING"
```

---

### **2. Centralized Logging**

Configure log aggregation for enterprise deployment:

```powershell
# Example: Copy logs to central location
$logPath = "C:\NoIDPrivacy\Logs"
$centralPath = "\\fileserver\HardeningLogs\$env:COMPUTERNAME"

if (Test-Path $logPath) {
    Copy-Item -Path "$logPath\*" -Destination $centralPath -Recurse -Force
}
```

---

### **3. Rollback Plan**

Always maintain rollback capability:

```powershell
# Before mass deployment, test rollback
.\NoIDPrivacy.ps1 -Module DNS

# Restore from latest backup (uses Core\Rollback.ps1)
.\Core\Rollback.ps1 -RestoreLatest

# Or restore specific module
.\Modules\DNS\Public\Restore-DNSSettings.ps1

# Verify rollback worked
.\Tools\Verify-Complete-Hardening.ps1
```

---

## Troubleshooting Non-Interactive Mode

### **Issue: Still Showing Prompts**

**Cause:** Provider/mode not configured in `config.json`

**Solution:**
```json
{
  "modules": {
    "DNS": { "provider": "Quad9" },
    "Privacy": { "mode": "MSRecommended" }
  }
}
```

---

### **Issue: Script Fails Silently**

**Cause:** Error suppression in CI/CD

**Solution:**
```powershell
# Use verbose logging + error action
.\NoIDPrivacy.ps1 -Module All -VerboseLogging -ErrorAction Stop
```

---

### **Issue: Insufficient Permissions**

**Cause:** Not running as Administrator

**Solution:**
```powershell
# For scheduled tasks, use SYSTEM account or admin user
# For GPO, startup scripts run as SYSTEM automatically
```

---

## Complete Example: Enterprise Deployment Script

```powershell
<#
.SYNOPSIS
    Enterprise deployment wrapper for NoID Privacy
    
.DESCRIPTION
    Automated hardening with centralized logging and email reporting
#>

param(
    [switch]$DryRun,
    [string]$EmailRecipient = "security@company.com"
)

$ErrorActionPreference = "Stop"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

try {
    # Pre-flight checks
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Must run as Administrator"
    }
    
    # Run hardening
    Write-Output "Starting NoID Privacy hardening..."
    $result = & "$scriptRoot\NoIDPrivacy.ps1" -Module All -DryRun:$DryRun -VerboseLogging
    
    # Collect logs
    $logPath = "$scriptRoot\Logs"
    $latestLog = Get-ChildItem $logPath -Filter "NoIDPrivacy-*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    
    # Send report email
    $emailBody = @"
NoID Privacy Hardening Report

Computer: $env:COMPUTERNAME
Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Mode: $(if($DryRun){"DRY RUN"}else{"APPLY"})

Log file attached.
"@
    
    Send-MailMessage -To $EmailRecipient `
                     -From "hardening@company.com" `
                     -Subject "Hardening Report - $env:COMPUTERNAME" `
                     -Body $emailBody `
                     -Attachments $latestLog.FullName `
                     -SmtpServer "smtp.company.com"
    
    Write-Output "Hardening completed successfully"
    exit 0
}
catch {
    Write-Error "Hardening failed: $_"
    exit 1
}
```

---

## Summary

**For non-interactive execution:**

1. ✅ Configure `provider` and `mode` in `config.json`
2. ✅ Use `-Module All` parameter
3. ✅ Enable `-VerboseLogging` for CI/CD
4. ✅ Always test with `-DryRun` first
5. ✅ Implement centralized logging
6. ✅ Plan rollback procedures

**The framework is fully automation-ready when configured correctly!**
