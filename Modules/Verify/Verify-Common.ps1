#Requires -Version 5.1

# Enable Strict Mode
Set-StrictMode -Version Latest

<#
.SYNOPSIS
    Common helper functions for all Verify modules

.DESCRIPTION
    Shared Test-BaselineCheck function and utilities used across all verify modules.
#>

# Initialize results array if not exists (defensive programming)
if (-not (Test-Path Variable:\script:results)) {
    $script:results = @()
}

function Test-BaselineCheck {
    <#
    .SYNOPSIS
        Tests a security baseline check and records the result
        
    .PARAMETER Category
        Category of the check (e.g., "Defender", "ASR", "Telemetry")
        
    .PARAMETER Name
        Name of the check
        
    .PARAMETER Test
        ScriptBlock that performs the test
        
    .PARAMETER Expected
        Expected value or validation ScriptBlock
        
    .PARAMETER Impact
        Impact level: Critical, High, Medium, Low
    #>
    param(
        [string]$Category,
        [string]$Name,
        [scriptblock]$Test,
        $Expected,
        [string]$Impact = "Medium"
    )
    
    $errorMessage = $null
    
    try {
        $actual = & $Test
        $passed = if ($Expected -is [scriptblock]) { & $Expected $actual } else { $actual -eq $Expected }
        
        $result = [PSCustomObject]@{
            Category = $Category
            Check = $Name
            Expected = $Expected
            Actual = $actual
            Status = if ($passed) { "PASS" } else { "FAIL" }
            Impact = $Impact
            ErrorMessage = $null
        }
    }
    catch {
        $result = [PSCustomObject]@{
            Category = $Category
            Check = $Name
            Expected = $Expected
            Actual = $null
            Status = "ERROR"
            Impact = $Impact
            ErrorMessage = $_.Exception.Message
        }
    }
    
    $script:results += $result
    
    # Display result
    $statusColor = switch ($result.Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "ERROR" { "Yellow" }
    }
    
    $statusSymbol = switch ($result.Status) {
        "PASS" { "[OK]" }
        "FAIL" { "[X]" }
        "ERROR" { "[!]" }
    }
    
    Write-Host "  $statusSymbol $Name" -ForegroundColor $statusColor
    
    if ($result.Status -eq "FAIL") {
        Write-Host "      Expected: $Expected, Got: $($result.Actual)" -ForegroundColor Gray
    }
    
    if ($result.Status -eq "ERROR") {
        Write-Host "      Error: $($result.ErrorMessage)" -ForegroundColor Gray
    }
}

function Get-RegistryValue {
    <#
    .SYNOPSIS
        Safely gets a registry value
        
    .PARAMETER Path
        Registry path
        
    .PARAMETER Name
        Value name
        
    .PARAMETER DefaultValue
        Default value if not found
    #>
    param(
        [string]$Path,
        [string]$Name,
        $DefaultValue = $null
    )
    
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($item) {
            return $item.$Name
        }
    }
    catch {
        # Silently return default
    }
    
    return $DefaultValue
}

function Test-RegistryValue {
    <#
    .SYNOPSIS
        Tests if a registry value exists and matches expected value
        
    .PARAMETER Path
        Registry path
        
    .PARAMETER Name
        Value name
        
    .PARAMETER ExpectedValue
        Expected value
    #>
    param(
        [string]$Path,
        [string]$Name,
        $ExpectedValue
    )
    
    $actual = Get-RegistryValue -Path $Path -Name $Name
    return ($actual -eq $ExpectedValue)
}

function Test-ServiceDisabled {
    <#
    .SYNOPSIS
        Tests if a service is disabled
        
    .PARAMETER ServiceName
        Name of the service
    #>
    param(
        [string]$ServiceName
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            return ($service.StartType -eq 'Disabled')
        }
        # If service doesn't exist, consider it "disabled"
        return $true
    }
    catch {
        return $true
    }
}

function Test-ScheduledTaskDisabled {
    <#
    .SYNOPSIS
        Tests if a scheduled task is disabled
        
    .PARAMETER TaskPath
        Path of the task
        
    .PARAMETER TaskName
        Name of the task
    #>
    param(
        [string]$TaskPath,
        [string]$TaskName
    )
    
    try {
        $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
        if ($task) {
            return ($task.State -eq 'Disabled')
        }
        # If task doesn't exist, consider it "disabled"
        return $true
    }
    catch {
        return $true
    }
}

function Test-AppNotInstalled {
    <#
    .SYNOPSIS
        Tests if a Windows app is not installed
        
    .PARAMETER AppName
        Name pattern of the app
    #>
    param(
        [string]$AppName
    )
    
    try {
        $app = Get-AppxPackage -Name $AppName -ErrorAction SilentlyContinue
        # Return true if app is NOT found (i.e., successfully removed)
        return ($null -eq $app)
    }
    catch {
        return $true
    }
}
