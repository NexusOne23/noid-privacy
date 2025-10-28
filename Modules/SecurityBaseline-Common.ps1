# =======================================================================================
# SecurityBaseline-Common.ps1 - Common Helper Functions
# =======================================================================================

<#
.SYNOPSIS
    Common helper functions for all SecurityBaseline modules
.DESCRIPTION
    Centralizes code duplication of logging/output functions.
    Best Practice 25H2: DRY (Don't Repeat Yourself)
#>

# Best Practice 25H2: Enable Strict Mode
Set-StrictMode -Version Latest

function Write-Section {
    <#
    .SYNOPSIS
        Writes a section header
    .PARAMETER Text
        Header-Text
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Info {
    <#
    .SYNOPSIS
        Writes an info message
    .PARAMETER Message
        Info-Text
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[i] $Message" -ForegroundColor Cyan
}

function Write-Success {
    <#
    .SYNOPSIS
        Writes a success message
    .PARAMETER Message
        Success-Text
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warning-Custom {
    <#
    .SYNOPSIS
        Writes a custom warning (not Write-Warning because that's too verbose)
    .PARAMETER Message
        Warning-Text
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Write-Error-Custom {
    <#
    .SYNOPSIS
        Writes a custom error message (not Write-Error because that's too disruptive)
    .PARAMETER Message
        Error-Text
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    Write-Host "[X] $Message" -ForegroundColor Red
}

function Set-RegistryValue {
    <#
    .SYNOPSIS
        Sets a registry value with automatic key creation
    .DESCRIPTION
        Helper function that automatically creates missing registry keys.
        Best Practice 25H2: Robust string formatting, error handling
        
        NOTE: For TrustedInstaller-protected keys use Set-RegistryValueSmart
              from the RegistryOwnership module!
    .PARAMETER Path
        Registry path
    .PARAMETER Name
        Value name
    .PARAMETER Value
        Value
    .PARAMETER Type
        Registry type (DWord, String, etc.)
    .PARAMETER Description
        Optional description for logging
    .OUTPUTS
        [bool] $true on success, $false on error
    .EXAMPLE
        Set-RegistryValue -Path "HKLM:\SOFTWARE\Test" -Name "Value" -Value 1 -Type DWord
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [object]$Value,
        
        [Parameter()]
        [Microsoft.Win32.RegistryValueKind]$Type = 'DWord',
        
        [Parameter()]
        [string]$Description
    )
    
    try {
        # Create key if not exists
        if (-not (Test-Path -Path $Path)) {
            Write-Verbose (Get-LocalizedString 'CommonCreatingKey' -f $Path)
            $null = New-Item -Path $Path -Force -ErrorAction Stop
        }
        
        # Check if value exists (SAFE method - no error records!)
        # Get ALL properties first, then check if our property is in the list
        $item = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
        $valueExists = $item -and ($item.PSObject.Properties.Name -contains $Name)
        
        if ($valueExists) {
            # Value exists - Set-ItemProperty (NO -Type parameter in PS 5.1!)
            Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force -ErrorAction Stop
        }
        else {
            # Value does NOT exist - New-ItemProperty (WITH -PropertyType!)
            New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force -ErrorAction Stop | Out-Null
        }
        
        if ($Description) {
            Write-Verbose "     $Description : $Name = $Value"
        }
        else {
            Write-Verbose (Get-LocalizedString 'CommonRegistrySet' -f $Path, $Name, $Value)
        }
        
        return $true
    }
    catch {
        Write-Error-Custom (Get-LocalizedString 'CommonRegistryError' -f $Path, $Name, $_)
        Write-Verbose "Details: $($_.Exception.Message)"
        return $false
    }
}

function Stop-ServiceSafe {
    <#
    .SYNOPSIS
        Stops and disables a service race-condition-free
    .DESCRIPTION
        Best Practice 25H2: Automatic ownership management + rollback condition
        
        PROBLEM (old):
            Stop-Service -> Service stops
            Set-Service -StartupType Disabled
            -> RACE: Service could restart between Stop and SetStartupType!
        
        SOLUTION (new):
            1. Set-Service -StartupType Disabled FIRST (prevents restart)
            2. Stop-Service with -NoWait
            3. Wait until service actually stopped (max. MaxWaitSeconds)
            4. Final check if really Disabled
    .PARAMETER ServiceName
        Service name
    .PARAMETER MaxWaitSeconds
        Maximum wait time in seconds (default: 10)
    .OUTPUTS
        [bool] $true on success, $false on error
    .EXAMPLE
        Stop-ServiceSafe -ServiceName "DiagTrack"
    .EXAMPLE
        Stop-ServiceSafe -ServiceName "WerSvc" -MaxWaitSeconds 5
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ServiceName,
        
        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$MaxWaitSeconds = 10
    )
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Verbose (Get-LocalizedString 'CommonServiceNotFound' -f $ServiceName)
            return $false
        }
        
        Write-Verbose (Get-LocalizedString 'CommonDisablingService' -f $ServiceName, $service.Status)
        
        # === STEP 1: Set StartupType to Disabled FIRST ===
        # CRITICAL: Prevents service from restarting between Stop and SetStartupType
        # Track errors via $Error.Count (reliable!)
        $errorBefore = $Error.Count
        
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
        
        # Check if error occurred via Error.Count
        if ($Error.Count -eq $errorBefore) {
            # No error = Success
            Write-Verbose "     StartupType: Disabled"
        } else {
            # Error = Legacy service not configurable
            Write-Verbose "     $(Get-LocalizedString 'CommonSetServiceFailed')"
            return $false
        }
        
        # === STEP 2: Check if service is running ===
        if ($service.Status -ne "Stopped") {
            # === STEP 3: Stop service ===
            Stop-Service -Name $ServiceName -Force -NoWait -ErrorAction Stop
            Write-Verbose "     Stop-Command sent"
            
            # === STEP 4: Wait until actually stopped ===
            $waited = 0
            do {
                Start-Sleep -Milliseconds 500
                $waited += 0.5
                
                $service = Get-Service -Name $ServiceName
                if ($service.Status -eq "Stopped") {
                    Write-Verbose ("     " + (Get-LocalizedString 'CommonServiceStopped' -f $waited))
                    break
                }
                
                if ($waited -ge $MaxWaitSeconds) {
                    Write-Warning (Get-LocalizedString 'CommonServiceTimeout' -f $ServiceName, $MaxWaitSeconds)
                    Write-Warning "  Status: $($service.Status)"
                    # Not critical - StartupType=Disabled is more important
                    break
                }
            } while ($true)
        }
        else {
            Write-Verbose "     $(Get-LocalizedString 'CommonServiceAlreadyStopped')"
        }
        
        # === STEP 5: Final check ===
        # CRITICAL FIX: Get-Service has NO StartupType property in PowerShell 5.1!
        # SOLUTION: Use Get-CimInstance for StartupType check
        try {
            $serviceCim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
            if ($serviceCim.StartMode -eq "Disabled") {
                $service = Get-Service -Name $ServiceName  # Refresh for Status
                if ($service.Status -eq "Stopped") {
                    Write-Verbose "[OK] $($ServiceName) - Disabled + Stopped"
                    return $true
                }
                else {
                    # StartupType=Disabled is reached, status is less critical
                    Write-Verbose (Get-LocalizedString 'CommonServiceDisabledWillNotStart' -f $ServiceName, $service.Status)
                    return $true
                }
            }
            else {
                Write-Error-Custom (Get-LocalizedString 'CommonServiceCouldNotDisable' -f $ServiceName, $serviceCim.StartMode)
                return $false
            }
        }
        catch {
            Write-Verbose (Get-LocalizedString 'CommonCIMCheckFailed' -f $_)
            # Fallback: Assume Set-Service was successful
            Write-Verbose (Get-LocalizedString 'CommonServiceDisabledAssumed' -f $ServiceName)
            return $true
        }
    }
    catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
        # Service doesn't exist - that's OK (already uninstalled or never installed)
        Write-Verbose (Get-LocalizedString 'CommonServiceNotInstalled' -f $ServiceName)
        return $true
    }
    catch {
        Write-Error-Custom (Get-LocalizedString 'CommonServiceDisableError' -f $ServiceName, $_)
        Write-Verbose "Details: $($_.Exception.Message)"
        return $false
    }
}

# Note: Export-ModuleMember is NOT needed for dot-sourced scripts
# Functions are automatically available in the calling scope
