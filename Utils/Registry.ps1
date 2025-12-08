<#
.SYNOPSIS
    Safe registry operation utilities for NoID Privacy
    
.DESCRIPTION
    Provides safe, validated registry manipulation functions with
    automatic backup and error handling.
    
.NOTES
    Author: NexusOne23
    Version: 2.2.0
    Requires: PowerShell 5.1+
#>

function Test-RegistryValueType {
    <#
    .SYNOPSIS
        Validate registry value type matches expected type
        
    .DESCRIPTION
        Performs strict type checking to ensure registry value
        matches the declared registry type before setting.
        
    .PARAMETER Value
        Value to validate
        
    .PARAMETER Type
        Expected registry type
        
    .OUTPUTS
        Boolean indicating if type matches
        
    .EXAMPLE
        Test-RegistryValueType -Value 1 -Type "DWord"
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "QWord")]
        [string]$Type
    )
    
    # Null values are not allowed for registry
    if ($null -eq $Value) {
        Write-Log -Level ERROR -Message "Registry value cannot be null" -Module "Registry"
        return $false
    }
    
    switch ($Type) {
        "String" {
            if ($Value -isnot [string]) {
                Write-Log -Level ERROR -Message "Value must be [string] for type String, got [$($Value.GetType().Name)]" -Module "Registry"
                return $false
            }
        }
        
        "ExpandString" {
            if ($Value -isnot [string]) {
                Write-Log -Level ERROR -Message "Value must be [string] for type ExpandString, got [$($Value.GetType().Name)]" -Module "Registry"
                return $false
            }
        }
        
        "DWord" {
            # DWord must be integer and fit in 32-bit (0 to 4294967295)
            if ($Value -isnot [int] -and $Value -isnot [uint32] -and $Value -isnot [long]) {
                Write-Log -Level ERROR -Message "Value must be numeric for type DWord, got [$($Value.GetType().Name)]" -Module "Registry"
                return $false
            }
            
            $numValue = [long]$Value
            if ($numValue -lt 0 -or $numValue -gt 4294967295) {
                Write-Log -Level ERROR -Message "DWord value must be between 0 and 4294967295, got $numValue" -Module "Registry"
                return $false
            }
        }
        
        "QWord" {
            # QWord must be integer and fit in 64-bit
            if ($Value -isnot [int] -and $Value -isnot [long] -and $Value -isnot [uint64]) {
                Write-Log -Level ERROR -Message "Value must be numeric for type QWord, got [$($Value.GetType().Name)]" -Module "Registry"
                return $false
            }
            
            # Check if value is in valid range for QWord (0 to 18446744073709551615)
            if ([long]$Value -lt 0) {
                Write-Log -Level ERROR -Message "QWord value cannot be negative, got $Value" -Module "Registry"
                return $false
            }
        }
        
        "Binary" {
            # Binary must be byte array
            if ($Value -isnot [byte[]]) {
                Write-Log -Level ERROR -Message "Value must be [byte[]] for type Binary, got [$($Value.GetType().Name)]" -Module "Registry"
                return $false
            }
        }
        
        "MultiString" {
            # MultiString must be string array
            if ($Value -isnot [string[]]) {
                Write-Log -Level ERROR -Message "Value must be [string[]] for type MultiString, got [$($Value.GetType().Name)]" -Module "Registry"
                return $false
            }
        }
    }
    
    return $true
}

function Set-RegistryValue {
    <#
    .SYNOPSIS
        Safely set a registry value with automatic backup
        
    .PARAMETER Path
        Registry path (e.g., "HKLM:\SOFTWARE\Policies\Microsoft\Windows")
        
    .PARAMETER Name
        Registry value name
        
    .PARAMETER Value
        Value to set
        
    .PARAMETER Type
        Registry value type (String, DWord, QWord, Binary, MultiString, ExpandString)
        
    .PARAMETER BackupName
        Optional backup name (if not provided, backup is skipped)
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        $Value,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("String", "ExpandString", "Binary", "DWord", "MultiString", "QWord")]
        [string]$Type,
        
        [Parameter(Mandatory = $false)]
        [string]$BackupName
    )
    
    try {
        # CRITICAL: Validate value type BEFORE setting
        if (-not (Test-RegistryValueType -Value $Value -Type $Type)) {
            $errMsg = "Type validation failed for $Path\$Name - Expected type: $Type, Value: $Value"
            Write-Log -Level ERROR -Message $errMsg -Module "Registry"
            throw $errMsg
        }
        
        # Create backup if requested
        if ($BackupName) {
            $parentPath = Split-Path -Path $Path -Parent
            if (Test-Path -Path $parentPath) {
                Backup-RegistryKey -KeyPath $parentPath -BackupName $BackupName | Out-Null
            }
        }
        
        # Ensure the key exists
        if (-not (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
            Write-Log -Level INFO -Message "Created registry key: $Path" -Module "Registry"
            
            # Track newly created key for proper rollback
            if (Get-Command Register-NewRegistryKey -ErrorAction SilentlyContinue) {
                Register-NewRegistryKey -KeyPath $Path
            }
        }
        
        # Set the value
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop | Out-Null
        
        Write-Log -Level SUCCESS -Message "Set registry value: $Path\$Name = $Value (Type: $Type)" -Module "Registry"
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to set registry value: $Path\$Name - $_" -Module "Registry" -Exception $_
        return $false
    }
}

function Get-RegistryValue {
    <#
    .SYNOPSIS
        Safely get a registry value
        
    .PARAMETER Path
        Registry path
        
    .PARAMETER Name
        Registry value name
        
    .PARAMETER DefaultValue
        Default value if registry value doesn't exist
        
    .OUTPUTS
        Registry value or default value
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        $DefaultValue = $null
    )
    
    try {
        if (Test-Path -Path $Path) {
            $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $value.$Name
        }
        else {
            Write-Log -Level WARNING -Message "Registry path not found: $Path" -Module "Registry"
            return $DefaultValue
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Registry value not found: $Path\$Name" -Module "Registry"
        return $DefaultValue
    }
}

function Remove-RegistryValue {
    <#
    .SYNOPSIS
        Safely remove a registry value
        
    .PARAMETER Path
        Registry path
        
    .PARAMETER Name
        Registry value name
        
    .PARAMETER BackupName
        Optional backup name
        
    .OUTPUTS
        Boolean indicating success
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $false)]
        [string]$BackupName
    )
    
    try {
        # Create backup if requested
        if ($BackupName) {
            Backup-RegistryKey -KeyPath $Path -BackupName $BackupName | Out-Null
        }
        
        if (Test-Path -Path $Path) {
            Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction Stop
            Write-Log -Level SUCCESS -Message "Removed registry value: $Path\$Name" -Module "Registry"
            return $true
        }
        else {
            Write-Log -Level WARNING -Message "Registry path not found: $Path" -Module "Registry"
            return $false
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to remove registry value: $Path\$Name" -Module "Registry" -Exception $_
        return $false
    }
}

function Test-RegistryValue {
    <#
    .SYNOPSIS
        Check if a registry value exists
        
    .PARAMETER Path
        Registry path
        
    .PARAMETER Name
        Registry value name
        
    .OUTPUTS
        Boolean indicating existence
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        
        [Parameter(Mandatory = $true)]
        [string]$Name
    )
    
    try {
        if (Test-Path -Path $Path) {
            $null = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
            return $true
        }
        return $false
    }
    catch {
        return $false
    }
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
