#Requires -Version 5.1

function Set-AntiAIRegistryValue {
    <#
    .SYNOPSIS
        Writes one AntiAI registry value with exact kind/value verification.
    #>
    # This private leaf helper is called only after the public module command has
    # completed its ShouldProcess decision and sealed-prestate checks.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')]
        [string]$Type,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Value,

        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )

    if ($DryRun) {
        Write-Log -Level DEBUG -Message "[DRYRUN] Would set $Path::$Name ($Type)" -Module 'AntiAI'
        return $true
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Container -ErrorAction Stop)) {
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }
    $typedValue = switch ($Type) {
        'DWord' { [int]$Value }
        'QWord' { [long]$Value }
        'String' { [string]$Value }
        'ExpandString' { [string]$Value }
        'MultiString' { [string[]]@($Value) }
        'Binary' { [byte[]]@($Value) }
    }
    New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type `
        -Value $typedValue -Force -ErrorAction Stop | Out-Null

    $key = Get-Item -LiteralPath $Path -ErrorAction Stop
    $actualType = $key.GetValueKind($Name).ToString()
    $actualValue = $key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $expectedJson = [PSCustomObject]@{ Value = $typedValue } | ConvertTo-Json -Compress -Depth 10
    $actualJson = [PSCustomObject]@{ Value = $actualValue } | ConvertTo-Json -Compress -Depth 10
    if ($actualType -ne $Type -or $actualJson -cne $expectedJson) {
        throw "AntiAI registry readback mismatch for $Path::$Name"
    }
    return $true
}
