function Test-IPv6Security {
    <#
    .SYNOPSIS
        Test the opt-in IPv6 component-disable registry state.

    .DESCRIPTION
        Checks for exact REG_DWORD DisabledComponents=0xFF. This is an optional
        Maximum-profile setting. Microsoft documents 0xFF as the IPv6-disable
        value but states that internal IPv6 functionality cannot be completely
        disabled, so this test asserts registry state rather than total runtime
        absence or complete mitm6 prevention.

    .EXAMPLE
        Test-IPv6Security
    #>
    [CmdletBinding()]
    param()

    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        $key = if (Test-Path -LiteralPath $regPath -PathType Container) {
            Get-Item -LiteralPath $regPath -ErrorAction Stop
        } else { $null }
        $exists = $key -and $key.GetValueNames() -contains 'DisabledComponents'
        $actual = if ($exists) { $key.GetValue('DisabledComponents') } else { $null }

        if ($exists -and $key.GetValueKind('DisabledComponents').ToString() -eq 'DWord' -and [int]$actual -eq 255) {
            return [PSCustomObject]@{
                Feature       = "IPv6 component disable (0xFF)"
                Pass          = $true
                Compliant     = $true
                NotApplicable = $false
                Message       = "IPv6 component-disable registry state matches (DisabledComponents = 0xFF)"
                Details       = "Exact registry state verified; reboot/runtime effectiveness and complete mitm6 prevention are not asserted"
            }
        }
        elseif ($exists) {
            return [PSCustomObject]@{
                Feature       = "IPv6 component disable (0xFF)"
                Pass          = $false
                Compliant     = $false
                NotApplicable = $false
                Message       = "IPv6 component-disable value/type mismatch (DisabledComponents = $actual)"
                Details       = "Expected exact REG_DWORD 255"
            }
        }
        else {
            return [PSCustomObject]@{
                Feature       = "IPv6 component disable (0xFF)"
                Pass          = $false
                Compliant     = $false
                NotApplicable = $false
                Message       = "Selected IPv6 component-disable value is absent"
                Details       = "Expected exact REG_DWORD 255"
            }
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test IPv6 security: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return [PSCustomObject]@{
            Feature       = "IPv6 component disable (0xFF)"
            Pass          = $false
            Compliant     = $false
            NotApplicable = $false
            Message       = "Error checking IPv6 status"
            Details       = "Could not determine IPv6 status: $_"
        }
    }
}
