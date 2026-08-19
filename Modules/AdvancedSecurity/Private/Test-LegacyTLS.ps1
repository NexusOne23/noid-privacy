function Test-LegacyTLS {
    <#
    .SYNOPSIS
        Test Legacy TLS configuration compliance

    .DESCRIPTION
        Verifies that TLS 1.0 and TLS 1.1 are disabled for both Client and Server.

    .OUTPUTS
        PSCustomObject with compliance details
    #>
    [CmdletBinding()]
    param()

    try {
        $result = [PSCustomObject]@{
            Feature = "Legacy TLS (1.0/1.1)"
            Status = "Unknown"
            Details = @()
            Compliant = $true
        }

        $tlsVersions = @("TLS 1.0", "TLS 1.1")
        $components = @("Server", "Client")
        $nonCompliantCount = 0

        foreach ($version in $tlsVersions) {
            foreach ($component in $components) {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\$component"

                if (Test-Path $regPath) {
                    $tlsKey = Get-Item -LiteralPath $regPath -ErrorAction Stop
                    $enabled = if ($tlsKey.GetValueNames() -contains 'Enabled') { $tlsKey.GetValue('Enabled') } else { $null }
                    $disabledByDefault = if ($tlsKey.GetValueNames() -contains 'DisabledByDefault') { $tlsKey.GetValue('DisabledByDefault') } else { $null }

                    if ($tlsKey.GetValueNames() -notcontains 'Enabled' -or $tlsKey.GetValueKind('Enabled').ToString() -ne 'DWord' -or
                        [int]$enabled -ne 0 -or $tlsKey.GetValueNames() -notcontains 'DisabledByDefault' -or
                        $tlsKey.GetValueKind('DisabledByDefault').ToString() -ne 'DWord' -or [int]$disabledByDefault -ne 1) {
                        $result.Details += "$version $component type/value mismatch (Enabled=$enabled, DisabledByDefault=$disabledByDefault)"
                        $nonCompliantCount++
                    }
                }
                else {
                    # Key missing usually means default (Enabled on old OS, Disabled on very new OS)
                    # For hardening, we expect explicit disable keys
                    $result.Details += "$version $component registry keys missing"
                    $nonCompliantCount++
                }
            }
        }

        if ($nonCompliantCount -eq 0) {
            $result.Status = "Secure (Disabled)"
            $result.Compliant = $true
        }
        else {
            $result.Status = "Insecure ($nonCompliantCount issues)"
            $result.Compliant = $false
        }

        return $result
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to test Legacy TLS: $_" -Module "AdvancedSecurity"
        return [PSCustomObject]@{
            Feature = "Legacy TLS (1.0/1.1)"
            Status = "Error"
            Details = @("Failed to test: $_")
            Compliant = $false
        }
    }
}
