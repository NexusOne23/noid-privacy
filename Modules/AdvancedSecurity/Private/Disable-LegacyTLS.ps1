function Disable-LegacyTLS {
    <#
    .SYNOPSIS
        Disable legacy TLS 1.0 and TLS 1.1

    .DESCRIPTION
        Disables TLS 1.0 and TLS 1.1 for both Client and Server to prevent
        BEAST, CRIME, and other attacks.

        Attack Prevention: BEAST, CRIME, weak cipher suites

        Impact: May break old internal web applications that haven't been updated

    .EXAMPLE
        Disable-LegacyTLS
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()

    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Disable LegacyTLS')) {
        return
    }


    try {
        Write-Log -Level INFO -Message "Disabling legacy TLS 1.0 and TLS 1.1..." -Module "AdvancedSecurity"

        $tlsVersions = @("TLS 1.0", "TLS 1.1")
        $components = @("Server", "Client")

        $setCount = 0

        foreach ($version in $tlsVersions) {
            foreach ($component in $components) {
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$version\$component"

                # The targeted registry pre-state was sealed before Apply.
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force -ErrorAction Stop | Out-Null
                }

                # Disable TLS version
                Remove-ItemProperty -LiteralPath $regPath -Name 'Enabled' -ErrorAction SilentlyContinue
                New-ItemProperty -Path $regPath -Name 'Enabled' -Value 0 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                Remove-ItemProperty -LiteralPath $regPath -Name 'DisabledByDefault' -ErrorAction SilentlyContinue
                New-ItemProperty -Path $regPath -Name 'DisabledByDefault' -Value 1 -PropertyType DWord -Force -ErrorAction Stop | Out-Null
                $tlsKey = Get-Item -LiteralPath $regPath -ErrorAction Stop
                if ($tlsKey.GetValueKind('Enabled').ToString() -ne 'DWord' -or [int]$tlsKey.GetValue('Enabled') -ne 0 -or
                    $tlsKey.GetValueKind('DisabledByDefault').ToString() -ne 'DWord' -or [int]$tlsKey.GetValue('DisabledByDefault') -ne 1) {
                    throw "$version $component post-apply type/value mismatch"
                }

                Write-Log -Level SUCCESS -Message "Disabled $version $component" -Module "AdvancedSecurity"
                $setCount += 2
            }
        }

        Write-Log -Level SUCCESS -Message "Legacy TLS disabled ($setCount registry keys set)" -Module "AdvancedSecurity"
        Write-Host ""
        Write-Host "Legacy TLS Disabled:" -ForegroundColor Green
        Write-Host "  TLS 1.0: Client + Server" -ForegroundColor Gray
        Write-Host "  TLS 1.1: Client + Server" -ForegroundColor Gray
        Write-Host ""
        Write-Host "WARNING: Old web applications may not work!" -ForegroundColor Yellow
        Write-Host "TLS 1.0 and TLS 1.1 client/server SCHANNEL states are disabled." -ForegroundColor Gray
        Write-Host "NoID Privacy does not infer the state of every other protocol from these values." -ForegroundColor Gray
        Write-Host ""

        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to disable legacy TLS: $_" -Module "AdvancedSecurity" -Exception $_.Exception
        return $false
    }
}
