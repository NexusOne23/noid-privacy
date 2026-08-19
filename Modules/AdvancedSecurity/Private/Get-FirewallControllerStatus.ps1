function Get-FirewallControllerStatus {
    <#
    .SYNOPSIS
        Detects a small set of common third-party Windows Firewall controllers.

    .DESCRIPTION
        Detection is advisory only. The caller must use the result solely as a
        prompt/default hint and must not silently skip firewall hardening.
    #>
    [CmdletBinding()]
    param()

    $products = @(
        [PSCustomObject]@{
            Name          = 'Windows Firewall Control'
            Services      = @('wfcs')
            Processes     = @('wfc')
            DisplayNameRx = '(?i)Windows Firewall Control'
        }
        [PSCustomObject]@{
            Name          = 'Bitdefender'
            Services      = @('vsserv', 'bdservicehost')
            Processes     = @('bdagent', 'bdservicehost')
            DisplayNameRx = '(?i)Bitdefender'
        }
        [PSCustomObject]@{
            Name          = 'ESET'
            Services      = @('ekrn')
            Processes     = @('egui', 'ekrn')
            DisplayNameRx = '(?i)ESET'
        }
        [PSCustomObject]@{
            Name          = 'Kaspersky'
            Services      = @('avp')
            Processes     = @('avp', 'avpui')
            DisplayNameRx = '(?i)Kaspersky'
        }
    )

    $evidence = [System.Collections.Generic.List[object]]::new()
    $errors = [System.Collections.Generic.List[string]]::new()

    foreach ($product in $products) {
        foreach ($serviceName in $product.Services) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction Stop
                $evidence.Add([PSCustomObject]@{
                        Product = $product.Name
                        Source  = 'Service'
                        Value   = $service.Name
                        State   = [string]$service.Status
                    })
            }
            catch [Microsoft.PowerShell.Commands.ServiceCommandException] {
                # A missing candidate service is the normal negative detection result.
                Write-Verbose "Candidate firewall-controller service is not installed: $serviceName"
            }
            catch {
                $errors.Add("Service detection failed for '$serviceName': $($_.Exception.Message)")
            }
        }

        foreach ($processName in $product.Processes) {
            try {
                $process = @(Get-Process -Name $processName -ErrorAction Stop)
                foreach ($item in $process) {
                    $evidence.Add([PSCustomObject]@{
                            Product = $product.Name
                            Source  = 'Process'
                            Value   = $item.ProcessName
                            State   = 'Running'
                        })
                }
            }
            catch [Microsoft.PowerShell.Commands.ProcessCommandException] {
                # A missing candidate process is the normal negative detection result.
                Write-Verbose "Candidate firewall-controller process is not running: $processName"
            }
            catch {
                $errors.Add("Process detection failed for '$processName': $($_.Exception.Message)")
            }
        }
    }

    $uninstallRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )

    foreach ($root in $uninstallRoots) {
        try {
            $installedEntries = @(Get-ItemProperty -Path $root -ErrorAction Stop)
            foreach ($entry in $installedEntries) {
                if ([string]::IsNullOrWhiteSpace([string]$entry.DisplayName)) { continue }

                foreach ($product in $products) {
                    if ([string]$entry.DisplayName -match $product.DisplayNameRx) {
                        $evidence.Add([PSCustomObject]@{
                                Product = $product.Name
                                Source  = 'InstalledProduct'
                                Value   = [string]$entry.DisplayName
                                State   = 'Installed'
                            })
                        break
                    }
                }
            }
        }
        catch [System.Management.Automation.ItemNotFoundException] {
            # The uninstall root is optional (notably HKCU on fresh profiles).
            Write-Verbose "Optional uninstall inventory root is absent: $root"
        }
        catch {
            $errors.Add("Installed-product detection failed for '$root': $($_.Exception.Message)")
        }
    }

    $uniqueEvidence = @($evidence | Sort-Object Product, Source, Value -Unique)
    $detectedProducts = @($uniqueEvidence | Select-Object -ExpandProperty Product -Unique)

    return [PSCustomObject]@{
        Detected          = ($detectedProducts.Count -gt 0)
        Products          = $detectedProducts
        Evidence          = $uniqueEvidence
        DetectionComplete = ($errors.Count -eq 0)
        Errors            = @($errors)
    }
}

function Write-FirewallControllerRuntimeWarning {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [bool]$FirewallLayerSkipped,

        [Parameter(Mandatory = $false)]
        $Detection = $null
    )

    if ($null -eq $Detection) {
        $Detection = Get-FirewallControllerStatus
    }

    if (-not $Detection.DetectionComplete) {
        $detail = $Detection.Errors -join '; '
        Write-Log -Level WARNING -Message "Third-party firewall-controller detection was incomplete: $detail" -Module 'AdvancedSecurity'
    }

    if (-not $Detection.Detected) {
        return $Detection
    }

    $productList = $Detection.Products -join ', '
    if ($FirewallLayerSkipped) {
        Write-Log -Level INFO -Message "Third-party firewall controller detected ($productList); NoID Privacy firewall layer is explicitly skipped" -Module 'AdvancedSecurity'
    }
    else {
        $message = "Third-party firewall controller detected ($productList) while the NoID Privacy firewall layer is enabled. The controller may override or conflict with NoID Privacy rules; review its rules or rerun AdvancedSecurity and explicitly skip the firewall layer."
        Write-Host "WARNING: $message" -ForegroundColor Yellow
        Write-Log -Level WARNING -Message $message -Module 'AdvancedSecurity'
    }

    return $Detection
}
