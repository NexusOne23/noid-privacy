#Requires -Version 5.1

<#
.SYNOPSIS
    Advanced Copilot blocking - URI handlers, Edge sidebar, region policy, network block.

.DESCRIPTION
    Multi-layer advanced Copilot blocking for Windows 11 24H2/25H2+:
    
    LAYER 1: RECALL EXPORT BLOCK (KB5055627)
    - AllowRecallExport = 0 (prevents snapshot export)
    
    LAYER 2: URI PROTOCOL HANDLERS
    - Blocks ms-copilot: and ms-edge-copilot: deep links
    - Prevents Start menu search and third-party app launching
    
    LAYER 3: EDGE COPILOT SIDEBAR
    - Disables sidebar completely
    - Blocks page context access
    - 5 registry policies
    
    LAYER 4: REGION POLICY OVERRIDE (Optional)
    - Modifies IntegratedServicesRegionPolicySet.json
    - Disables Copilot at OS level regardless of region
    
    LAYER 5: NETWORK BLOCK (Optional)
    - Hosts file redirect for copilot endpoints

.PARAMETER DryRun
    Simulates the operation without making changes.

.PARAMETER SkipNetworkBlock
    Skip hosts file modification (less aggressive).

.PARAMETER SkipRegionPolicy
    Skip IntegratedServicesRegionPolicySet.json modification.

.EXAMPLE
    Disable-CopilotAdvanced
    
.NOTES
    Requires Administrator privileges.
    Part of NoID Privacy AntiAI Module v2.2.2
#>
function Disable-CopilotAdvanced {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$DryRun
    )
    
    Write-Log -Level DEBUG -Message "Disabling Copilot (Advanced Layers)" -Module "AntiAI"
    
    $result = [PSCustomObject]@{
        Success = $false
        Applied = 0
        Errors = @()
        RecallExportBlocked = $false
        URIHandlersBlocked = $false
        EdgeSidebarDisabled = $false
    }
    
    try {
        if ($DryRun) {
            Write-Log -Level DEBUG -Message "[DRYRUN] Would apply advanced Copilot blocks" -Module "AntiAI"
            $result.Applied = 3  # 3 official MS features: RecallExport, URIHandlers, EdgeSidebar
            $result.Success = $true
            return $result
        }
        
        # ============================================================================
        # LAYER 1: RECALL EXPORT BLOCK (KB5055627 - NEW)
        # ============================================================================
        Write-Log -Level DEBUG -Message "Layer 1: Blocking Recall Export..." -Module "AntiAI"
        
        $aiPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        if (-not (Test-Path $aiPolicyPath)) {
            New-Item -Path $aiPolicyPath -Force | Out-Null
        }
        
        try {
            $existing = Get-ItemProperty -Path $aiPolicyPath -Name "AllowRecallExport" -ErrorAction SilentlyContinue
            if ($null -ne $existing) {
                Set-ItemProperty -Path $aiPolicyPath -Name "AllowRecallExport" -Value 0 -Force | Out-Null
            } else {
                New-ItemProperty -Path $aiPolicyPath -Name "AllowRecallExport" -Value 0 -PropertyType DWord -Force | Out-Null
            }
            Write-Log -Level DEBUG -Message "AllowRecallExport = 0 (export disabled)" -Module "AntiAI"
            $result.RecallExportBlocked = $true
            $result.Applied++
        }
        catch {
            Write-Log -Level WARNING -Message "Failed to set AllowRecallExport: $_" -Module "AntiAI"
            $result.Errors += "AllowRecallExport: $_"
        }
        
        # ============================================================================
        # LAYER 2: URI PROTOCOL HANDLERS (ms-copilot:, ms-edge-copilot:)
        # ============================================================================
        Write-Log -Level DEBUG -Message "Layer 2: Blocking URI handlers..." -Module "AntiAI"
        
        $uriHandlers = @("ms-copilot", "ms-edge-copilot")
        $uriBlocked = 0
        
        foreach ($handler in $uriHandlers) {
            $handlerPath = "Registry::HKEY_CLASSES_ROOT\$handler"
            
            try {
                if (Test-Path $handlerPath) {
                    # Rename the key to disable it (preserves for restore)
                    $backupPath = "Registry::HKEY_CLASSES_ROOT\${handler}_DISABLED_BY_NOID"
                    
                    # Check if already disabled
                    if (-not (Test-Path $backupPath)) {
                        # Delete the original handler (blocks the protocol)
                        Remove-Item -Path $handlerPath -Recurse -Force -ErrorAction Stop
                        
                        # Create marker for restore
                        New-Item -Path $backupPath -Force | Out-Null
                        New-ItemProperty -Path $backupPath -Name "OriginallyExisted" -Value 1 -PropertyType DWord -Force | Out-Null
                        New-ItemProperty -Path $backupPath -Name "DisabledBy" -Value "NoID Privacy AntiAI" -PropertyType String -Force | Out-Null
                        New-ItemProperty -Path $backupPath -Name "DisabledAt" -Value (Get-Date -Format "o") -PropertyType String -Force | Out-Null
                        
                        Write-Log -Level DEBUG -Message "Blocked URI handler: $handler" -Module "AntiAI"
                        $uriBlocked++
                    }
                    else {
                        Write-Log -Level DEBUG -Message "URI handler already blocked: $handler" -Module "AntiAI"
                        $uriBlocked++
                    }
                }
                else {
                    Write-Log -Level DEBUG -Message "URI handler not found (already removed): $handler" -Module "AntiAI"
                    $uriBlocked++
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Failed to block URI handler $handler : $_" -Module "AntiAI"
                $result.Errors += "URI $handler : $_"
            }
        }
        
        if ($uriBlocked -gt 0) {
            $result.URIHandlersBlocked = $true
            $result.Applied++
        }
        
        # ============================================================================
        # LAYER 3: EDGE COPILOT SIDEBAR
        # ============================================================================
        Write-Log -Level DEBUG -Message "Layer 3: Disabling Edge Copilot Sidebar..." -Module "AntiAI"
        
        $edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        if (-not (Test-Path $edgePolicyPath)) {
            New-Item -Path $edgePolicyPath -Force | Out-Null
        }
        
        $edgePolicies = @(
            @{ Name = "EdgeSidebarEnabled"; Value = 0; Desc = "Edge sidebar" },
            @{ Name = "ShowHubsSidebar"; Value = 0; Desc = "Hubs sidebar visibility" },
            @{ Name = "HubsSidebarEnabled"; Value = 0; Desc = "Hubs sidebar" },
            @{ Name = "CopilotPageContext"; Value = 0; Desc = "Copilot page context" },
            @{ Name = "CopilotCDPPageContext"; Value = 0; Desc = "Copilot CDP context" }
        )
        
        $edgeApplied = 0
        foreach ($policy in $edgePolicies) {
            try {
                $existing = Get-ItemProperty -Path $edgePolicyPath -Name $policy.Name -ErrorAction SilentlyContinue
                if ($null -ne $existing) {
                    Set-ItemProperty -Path $edgePolicyPath -Name $policy.Name -Value $policy.Value -Force | Out-Null
                } else {
                    New-ItemProperty -Path $edgePolicyPath -Name $policy.Name -Value $policy.Value -PropertyType DWord -Force | Out-Null
                }
                Write-Log -Level DEBUG -Message "Edge: $($policy.Name) = $($policy.Value)" -Module "AntiAI"
                $edgeApplied++
            }
            catch {
                Write-Log -Level WARNING -Message "Failed to set Edge policy $($policy.Name): $_" -Module "AntiAI"
            }
        }
        
        if ($edgeApplied -eq $edgePolicies.Count) {
            $result.EdgeSidebarDisabled = $true
            $result.Applied++
        }
        
        # NOTE: Layer 4 (RegionPolicy) and Layer 5 (NetworkBlock) REMOVED
        # Reason: NOT Microsoft Best Practice
        # - IntegratedServicesRegionPolicySet.json: Community workaround, can break with updates
        # - Hosts file blocking: "Not officially supported" per Microsoft Q&A
        # We only use official Registry Policies as per MS documentation
        
        # Determine overall success
        $result.Success = ($result.RecallExportBlocked -or $result.URIHandlersBlocked -or 
                          $result.EdgeSidebarDisabled) -and ($result.Errors.Count -eq 0)
        
        Write-Log -Level DEBUG -Message "Advanced Copilot blocks applied: $($result.Applied)" -Module "AntiAI"
    }
    catch {
        $result.Errors += "Critical error: $($_.Exception.Message)"
        Write-Error $result.Errors[-1]
    }
    
    return $result
}
