<#
.SYNOPSIS
    Dependency checking utilities for NoID Privacy
    
.DESCRIPTION
    Provides functions to check for required external tools and dependencies
    
.NOTES
    Author: NexusOne23
    Version: 2.2.4
    Requires: PowerShell 5.1+
#>

function Test-CommandExists {
    <#
    .SYNOPSIS
        Check if a command/executable exists
        
    .PARAMETER Command
        Command or executable name to check
        
    .OUTPUTS
        Boolean indicating existence
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Command
    )
    
    try {
        $null = Get-Command $Command -ErrorAction Stop
        return $true
    }
    catch {
        return $false
    }
}

function Test-SecEditAvailable {
    <#
    .SYNOPSIS
        Check if secedit.exe is available
        
    .DESCRIPTION
        Verifies secedit.exe exists (required for Security Baseline module)
        
    .OUTPUTS
        PSCustomObject with availability status
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $result = [PSCustomObject]@{
        Available = $false
        Path      = $null
        Version   = $null
        Error     = $null
    }
    
    try {
        # secedit.exe is typically in System32
        $seceditPath = Join-Path $env:SystemRoot "System32\secedit.exe"
        
        if (Test-Path $seceditPath) {
            $result.Available = $true
            $result.Path = $seceditPath
            
            # Try to get version
            try {
                $versionInfo = (Get-Item $seceditPath).VersionInfo
                $result.Version = $versionInfo.FileVersion
            }
            catch {
                $result.Version = "Unknown"
            }
        }
        else {
            $result.Error = "secedit.exe not found at expected location: $seceditPath"
        }
    }
    catch {
        $result.Error = "Failed to check for secedit.exe: $($_.Exception.Message)"
    }
    
    return $result
}

function Test-AuditPolAvailable {
    <#
    .SYNOPSIS
        Check if auditpol.exe is available
        
    .DESCRIPTION
        Verifies auditpol.exe exists (required for Security Baseline module)
        
    .OUTPUTS
        PSCustomObject with availability status
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $result = [PSCustomObject]@{
        Available = $false
        Path      = $null
        Version   = $null
        Error     = $null
    }
    
    try {
        # auditpol.exe is typically in System32
        $auditpolPath = Join-Path $env:SystemRoot "System32\auditpol.exe"
        
        if (Test-Path $auditpolPath) {
            $result.Available = $true
            $result.Path = $auditpolPath
            
            # Try to get version
            try {
                $versionInfo = (Get-Item $auditpolPath).VersionInfo
                $result.Version = $versionInfo.FileVersion
            }
            catch {
                $result.Version = "Unknown"
            }
        }
        else {
            $result.Error = "auditpol.exe not found at expected location: $auditpolPath"
        }
    }
    catch {
        $result.Error = "Failed to check for auditpol.exe: $($_.Exception.Message)"
    }
    
    return $result
}

function Test-ThirdPartySecurityProduct {
    <#
    .SYNOPSIS
        Detect third-party antivirus or EDR/XDR products

    .DESCRIPTION
        Unified detection function used by ASR module and Verify script.
        Uses a 3-layer approach. The layer in which a product is detected reflects
        its REGISTRATION MECHANISM with Windows, not its product class or
        detection sophistication. Most modern AV/endpoint products (consumer or
        enterprise) employ heuristic, behavioral, reputation, ML/AI, exploit
        prevention, and cloud-sandbox detection regardless of which layer detects
        them. Many vendors appear in both layers depending on the SKU
        (e.g. Bitdefender consumer = Layer 1, Bitdefender GravityZone = Layer 2).

        Layer 1: WMI SecurityCenter2 -- catches AV products that register with
                 Windows Security Center (e.g. Bitdefender, Kaspersky, Avira,
                 Norton, ESET consumer SKUs)
        Layer 2: Defender Passive Mode via Get-MpComputerStatus -- catches
                 endpoint products that put Defender into passive mode rather
                 than registering with Security Center (e.g. CrowdStrike Falcon,
                 SentinelOne, enterprise EDR/XDR SKUs)
        Layer 3: Known service names (provides product display name for Layer 2
                 detections)

    .OUTPUTS
        PSCustomObject with:
        - Detected: Boolean - True if third-party product found
        - ProductName: String - Name of detected product
        - DetectionMethod: String - How it was detected (SecurityCenter2, PassiveMode, Service)
        - DefenderPassiveMode: Boolean - True if Defender is in passive mode
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $result = [PSCustomObject]@{
        Detected            = $false
        ProductName         = $null
        DetectionMethod     = $null
        DefenderPassiveMode = $false
    }

    # Layer 1: WMI SecurityCenter2 -- AV products registered with Windows Security Center
    try {
        $avProducts = Get-CimInstance -Namespace "root/SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
        $thirdPartyAV = $avProducts | Where-Object { $_.displayName -notmatch "Windows Defender|Microsoft Defender" } | Select-Object -First 1

        if ($thirdPartyAV) {
            $result.Detected = $true
            $result.ProductName = $thirdPartyAV.displayName
            $result.DetectionMethod = "SecurityCenter2"

            # Also check passive mode for complete info
            try {
                $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
                if ($defenderStatus -and $defenderStatus.AMRunningMode -eq "Passive Mode") {
                    $result.DefenderPassiveMode = $true
                }
            }
            catch { $null = $null }

            return $result
        }
    }
    catch {
        # SecurityCenter2 not available (e.g., Server OS) - continue to Layer 2
        $null = $null
    }

    # Layer 2: Defender Passive Mode -- endpoint products that put Defender into passive mode
    # instead of registering with Security Center (typically enterprise EDR/XDR deployments)
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus -and $defenderStatus.AMRunningMode -eq "Passive Mode") {
            $result.Detected = $true
            $result.DefenderPassiveMode = $true
            $result.DetectionMethod = "PassiveMode"

            # Layer 3: Try to identify the specific EDR/XDR product by service name
            $edrServices = @(
                @{ Name = "CSFalconService";      Display = "CrowdStrike Falcon" },
                @{ Name = "SentinelAgent";         Display = "SentinelOne" },
                @{ Name = "CbDefense";             Display = "Carbon Black Cloud" },
                @{ Name = "CylanceSvc";            Display = "Cylance/Arctic Wolf Aurora" },
                @{ Name = "xagt";                  Display = "Trellix Endpoint Security (HX)" },
                @{ Name = "masvc";                 Display = "Trellix Agent" },
                @{ Name = "mfeatp";                Display = "Trellix Adaptive Threat Protection" },
                @{ Name = "cyserver";              Display = "Palo Alto Cortex XDR" },
                @{ Name = "EPSecurityService";     Display = "Bitdefender GravityZone" },
                @{ Name = "EPIntegrationService";  Display = "Bitdefender GravityZone" },
                @{ Name = "avp";                   Display = "Kaspersky Endpoint Security" },
                @{ Name = "klnagent";              Display = "Kaspersky Security Center Agent" },
                @{ Name = "SEPAgent";              Display = "Broadcom/Symantec Endpoint Protection" },
                @{ Name = "SepMasterService";      Display = "Broadcom/Symantec Endpoint Protection" },
                @{ Name = "ekrn";                  Display = "ESET Endpoint Security" },
                @{ Name = "EraAgentSvc";           Display = "ESET PROTECT Agent" },
                @{ Name = "Sophos MCS Agent";      Display = "Sophos Endpoint" },
                @{ Name = "HitmanPro.Alert";       Display = "Sophos Endpoint" }
            )

            foreach ($edr in $edrServices) {
                $svc = Get-Service -Name $edr.Name -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq "Running") {
                    $result.ProductName = $edr.Display
                    $result.DetectionMethod = "PassiveMode+Service"
                    return $result
                }
            }

            # No known service found but Defender IS in passive mode = unknown product
            $result.ProductName = "Unknown Security Product (Defender in Passive Mode)"
            return $result
        }
    }
    catch {
        # Get-MpComputerStatus failed - Defender may not be available at all
        $null = $null
    }

    return $result
}

function Test-WindowsDefenderAvailable {
    <#
    .SYNOPSIS
        Check if Windows Defender is available and running as primary AV

    .DESCRIPTION
        Verifies Windows Defender service status (required for ASR module).
        Now also detects Passive Mode where Defender is running but not primary.

    .OUTPUTS
        PSCustomObject with availability status
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $result = [PSCustomObject]@{
        Available      = $false
        ServiceRunning = $false
        IsPassiveMode  = $false
        ServiceName    = "WinDefend"
        Error          = $null
    }

    try {
        $defenderService = Get-Service -Name "WinDefend" -ErrorAction SilentlyContinue

        if ($defenderService) {
            $result.Available = $true
            $result.ServiceRunning = ($defenderService.Status -eq "Running")

            if (-not $result.ServiceRunning) {
                $result.Error = "Windows Defender service exists but is not running (Status: $($defenderService.Status))"
            }
            else {
                # Check if Defender is in Passive Mode (another AV is primary)
                try {
                    $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
                    if ($defenderStatus -and $defenderStatus.AMRunningMode -eq "Passive Mode") {
                        $result.IsPassiveMode = $true
                        $result.Error = "Windows Defender is running in Passive Mode (third-party security product is primary)"
                    }
                }
                catch { $null = $null }
            }
        }
        else {
            $result.Error = "Windows Defender service (WinDefend) not found"
        }
    }
    catch {
        $result.Error = "Failed to check Windows Defender: $($_.Exception.Message)"
    }

    return $result
}

function Test-AllDependencies {
    <#
    .SYNOPSIS
        Check all required dependencies for NoID Privacy
        
    .DESCRIPTION
        Performs comprehensive dependency check for all modules
        
    .OUTPUTS
        PSCustomObject with all dependency statuses
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()
    
    $result = [PSCustomObject]@{
        AllAvailable     = $true
        SecurityBaseline = @{
            secedit  = $null
            auditpol = $null
        }
        ASR              = @{
            defender = $null
        }
        MissingCritical  = @()
        MissingOptional  = @()
    }
    
    # Check secedit.exe (CRITICAL for SecurityBaseline)
    $result.SecurityBaseline.secedit = Test-SecEditAvailable
    if (-not $result.SecurityBaseline.secedit.Available) {
        $result.AllAvailable = $false
        $result.MissingCritical += "secedit.exe (required for Security Baseline)"
    }
    
    # Check auditpol.exe (CRITICAL for SecurityBaseline)
    $result.SecurityBaseline.auditpol = Test-AuditPolAvailable
    if (-not $result.SecurityBaseline.auditpol.Available) {
        $result.AllAvailable = $false
        $result.MissingCritical += "auditpol.exe (required for Security Baseline)"
    }
    
    # NOTE: LGPO.exe check removed - v2.0 SecurityBaseline is fully self-contained
    
    # Check Windows Defender (CRITICAL for ASR)
    $result.ASR.defender = Test-WindowsDefenderAvailable
    if (-not $result.ASR.defender.Available -or -not $result.ASR.defender.ServiceRunning) {
        # Check if a third-party security product is present (not a critical failure)
        $thirdParty = Test-ThirdPartySecurityProduct
        if ($thirdParty.Detected) {
            $result.MissingOptional += "Windows Defender not primary (ASR skipped: $($thirdParty.ProductName))"
        }
        else {
            $result.AllAvailable = $false
            $result.MissingCritical += "Windows Defender (required for ASR module)"
        }
    }
    elseif ($result.ASR.defender.IsPassiveMode) {
        $thirdParty = Test-ThirdPartySecurityProduct
        $productName = if ($thirdParty.ProductName) { $thirdParty.ProductName } else { "Unknown" }
        $result.MissingOptional += "Windows Defender in Passive Mode (ASR skipped: $productName)"
    }
    
    return $result
}

# Note: Export-ModuleMember not used - this script is dot-sourced, not imported as module
