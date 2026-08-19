#Requires -Version 5.1

function Get-PrivacyApplicability {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $sku = [int]$os.OperatingSystemSKU
    $editionKey = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $editionId = [string]$editionKey.GetValue('EditionID', '')
    $management = Get-PrivacyManagementState
    $ucpd = Get-PrivacyUcpdProtectionState
    $homeSkus = @(2, 3, 5, 26, 98, 99, 100, 101)
    $professionalSkus = @(6, 16, 48, 49, 103, 161, 162, 164)
    $enterpriseSkus = @(4, 27, 70, 72, 84, 125, 126, 129, 130, 175)
    $educationSkus = @(121, 122)
    $iotEnterpriseSkus = @(188, 191)
    $family = if ($sku -in $homeSkus) { 'Home' }
        elseif ($sku -in $professionalSkus) { 'Professional' }
        elseif ($sku -in $enterpriseSkus) { 'Enterprise' }
        elseif ($sku -in $educationSkus) { 'Education' }
        elseif ($sku -in $iotEnterpriseSkus) { 'IoTEnterprise' }
        elseif ($editionId -match '^Core') { 'Home' }
        elseif ($editionId -match '^Professional') { 'Professional' }
        elseif ($editionId -match '^Enterprise') { 'Enterprise' }
        elseif ($editionId -match '^Education') { 'Education' }
        elseif ($editionId -match '^IoTEnterprise') { 'IoTEnterprise' }
        else { 'Unknown' }
    if ($family -eq 'Unknown') {
        throw "Unsupported or unknown Privacy edition applicability: SKU=$sku, EditionID='$editionId'"
    }
    $multiSession = ($sku -eq 175 -or $editionId -match '(?i)ServerRdsh|MultiSession')
    $tier1OsSupported = ($family -in @('Enterprise', 'Education')) -and ([int]$os.BuildNumber -ge 26100) -and -not $multiSession
    return [PSCustomObject]@{
        EditionFamily = $family
        OperatingSystemSKU = $sku
        EditionID = $editionId
        BuildNumber = [int]$os.BuildNumber
        WindowsManagedPolicySupported = $family -in @('Professional', 'Enterprise', 'Education', 'IoTEnterprise')
        EnterprisePolicySupported = $family -in @('Enterprise', 'Education', 'IoTEnterprise')
        # RemoveDefaultMicrosoftStorePackages (Tier 1 policy-based in-box app removal):
        # Microsoft Learn ("Policy-based in-box app removal", updated 2026-05-01) documents
        # Enterprise/Education only, Windows 11 version 24H2 (build 26100) or newer -- NOT
        # limited to 25H2/26200 as older secondary sources still state.
        DomainJoined = [bool]$management.DomainJoined
        MdmRegistered = [bool]$management.MdmRegistered
        ManagementStateKnown = [bool]$management.StateKnown
        ManagementQueryErrors = @($management.QueryErrors)
        MultiSession = $multiSession
        Tier1PolicyRemovalOsSupported = $tier1OsSupported
        Tier1PolicyRemovalSupported = $tier1OsSupported -and -not [bool]$management.ExternallyManaged
        UcpdProtectionStateKnown = [bool]$ucpd.StateKnown
        UcpdProtectionActive = [bool]$ucpd.Active
        UcpdStatus = [string]$ucpd.Status
        UcpdQueryError = [string]$ucpd.Error
        Source = 'Win32_OperatingSystem/Win32_ComputerSystem/MDMRegistrationApi/ServiceController'
    }
}

function Get-PrivacyTargetApplicability {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Applicability
    )

    $enterpriseOnlyNames = @(
        'DisableWindowsSpotlightFeatures',
        'DisableWindowsSpotlightOnSettings',
        'DisableWindowsSpotlightOnActionCenter',
        'DisableSpotlightCollectionOnDesktop',
        'DisableCloudOptimizedContent',
        'DisableSoftLanding'
    )
    if ($Name -in $enterpriseOnlyNames -and -not [bool]$Applicability.EnterprisePolicySupported) {
        return [PSCustomObject]@{
            Applicable = $false
            Reason = "$Name is documented only for Enterprise/Education/IoT Enterprise"
        }
    }

    if ($Name -eq 'EnableAccountNotifications' -and
        [string]$Applicability.EditionFamily -notin @('Home', 'Professional')) {
        return [PSCustomObject]@{
            Applicable = $false
            Reason = 'The visible Windows Settings account-notification switch is present and runtime-validated only on Home/Professional; Enterprise exposes no corresponding user switch'
        }
    }

    # Tier 1 policy-based in-box app removal (RemoveDefaultMicrosoftStorePackages) is
    # documented only for Enterprise/Education, Windows 11 24H2 (build 26100) or newer.
    # This is an edition/build gate only -- it is evaluated before the general Windows
    # managed-policy check below because it is stricter than "any managed-policy edition".
    $isTier1AppxRemovalPolicy = $Path -match '(?i)^HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Appx\\RemoveDefaultMicrosoftStorePackages(\\.+)?$'
    $tier1OsSupported = [bool]($Applicability.PSObject.Properties['Tier1PolicyRemovalOsSupported'] -and $Applicability.Tier1PolicyRemovalOsSupported)
    $tier1PolicyRemovalSupported = [bool]($Applicability.PSObject.Properties['Tier1PolicyRemovalSupported'] -and $Applicability.Tier1PolicyRemovalSupported)
    if ($isTier1AppxRemovalPolicy -and -not $tier1PolicyRemovalSupported) {
        $reason = if (-not $tier1OsSupported) {
            'RemoveDefaultMicrosoftStorePackages is documented only for single-session Windows 11 Enterprise/Education, version 24H2 (build 26100) or newer'
        }
        elseif ($Applicability.PSObject.Properties['ManagementStateKnown'] -and -not [bool]$Applicability.ManagementStateKnown) {
            'Domain/MDM management state could not be proven; Tier 1 fails closed while other Privacy targets remain available'
        }
        elseif ([bool]$Applicability.DomainJoined -or [bool]$Applicability.MdmRegistered) {
            'An AD-domain or MDM policy controller is registered; configure this policy in that authoritative channel to avoid last-writer-wins conflicts'
        }
        else { 'Tier 1 policy applicability could not be proven' }
        return [PSCustomObject]@{
            Applicable = $false
            Reason = $reason
        }
    }

    # OneDrive is a separately serviced application whose documented policies
    # are read by the sync client. All other Windows Administrative Template /
    # Policy CSP targets in this module require a managed-policy Windows edition.
    $isOneDrivePolicy = $Path -match '(?i)^HKLM:\\SOFTWARE\\Policies\\Microsoft\\OneDrive$'
    $isWindowsManagedPolicy = -not $isOneDrivePolicy -and (
        $Path -match '(?i)^HKLM:\\SOFTWARE\\Policies\\Microsoft\\(?:Windows|Dsh|FindMyDevice|InputPersonalization)' -or
        $Path -match '(?i)^HKCU:\\Software\\Policies\\Microsoft\\Windows' -or
        $Path -match '(?i)^HKU:\\S-1-(?:5-21|12-1)-[0-9-]+\\Software\\Policies\\Microsoft\\Windows' -or
        $Path -match '(?i)^HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\TextInput$'
    )
    if ($isWindowsManagedPolicy -and -not [bool]$Applicability.WindowsManagedPolicySupported) {
        return [PSCustomObject]@{
            Applicable = $false
            Reason = "$Name is a Windows managed-policy target not documented for Home"
        }
    }

    $isUcpdProtectedWidgetsPolicy =
        $Path -ieq 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -and
        $Name -ieq 'AllowNewsAndInterests'
    if ($isUcpdProtectedWidgetsPolicy) {
        $stateKnown = [bool](
            $Applicability.PSObject.Properties['UcpdProtectionStateKnown'] -and
            $Applicability.UcpdProtectionStateKnown)
        $protectionActive = [bool](
            -not $Applicability.PSObject.Properties['UcpdProtectionActive'] -or
            $Applicability.UcpdProtectionActive)
        if (-not $stateKnown -or $protectionActive) {
            $reason = if (-not $stateKnown) {
                'Windows UCPD protection state could not be proven; exact Apply/Restore fails closed for AllowNewsAndInterests'
            }
            else {
                'Windows UCPD is active and blocks PowerShell Apply/Restore for AllowNewsAndInterests; exact BAVR preserves the target unchanged'
            }
            return [PSCustomObject]@{ Applicable = $false; Reason = $reason }
        }
    }
    return [PSCustomObject]@{ Applicable = $true; Reason = $null }
}
