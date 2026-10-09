function Get-AdvancedSecurityApplicability {
    <#
    .SYNOPSIS
        Resolve edition-dependent AdvancedSecurity applicability.

    .DESCRIPTION
        Uses Win32_OperatingSystem.OperatingSystemSKU as the primary,
        language-independent edition signal and EditionID only as a fallback.
        Microsoft documents Remote Desktop hosting for Professional,
        Enterprise and Education. WirelessDisplay, AllowOptionalContent and
        DeliveryOptimization policy CSPs additionally document IoT Enterprise;
        none of these policy surfaces lists Home.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $sku = [int]$os.OperatingSystemSKU
    $editionKey = Get-Item -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $editionId = [string]$editionKey.GetValue('EditionID', '')

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
        throw "Unsupported or unknown Windows edition applicability: SKU=$sku, EditionID='$editionId'"
    }

    $managedPolicySupported = $family -in @('Professional', 'Enterprise', 'Education', 'IoTEnterprise')
    return [PSCustomObject]@{
        EditionFamily           = $family
        OperatingSystemSKU      = $sku
        EditionID               = $editionId
        RdpHostSupported        = $family -in @('Professional', 'Enterprise', 'Education')
        ManagedPolicySupported  = $managedPolicySupported
        WirelessDisplaySupported = $managedPolicySupported
        Source = 'Win32_OperatingSystem.OperatingSystemSKU/EditionID'
    }
}
