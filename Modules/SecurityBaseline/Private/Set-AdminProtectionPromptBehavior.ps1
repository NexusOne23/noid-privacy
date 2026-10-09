#Requires -Version 5.1

# The prompt policy of Administrator protection ("User Account Control: Behavior
# of the elevation prompt for administrators running with Administrator
# protection"): 1 = credentials on the secure desktop (Windows default and
# Microsoft's v2 baseline value), 2 = consent on the secure desktop. Its prestate
# is sealed together with the security-template registry values
# (Backup-SecurityTemplateRegistryState).
$script:AdminProtectionPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$script:AdminProtectionPromptValueName = 'ConsentPromptBehaviorEnhancedAdmin'

function Set-AdminProtectionPromptBehavior {
    <#
    .SYNOPSIS
        Applies and verifies the selected Administrator protection prompt.

    .DESCRIPTION
        Runs after the security template has set TypeOfAdminApprovalMode and
        ConsentPromptBehaviorEnhancedAdmin. Consent expects 2. Credentials and
        Classic expect Microsoft's v2 baseline value 1; with Classic,
        Administrator protection is off and the value has no effect. A value
        that differs is corrected, then the result is verified.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Credentials', 'Consent', 'Classic')]
        [string]$AdminProtectionMode
    )

    $expectedType = if ($AdminProtectionMode -eq 'Classic') { 1 } else { 2 }
    $key = Get-Item -LiteralPath $script:AdminProtectionPolicyPath -ErrorAction Stop
    $actualType = $key.GetValue('TypeOfAdminApprovalMode', $null)
    if ($null -eq $actualType -or $key.GetValueKind('TypeOfAdminApprovalMode').ToString() -ne 'DWord' -or
        [string]$actualType -ne [string]$expectedType) {
        throw "TypeOfAdminApprovalMode expected DWord/$expectedType, got $actualType"
    }

    $names = @($key.GetValueNames())
    $present = $names -contains $script:AdminProtectionPromptValueName
    $current = if ($present) { $key.GetValue($script:AdminProtectionPromptValueName, $null) } else { $null }
    $currentKind = if ($present) { $key.GetValueKind($script:AdminProtectionPromptValueName).ToString() } else { $null }

    $target = if ($AdminProtectionMode -eq 'Consent') { 2 } else { 1 }
    if (-not ($present -and $currentKind -eq 'DWord' -and [string]$current -eq [string]$target)) {
        if ($PSCmdlet.ShouldProcess("$($script:AdminProtectionPolicyPath)\$($script:AdminProtectionPromptValueName)", "Set DWord $target")) {
            $null = New-ItemProperty -LiteralPath $script:AdminProtectionPolicyPath `
                -Name $script:AdminProtectionPromptValueName -PropertyType DWord -Value $target -Force -ErrorAction Stop
        }
    }

    $key = Get-Item -LiteralPath $script:AdminProtectionPolicyPath -ErrorAction Stop
    $present = @($key.GetValueNames()) -contains $script:AdminProtectionPromptValueName
    $value = if ($present) { $key.GetValue($script:AdminProtectionPromptValueName, $null) } else { $null }
    $kind = if ($present) { $key.GetValueKind($script:AdminProtectionPromptValueName).ToString() } else { $null }
    if (-not $present -or $kind -ne 'DWord' -or [string]$value -ne [string]$target) {
        throw "ConsentPromptBehaviorEnhancedAdmin expected DWord/$target, got $kind/$value"
    }
    return [PSCustomObject]@{
        TypeOfAdminApprovalMode = [int]$actualType
        Value                   = $(if ($present -and $kind -eq 'DWord') { [int]$value } else { $null })
    }
}
