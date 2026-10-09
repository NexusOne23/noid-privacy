function Assert-SecurityBaselineServicePrestate {
    <#
    .SYNOPSIS
        Prove that the Xbox service startup prestates still match sealed backup inputs.

    .DESCRIPTION
        Binds service applicability to the pre-Apply inventory. A service that
        appears, disappears, or changes startup/delayed-start state after its
        snapshot causes a fail-closed result before secedit can mutate it.
        Runtime status is deliberately not compared because this baseline owns
        startup configuration only and its restore artifact is startup-only.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$ServiceNamesWithSealedPrestate
    )

    $canonicalNames = @('XboxGipSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc')
    $requestedNames = @($ServiceNamesWithSealedPrestate)
    if (@($requestedNames | Sort-Object -Unique).Count -ne $requestedNames.Count -or
        @($requestedNames | Where-Object { $_ -notin $canonicalNames }).Count -gt 0) {
        throw 'SecurityBaseline service prestate list is invalid or contains duplicates'
    }

    $installedServices = @(Get-Service -ErrorAction Stop)
    foreach ($serviceName in $canonicalNames) {
        $artifacts = @($global:BackupIndex | Where-Object {
                [string]$_.Module -eq 'SecurityBaseline' -and
                [string]$_.Type -eq 'Service' -and
                [string]$_.ServiceName -eq $serviceName
            })
        $liveServices = @($installedServices | Where-Object { [string]$_.Name -eq $serviceName })
        $mustExist = $serviceName -in $requestedNames

        if (-not $mustExist) {
            if ($artifacts.Count -ne 0 -or $liveServices.Count -ne 0) {
                throw "SecurityBaseline service appeared after backup inventory: $serviceName"
            }
            continue
        }
        if ($artifacts.Count -ne 1 -or $liveServices.Count -ne 1) {
            throw "SecurityBaseline service inventory drift: $serviceName"
        }

        $saved = Get-Content -LiteralPath $artifacts[0].BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ([int]$saved.SchemaVersion -ne 2 -or
            -not ([string]$saved.Name).Equals($serviceName, [StringComparison]::OrdinalIgnoreCase) -or
            -not $saved.PSObject.Properties['RestoreRuntimeState'] -or
            [bool]$saved.RestoreRuntimeState) {
            throw "SecurityBaseline service artifact is not a startup-only schema-2 snapshot: $serviceName"
        }
        if ([string]$liveServices[0].StartType -ne [string]$saved.StartType) {
            throw "SecurityBaseline service startup state changed after backup: $serviceName"
        }

        $serviceKey = Get-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -ErrorAction Stop
        $delayedExists = $serviceKey.GetValueNames() -contains 'DelayedAutoStart'
        if ($delayedExists -ne [bool]$saved.DelayedAutoStartExists -or
            ($delayedExists -and
                ($serviceKey.GetValueKind('DelayedAutoStart').ToString() -ne 'DWord' -or
                 [int]$serviceKey.GetValue('DelayedAutoStart') -ne [int]$saved.DelayedAutoStart))) {
            throw "SecurityBaseline service delayed-start state changed after backup: $serviceName"
        }
    }
    return $true
}
