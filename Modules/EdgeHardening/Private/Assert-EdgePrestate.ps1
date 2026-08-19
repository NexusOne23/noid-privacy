#Requires -Version 5.1

function Assert-EdgePrestate {
    <#
    .SYNOPSIS
        Reconcile live Edge applicability and selected registry prestate before Apply.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Snapshot
    )

    $null = Assert-EdgePolicySnapshot -Snapshot $Snapshot
    if ([int]$Snapshot.SchemaVersion -ne 6) {
        throw 'Pre-Apply Edge reconciliation requires a schema-6 snapshot'
    }

    $currentEdge = Get-EdgeInstallationStatus
    foreach ($property in @('Installed', 'Path', 'Version', 'Major')) {
        if ([string]$currentEdge.$property -cne [string]$Snapshot.EdgeInstallationStatus.$property) {
            throw "Edge installation state changed after backup: $property"
        }
    }
    foreach ($property in @('Paths', 'Installations', 'UnreadablePaths')) {
        $currentJson = ConvertTo-Json -InputObject @($currentEdge.$property) -Compress -Depth 10
        $sealedJson = ConvertTo-Json -InputObject @($Snapshot.EdgeInstallationStatus.$property) -Compress -Depth 10
        if ($currentJson -cne $sealedJson) {
            throw "Edge installation state changed after backup: $property"
        }
    }

    $currentApplicability = Get-EdgeRuntimeApplicability
    foreach ($property in @(
            'EditionFamily', 'OperatingSystemSKU', 'EditionID', 'DomainJoined',
            'MdmRegistered', 'MdmEditionEligible', 'ManagedWindowsEligible',
            'EvidenceSource'
        )) {
        if ([string]$currentApplicability.$property -cne [string]$Snapshot.RuntimeApplicability.$property) {
            throw "Edge runtime applicability changed after backup: $property"
        }
    }

    foreach ($entry in @($Snapshot.Entries)) {
        $path = [string]$entry.Path
        $name = [string]$entry.Name
        $keyExists = Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop
        if ($keyExists -ne [bool]$entry.KeyExisted) {
            throw "Edge key existence changed after backup: $path"
        }
        $valueExists = $false
        $actualType = $null
        $actualValue = $null
        if ($keyExists) {
            $key = Get-Item -LiteralPath $path -ErrorAction Stop
            $valueExists = $key.GetValueNames() -contains $name
            if ($valueExists) {
                $actualType = $key.GetValueKind($name).ToString()
                $actualValue = $key.GetValue(
                    $name,
                    $null,
                    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                )
            }
        }
        if ($valueExists -ne [bool]$entry.Exists) {
            throw "Edge value existence changed after backup: $path::$name"
        }
        if ($valueExists) {
            $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
            $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
            if ($actualType -cne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                throw "Edge value changed after backup: $path::$name"
            }
        }
    }
    return $true
}
