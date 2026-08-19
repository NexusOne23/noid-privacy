#Requires -Version 5.1

function Assert-SecurityBaselinePrestate {
    <#
    .SYNOPSIS
        Reconcile every SecurityBaseline artifact before the first mutation.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $artifacts = @($global:BackupIndex | Where-Object { [string]$_.Module -eq 'SecurityBaseline' })
    $requiredBaselineArtifacts = @(
        'RegistryPolicies', 'SecurityTemplate', 'UACStandardUserElevation',
        'SecurityTemplateRegistryState', 'AuditPolicies', 'XboxTask'
    )
    $baselineArtifacts = @($artifacts | Where-Object { [string]$_.Type -eq 'SecurityBaseline' })
    $serviceArtifacts = @($artifacts | Where-Object { [string]$_.Type -eq 'Service' })
    $unsupportedArtifacts = @($artifacts | Where-Object {
            [string]$_.Type -notin @('SecurityBaseline', 'Service')
        })
    $baselineNames = @($baselineArtifacts | ForEach-Object { [string]$_.Name })
    $serviceNamesInInventory = @($serviceArtifacts | ForEach-Object { [string]$_.ServiceName })
    $canonicalServiceNames = @('XboxGipSvc', 'XblAuthManager', 'XblGameSave', 'XboxNetApiSvc')
    if ($unsupportedArtifacts.Count -ne 0 -or
        $baselineArtifacts.Count -ne $requiredBaselineArtifacts.Count -or
        @($baselineNames | Sort-Object -Unique).Count -ne $baselineNames.Count -or
        @($requiredBaselineArtifacts | Where-Object { $_ -notin $baselineNames }).Count -ne 0 -or
        @($serviceNamesInInventory | Sort-Object -Unique).Count -ne $serviceNamesInInventory.Count -or
        @($serviceNamesInInventory | Where-Object { $_ -notin $canonicalServiceNames }).Count -ne 0) {
        throw 'SecurityBaseline backup artifact inventory is incomplete, duplicated or unsupported'
    }
    function Get-OneBaselineArtifact {
        param([string]$Name, [string]$Type = 'SecurityBaseline')
        $artifactMatches = @($artifacts | Where-Object {
                [string]$_.Name -eq $Name -and [string]$_.Type -eq $Type
            })
        if ($artifactMatches.Count -ne 1) {
            throw "Expected one SecurityBaseline artifact '$Name/$Type'; found $($artifactMatches.Count)"
        }
        return $artifactMatches[0]
    }
    function Assert-RegistryValuePrestate {
        param($Entry, [string]$Path, [string]$Name, [switch]$BaselineType)
        $exactExpectedName = $Name
        foreach ($propertyName in @('OriginalValueName', 'OriginalName')) {
            if ([bool]$Entry.Exists -and $Entry.PSObject.Properties[$propertyName]) {
                if ([string]::IsNullOrWhiteSpace([string]$Entry.$propertyName) -or
                    -not ([string]$Entry.$propertyName).Equals($Name, [StringComparison]::OrdinalIgnoreCase)) {
                    throw "SecurityBaseline original value-name identity is invalid: $Path::$Name"
                }
                $exactExpectedName = [string]$Entry.$propertyName
            }
        }
        $keyExists = Test-Path -LiteralPath $Path -PathType Container -ErrorAction Stop
        if ($keyExists -ne [bool]$Entry.KeyExisted) {
            throw "SecurityBaseline key existence changed after backup: $Path"
        }
        $exists = $false
        $value = $null
        $type = $null
        if ($keyExists) {
            $key = Get-Item -LiteralPath $Path -ErrorAction Stop
            $matchingNames = @($key.GetValueNames() | Where-Object {
                    ([string]$_).Equals($exactExpectedName, [StringComparison]::OrdinalIgnoreCase)
                })
            $exists = $matchingNames.Count -eq 1
            if ($exists) {
                if ([string]$matchingNames[0] -cne $exactExpectedName) {
                    throw "SecurityBaseline value-name casing changed after backup: $Path::$exactExpectedName"
                }
                $value = $key.GetValue([string]$matchingNames[0], $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $type = if ($BaselineType) {
                    ConvertTo-RegistryTypeString -Kind $key.GetValueKind([string]$matchingNames[0])
                }
                else {
                    $key.GetValueKind([string]$matchingNames[0]).ToString()
                }
            }
        }
        if ($exists -ne [bool]$Entry.Exists) {
            throw "SecurityBaseline value existence changed after backup: $Path::$Name"
        }
        if ($exists) {
            $expectedJson = ConvertTo-Json -InputObject @($Entry.Value) -Compress -Depth 20
            if ($Entry.PSObject.Properties['OriginalValue']) {
                $expectedJson = ConvertTo-Json -InputObject @($Entry.OriginalValue) -Compress -Depth 20
            }
            $actualJson = ConvertTo-Json -InputObject @($value) -Compress -Depth 20
            if ($type -cne [string]$Entry.Type -or $actualJson -cne $expectedJson) {
                throw "SecurityBaseline value changed after backup: $Path::$Name"
            }
        }
    }

    $registryArtifact = Get-OneBaselineArtifact -Name 'RegistryPolicies'
    $registrySnapshot = Get-Content -LiteralPath $registryArtifact.BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$registrySnapshot.SchemaVersion -notin @(3, 4) -or
        [string]$registrySnapshot.UserRegistryRoot -notmatch '^HKU:\\S-1-(?:5-21|12-1)-[0-9-]+$' -or
        [int]$registrySnapshot.DirectiveCount -ne (
            @($registrySnapshot.Computer).Count + @($registrySnapshot.User).Count +
            @($registrySnapshot.ComputerClearKeys).Count + @($registrySnapshot.UserClearKeys).Count
        )) {
        throw 'SecurityBaseline RegistryPolicies artifact has an invalid schema or user root'
    }
    if ([int]$registrySnapshot.SchemaVersion -eq 4) {
        if (-not $registrySnapshot.PSObject.Properties['AbsentAncestorKeys']) {
            throw 'SecurityBaseline RegistryPolicies artifact has no absent-ancestor inventory'
        }
        foreach ($ancestorPath in @($registrySnapshot.AbsentAncestorKeys)) {
            if (Test-Path -LiteralPath ([string]$ancestorPath) -PathType Container -ErrorAction Stop) {
                throw "SecurityBaseline absent registry ancestor appeared after backup: $ancestorPath"
            }
        }
    }
    foreach ($scope in @('Computer', 'User')) {
        $hive = if ($scope -eq 'Computer') { 'HKLM:' } else { [string]$registrySnapshot.UserRegistryRoot }
        foreach ($entry in @($registrySnapshot.$scope)) {
            $relativePath = ([string]$entry.KeyName).Trim([char[]]@('[', ']'))
            Assert-RegistryValuePrestate -Entry $entry -Path "$hive\$relativePath" -Name ([string]$entry.ValueName) -BaselineType
        }
        $clearProperty = $scope + 'ClearKeys'
        foreach ($clearEntry in @($registrySnapshot.$clearProperty)) {
            $relativePath = ([string]$clearEntry.KeyName).Trim([char[]]@('[', ']'))
            $path = "$hive\$relativePath"
            $keyExists = Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop
            if ($keyExists -ne [bool]$clearEntry.KeyExisted) {
                throw "SecurityBaseline clear-key existence changed after backup: $path"
            }
            $expectedValues = @{}
            foreach ($valueEntry in @($clearEntry.Values)) {
                $name = [string]$valueEntry.Name
                if ($expectedValues.ContainsKey($name)) { throw "Duplicate clear-key value in artifact: $path::$name" }
                $expectedValues[$name] = $valueEntry
            }
            $actualNames = @()
            if ($keyExists) {
                $key = Get-Item -LiteralPath $path -ErrorAction Stop
                $actualNames = @($key.GetValueNames())
                foreach ($name in $actualNames) {
                    if (-not $expectedValues.ContainsKey([string]$name)) {
                        throw "SecurityBaseline clear-key value appeared after backup: $path::$name"
                    }
                    $entry = $expectedValues[[string]$name]
                    # The hashtable lookup is case-insensitive by design (duplicate
                    # detection must catch case-variant duplicates); casing drift is
                    # checked explicitly, matching Assert-RegistryValuePrestate.
                    if ([string]$entry.Name -cne [string]$name) {
                        throw "SecurityBaseline clear-key value-name casing changed after backup: $path::$name"
                    }
                    $actualType = ConvertTo-RegistryTypeString -Kind $key.GetValueKind([string]$name)
                    $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
                    $actualJson = ConvertTo-Json -InputObject @($key.GetValue(
                            [string]$name,
                            $null,
                            [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
                        )) -Compress -Depth 20
                    if ($actualType -cne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                        throw "SecurityBaseline clear-key value changed after backup: $path::$name"
                    }
                }
            }
            if ($actualNames.Count -ne $expectedValues.Count) {
                throw "SecurityBaseline clear-key value inventory changed after backup: $path"
            }
        }
    }

    $templateRegistryArtifact = Get-OneBaselineArtifact -Name 'SecurityTemplateRegistryState'
    $templateRegistry = Get-Content -LiteralPath $templateRegistryArtifact.BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$templateRegistry.SchemaVersion -notin @(2, 3) -or
        [int]$templateRegistry.TargetCount -ne @($templateRegistry.Values).Count) {
        throw 'Security-template registry artifact has an invalid schema or count'
    }
    if ([int]$templateRegistry.SchemaVersion -eq 3) {
        if (-not $templateRegistry.PSObject.Properties['AbsentAncestorKeys']) {
            throw 'Security-template registry artifact has no absent-ancestor inventory'
        }
        foreach ($ancestorPath in @($templateRegistry.AbsentAncestorKeys)) {
            if (Test-Path -LiteralPath ([string]$ancestorPath) -PathType Container -ErrorAction Stop) {
                throw "Security-template absent registry ancestor appeared after backup: $ancestorPath"
            }
        }
    }
    foreach ($entry in @($templateRegistry.Values)) {
        Assert-RegistryValuePrestate -Entry $entry -Path ([string]$entry.Path) -Name ([string]$entry.Name)
    }

    $uacArtifact = Get-OneBaselineArtifact -Name 'UACStandardUserElevation'
    $uac = Get-Content -LiteralPath $uacArtifact.BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$uac.SchemaVersion -notin @(2, 3) -or [string]$uac.Name -ne 'ConsentPromptBehaviorUser') {
        throw 'SecurityBaseline UAC artifact has an invalid schema or target'
    }
    if ([int]$uac.SchemaVersion -eq 3) {
        if (-not $uac.PSObject.Properties['AbsentAncestorKeys']) {
            throw 'SecurityBaseline UAC artifact has no absent-ancestor inventory'
        }
        foreach ($ancestorPath in @($uac.AbsentAncestorKeys)) {
            if (Test-Path -LiteralPath ([string]$ancestorPath) -PathType Container -ErrorAction Stop) {
                throw "UAC absent registry ancestor appeared after backup: $ancestorPath"
            }
        }
    }
    Assert-RegistryValuePrestate -Entry $uac -Path ([string]$uac.Path) -Name ([string]$uac.Name)

    $auditArtifact = Get-OneBaselineArtifact -Name 'AuditPolicies'
    $audit = Get-Content -LiteralPath $auditArtifact.BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$audit.SchemaVersion -ne 2 -or [int]$audit.PolicyCount -ne @($audit.Policies).Count) {
        throw 'SecurityBaseline audit-policy artifact has an invalid schema or count'
    }
    foreach ($policy in @($audit.Policies)) {
        $guid = [Guid]::Parse([string]$policy.SubcategoryGuid)
        $currentFlags = [uint32](Get-AuditPolicyState -SubcategoryGuid $guid)
        if ($currentFlags -ne [uint32]$policy.AuditingInformation) {
            throw "SecurityBaseline audit policy changed after backup: $guid"
        }
    }

    $securityTemplateArtifact = Get-OneBaselineArtifact -Name 'SecurityTemplate'
    $securityTemplateTargets = Join-Path $PSScriptRoot '..\ParsedSettings\SecurityTemplates.json'
    $tempTemplate = Join-Path $env:TEMP "NoID_SecurityTemplatePreApply_$([Guid]::NewGuid().ToString('N')).inf"
    try {
        $currentTemplate = Backup-SecurityTemplate -BackupPath $tempTemplate -SecurityTemplatePath $securityTemplateTargets
        if (-not $currentTemplate.Success) {
            throw "Security-template prestate re-export failed: $($currentTemplate.Errors -join '; ')"
        }
        $expectedHash = (Get-FileHash -LiteralPath $securityTemplateArtifact.BackupFile -Algorithm SHA256 -ErrorAction Stop).Hash
        $actualHash = (Get-FileHash -LiteralPath $tempTemplate -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($actualHash -cne $expectedHash) {
            throw 'Security-template System Access/Privilege Rights changed after backup'
        }
    }
    finally {
        Remove-Item -LiteralPath $tempTemplate -Force -ErrorAction SilentlyContinue
    }

    $taskArtifact = Get-OneBaselineArtifact -Name 'XboxTask'
    $savedTask = Get-Content -LiteralPath $taskArtifact.BackupFile -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$savedTask.SchemaVersion -ne 2 -or
        [string]$savedTask.TaskPath -ne '\Microsoft\XblGameSave\' -or
        [string]$savedTask.TaskName -ne 'XblGameSaveTask') {
        throw 'SecurityBaseline Xbox task artifact has an invalid schema or target'
    }
    $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object {
            [string]$_.TaskPath -eq [string]$savedTask.TaskPath -and
            [string]$_.TaskName -eq [string]$savedTask.TaskName
        })
    if (($tasks.Count -eq 1) -ne [bool]$savedTask.Exists) {
        throw 'SecurityBaseline Xbox task existence changed after backup'
    }
    if ($tasks.Count -gt 1) { throw 'SecurityBaseline Xbox task identity is ambiguous' }
    if ($tasks.Count -eq 1 -and
        ([string]$tasks[0].State -ne 'Disabled') -ne [bool]$savedTask.Enabled) {
        throw 'SecurityBaseline Xbox task enabled state changed after backup'
    }

    $null = Assert-SecurityBaselineServicePrestate -ServiceNamesWithSealedPrestate $serviceNamesInInventory
    return $true
}
