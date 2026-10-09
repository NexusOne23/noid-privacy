#Requires -Version 5.1

# Registry policy readback is not an acknowledgement from the running Defender
# engine. A native preference change makes Defender consume the current policy.
# Keep that change inside one declared ASR target, under an equivalent policy
# value, and recover the exact local preference afterwards. A protected journal
# covers interruption between those calls; existing sealed backups stay intact.
if (-not (Get-Command Assert-NoIDIntentStateAcl -ErrorAction SilentlyContinue)) {
    . (Join-Path $PSScriptRoot 'IntentState.ps1')
}

function Get-NoIDAsrRuntimePath {
    [CmdletBinding()]
    [OutputType([string])]
    param([ValidateSet('Policy', 'Local', 'Journal')][string]$Kind)
    switch ($Kind) {
        'Policy' { 'SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' }
        'Local' { 'SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules' }
        'Journal' { Join-Path (Split-Path (Get-NoIDIntentStatePath) -Parent) 'asr-runtime-pending.json' }
    }
}

function Get-NoIDAsrRuntimeValue {
    [CmdletBinding()]
    param([ValidateSet('Policy', 'Local')][string]$Kind, [Parameter(Mandatory)][guid]$RuleId)
    $id = $RuleId.ToString('D')
    $state = [ordered]@{ KeyExisted=$false; Exists=$false; Name=$null; Kind=$null; Data=$null }
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey((Get-NoIDAsrRuntimePath $Kind), $false)
    if ($null -eq $key) { return [pscustomobject]$state }
    try {
        $state.KeyExisted = $true
        $names = @($key.GetValueNames() | Where-Object { $_.Equals($id, [StringComparison]::OrdinalIgnoreCase) })
        if ($names.Count -gt 1) { throw 'ASR runtime target has ambiguous registry identity' }
        if ($names.Count -eq 1) {
            $state.Exists = $true
            $state.Name = [string]$names[0]
            $state.Kind = $key.GetValueKind($state.Name).ToString()
            $state.Data = $key.GetValue($state.Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        }
    }
    finally { $key.Dispose() }
    return [pscustomobject]$state
}

function Test-NoIDAsrRuntimeValueEqual {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Left, [Parameter(Mandatory)]$Right, [switch]$IgnoreKeyExistence)
    if (-not $IgnoreKeyExistence -and $Left.KeyExisted -ne $Right.KeyExisted) { return $false }
    foreach ($name in @('Exists', 'Name', 'Kind', 'Data')) {
        if ((ConvertTo-Json -InputObject $Left.$name -Compress -Depth 4) -cne
            (ConvertTo-Json -InputObject $Right.$name -Compress -Depth 4)) { return $false }
    }
    return $true
}

function Get-NoIDAsrRuntimeMissingPolicyKeys {
    [CmdletBinding()]
    param()
    $path = Get-NoIDAsrRuntimePath Policy
    $missing = @()
    while ($path.Length -gt 'SOFTWARE\Policies'.Length) {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $false)
        if ($null -ne $key) { $key.Dispose(); break }
        $missing += $path
        $path = $path.Substring(0, $path.LastIndexOf('\'))
    }
    return $missing
}

function Assert-NoIDAsrRuntimeRecord {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)]$Record)
    $null = Assert-NoIDIntentExactProperties -Object $Record -Label 'ASR runtime recovery' -Expected @(
        'SchemaVersion', 'Target', 'RuleId', 'Policy', 'Local', 'MissingPolicyKeys', 'GuardAction', 'TemporaryAction', 'ContentSha256'
    )
    if ($Record.ContentSha256 -isnot [string] -or $Record.ContentSha256 -cnotmatch '\A[0-9a-f]{64}\z' -or
        (Get-NoIDAsrRuntimeRecordHash $Record) -cne $Record.ContentSha256) {
        throw 'ASR runtime recovery content hash differs'
    }
    $id = [guid]::Empty
    if ($Record.SchemaVersion -isnot [int] -or $Record.SchemaVersion -ne 1 -or
        $Record.Target -cne 'AsrPolicyRuntime' -or $Record.RuleId -isnot [string] -or
        -not [guid]::TryParseExact($Record.RuleId, 'D', [ref]$id) -or $id -eq [guid]::Empty -or
        $Record.RuleId -cne $id.ToString('D') -or
        $Record.GuardAction -isnot [int] -or $Record.GuardAction -notin @(0, 1, 2, 5, 6) -or
        $Record.TemporaryAction -isnot [int] -or $Record.TemporaryAction -notin @(1, 2)) {
        throw 'ASR runtime recovery has an invalid identity or action'
    }
    foreach ($layer in @('Policy', 'Local')) {
        $state = $Record.$layer
        $null = Assert-NoIDIntentExactProperties -Object $state -Label "ASR runtime $layer" -Expected @(
            'KeyExisted', 'Exists', 'Name', 'Kind', 'Data'
        )
        if ($state.KeyExisted -isnot [bool] -or $state.Exists -isnot [bool] -or
            ($state.Exists -and -not $state.KeyExisted)) { throw 'ASR runtime registry existence is invalid' }
        if (-not $state.Exists) {
            if ($null -ne $state.Name -or $null -ne $state.Kind -or $null -ne $state.Data) {
                throw 'ASR runtime absent value contains data'
            }
            continue
        }
        if ($state.Name -isnot [string] -or -not $state.Name.Equals($Record.RuleId, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'ASR runtime registry value is outside the recorded target'
        }
        if ($layer -eq 'Local') {
            if ($state.Kind -cne 'DWord' -or $state.Data -isnot [int] -or $state.Data -notin @(0, 1, 2, 5, 6) -or
                $state.Data -eq $Record.TemporaryAction) { throw 'ASR runtime local prestate is not safely replayable' }
        }
        else {
            switch -CaseSensitive ($state.Kind) {
                'String' { if ($state.Data -isnot [string]) { throw 'Invalid ASR policy string' } }
                'ExpandString' { if ($state.Data -isnot [string]) { throw 'Invalid ASR policy string' } }
                'DWord' { if ($state.Data -isnot [int]) { throw 'Invalid ASR policy DWord' } }
                'QWord' { if ($state.Data -isnot [int] -and $state.Data -isnot [long]) { throw 'Invalid ASR policy QWord' } }
                'MultiString' { foreach ($item in @($state.Data)) { if ($item -isnot [string]) { throw 'Invalid ASR policy string array' } } }
                'Binary' { foreach ($item in @($state.Data)) { if (($item -isnot [byte] -and $item -isnot [int]) -or $item -lt 0 -or $item -gt 255) { throw 'Invalid ASR policy bytes' } } }
                default { throw 'Unsupported ASR policy registry type' }
            }
        }
    }
    $expectedPath = Get-NoIDAsrRuntimePath Policy
    foreach ($path in @($Record.MissingPolicyKeys)) {
        if ($path -isnot [string] -or $path -cne $expectedPath -or $path.Length -le 'SOFTWARE\Policies'.Length) {
            throw 'ASR runtime recovery contains an invalid absent policy ancestor'
        }
        $expectedPath = $expectedPath.Substring(0, $expectedPath.LastIndexOf('\'))
    }
    if ($Record.Policy.KeyExisted -eq (@($Record.MissingPolicyKeys).Count -gt 0)) {
        throw 'ASR runtime policy key-existence inventory contradicts its target'
    }
    return $true
}

function Get-NoIDAsrRuntimeRecordHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record)
    $canonical = [ordered]@{}
    foreach ($name in @('SchemaVersion', 'Target', 'RuleId', 'Policy', 'Local', 'MissingPolicyKeys', 'GuardAction', 'TemporaryAction')) {
        $canonical[$name] = $Record.$name
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $canonical -Depth 8 -Compress))
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Read-NoIDAsrRuntimeRecord {
    [CmdletBinding()]
    param()
    $path = Get-NoIDAsrRuntimePath Journal
    if (-not (Test-Path -LiteralPath $path -ErrorAction Stop)) { return $null }
    $null = Assert-NoIDIntentStateAcl -StatePath $path
    if ((Get-Item -LiteralPath $path -Force -ErrorAction Stop).Length -gt 131072) {
        throw 'ASR runtime recovery record is too large'
    }
    $record = Get-Content -LiteralPath $path -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $null = Assert-NoIDAsrRuntimeRecord $record
    return $record
}

function Get-NoIDAsrRuntimeGuard {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Record)
    return [pscustomobject][ordered]@{
        KeyExisted=$true; Exists=$true
        Name=if ($Record.Policy.Exists) { $Record.Policy.Name } else { $Record.RuleId }
        Kind='String'; Data=([int]$Record.GuardAction).ToString([Globalization.CultureInfo]::InvariantCulture)
    }
}

function Write-NoIDAsrRuntimePolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$RuleId, [Parameter(Mandatory)]$State)
    # Internal primitive: the public caller owns confirmation and recovery.
    $path = Get-NoIDAsrRuntimePath Policy
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $true)
    try {
        if ($State.Exists) {
            if ($null -eq $key) { $key = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($path) }
            $data = switch ($State.Kind) {
                'Binary' { ,([byte[]]@($State.Data)) }
                'MultiString' { ,([string[]]@($State.Data)) }
                'DWord' { [int]$State.Data }
                'QWord' { [long]$State.Data }
                default { [string]$State.Data }
            }
            $key.SetValue($State.Name, $data, [Microsoft.Win32.RegistryValueKind]$State.Kind)
        }
        elseif ($null -ne $key) { $key.DeleteValue($RuleId.ToString('D'), $false) }
    }
    finally { if ($null -ne $key) { $key.Dispose() } }
}

function Restore-NoIDAsrRuntimeRecord {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Record)
    $null = Assert-NoIDAsrRuntimeRecord $Record
    $id = [guid]$Record.RuleId
    $local = Get-NoIDAsrRuntimeValue Local $id
    $policy = Get-NoIDAsrRuntimeValue Policy $id
    $guard = Get-NoIDAsrRuntimeGuard $Record
    $originalLocal = Test-NoIDAsrRuntimeValueEqual $local $Record.Local -IgnoreKeyExistence
    $temporaryLocal = $local.Exists -and $local.Kind -ceq 'DWord' -and [int]$local.Data -eq $Record.TemporaryAction
    $originalPolicy = Test-NoIDAsrRuntimeValueEqual $policy $Record.Policy -IgnoreKeyExistence
    if ((-not $originalLocal -and -not $temporaryLocal) -or
        (-not $originalPolicy -and -not (Test-NoIDAsrRuntimeValueEqual $policy $guard))) {
        throw 'ASR runtime target changed after preparation; later state has not been overwritten'
    }
    if (-not $PSCmdlet.ShouldProcess($Record.RuleId, 'Recover exact local ASR preference and temporary policy value')) { return }
    if (-not $originalLocal) {
        if ($Record.Local.Exists) {
            Add-MpPreference -AttackSurfaceReductionRules_Ids $Record.RuleId `
                -AttackSurfaceReductionRules_Actions ([int]$Record.Local.Data) -ErrorAction Stop | Out-Null
        }
        else {
            Remove-MpPreference -AttackSurfaceReductionRules_Ids $Record.RuleId -ErrorAction Stop | Out-Null
        }
    }
    if (-not $originalPolicy) { Write-NoIDAsrRuntimePolicy $id $Record.Policy }
    foreach ($path in @($Record.MissingPolicyKeys)) {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($path, $false)
        if ($null -eq $key) { continue }
        try {
            if ($key.ValueCount -ne 0 -or $key.SubKeyCount -ne 0) {
                throw 'A temporary ASR policy key contains later state; it has not been removed'
            }
        }
        finally { $key.Dispose() }
        [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKey($path, $false)
    }
    if (-not (Test-NoIDAsrRuntimeValueEqual (Get-NoIDAsrRuntimeValue Local $id) $Record.Local) -or
        -not (Test-NoIDAsrRuntimeValueEqual (Get-NoIDAsrRuntimeValue Policy $id) $Record.Policy)) {
        throw 'ASR runtime recovery did not reach its exact recorded prestate'
    }
    [IO.File]::Delete((Get-NoIDAsrRuntimePath Journal))
}

function Restore-NoIDPendingAsrRuntime {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    $mutex = Enter-NoIDAsrRuntimeMutation
    try {
        $record = Read-NoIDAsrRuntimeRecord
        if ($null -ne $record -and $PSCmdlet.ShouldProcess($record.RuleId, 'Complete interrupted ASR runtime recovery')) {
            Restore-NoIDAsrRuntimeRecord -Record $record -Confirm:$false
        }
    }
    finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
}

function Enter-NoIDAsrRuntimeMutation {
    [CmdletBinding()]
    [OutputType([Threading.Mutex])]
    param()
    $mutex = [Threading.Mutex]::new($false, 'Global\NoIDPrivacyAsrRuntimeV1')
    try {
        try { $held = $mutex.WaitOne(0, $false) }
        catch [Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'Another ASR runtime operation is already running' }
        return $mutex
    }
    catch { $mutex.Dispose(); throw }
}

function Sync-NoIDAsrPolicyRuntime {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][guid]$RuleId, [switch]$AllowStoppedDefender)
    if ($RuleId -eq [guid]::Empty) { throw 'ASR runtime synchronization requires a declared rule' }
    if (-not $PSCmdlet.ShouldProcess($RuleId, 'Notify Defender while preserving exact local ASR preferences')) { return }
    if ($AllowStoppedDefender -and (Get-Service -Name WinDefend -ErrorAction Stop).Status -eq 'Stopped') {
        # Baseline policy remains useful when a different antivirus owns the PC.
        # Do not start Defender or imply active ASR enforcement in that case.
        Write-Warning 'Defender is stopped. ASR policy is saved, but active ASR protection cannot be confirmed.'
        return
    }
    $mutex = Enter-NoIDAsrRuntimeMutation
    try { Invoke-NoIDAsrPolicyRuntime -RuleId $RuleId }
    finally { $mutex.ReleaseMutex(); $mutex.Dispose() }
}

function Invoke-NoIDAsrPolicyRuntime {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$RuleId)
    if ($null -ne (Read-NoIDAsrRuntimeRecord)) {
        throw 'Pending ASR runtime recovery must complete before changing policy'
    }
    $preference = Get-MpPreference -ErrorAction Stop
    $ids = @($preference.AttackSurfaceReductionRules_Ids)
    $actions = @($preference.AttackSurfaceReductionRules_Actions)
    if ($ids.Count -eq 1 -and $actions.Count -eq 1 -and
        $null -eq $ids[0] -and $null -eq $actions[0]) {
        $ids = @()
        $actions = @()
    }
    if ($ids.Count -ne $actions.Count) { throw 'Defender returned mismatched ASR arrays' }
    $ruleActions = @(for ($i = 0; $i -lt $ids.Count; $i++) {
            if (([guid]$ids[$i]) -eq $RuleId) { [int]$actions[$i] }
        })
    if ($ruleActions.Count -gt 1) { throw 'Defender returned duplicate ASR runtime targets' }
    $local = Get-NoIDAsrRuntimeValue Local $RuleId
    $record = [pscustomobject][ordered]@{
        SchemaVersion=1; Target='AsrPolicyRuntime'; RuleId=$RuleId.ToString('D')
        Policy=(Get-NoIDAsrRuntimeValue Policy $RuleId); Local=$local
        MissingPolicyKeys=@(Get-NoIDAsrRuntimeMissingPolicyKeys)
        GuardAction=if ($ruleActions.Count -eq 1) { $ruleActions[0] } else { 0 }
        TemporaryAction=if ($local.Exists -and [int]$local.Data -eq 1) { 2 } else { 1 }
        ContentSha256=''
    }
    $record.ContentSha256 = Get-NoIDAsrRuntimeRecordHash $record
    $json = ConvertTo-Json -InputObject $record -Depth 8
    if ([Text.Encoding]::UTF8.GetByteCount($json) -gt 131072) { throw 'ASR runtime recovery record is too large' }
    $null = Assert-NoIDAsrRuntimeRecord ($json | ConvertFrom-Json -ErrorAction Stop)
    # Defender owns this native store. Refuse an unsupported missing store
    # instead of creating persistent local key state outside the recovery scope.
    if (-not $local.KeyExisted) { throw 'The native Defender ASR preference store is unavailable' }
    $null = Initialize-NoIDIntentStateDirectory
    $path = Get-NoIDAsrRuntimePath Journal
    $staging = $path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    try {
        $stream = [IO.File]::Open($staging, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
        finally { $stream.Dispose() }
        Set-NoIDIntentPathSecurity -Path $staging -IsDirectory $false
        $null = Assert-NoIDIntentStateAcl -StatePath $staging
        [IO.File]::Move($staging, $path)
    }
    finally { if ([IO.File]::Exists($staging)) { [IO.File]::Delete($staging) } }
    $published = Read-NoIDAsrRuntimeRecord
    if ((ConvertTo-Json $published -Depth 8 -Compress) -cne (ConvertTo-Json $record -Depth 8 -Compress)) {
        throw 'ASR runtime recovery publication differs from its prepared state'
    }
    $mutationStarted = $false
    try {
        if (-not (Test-NoIDAsrRuntimeValueEqual (Get-NoIDAsrRuntimeValue Local $RuleId) $record.Local) -or
            -not (Test-NoIDAsrRuntimeValueEqual (Get-NoIDAsrRuntimeValue Policy $RuleId) $record.Policy)) {
            throw 'ASR runtime target changed during preparation'
        }
        $guard = Get-NoIDAsrRuntimeGuard $record
        $mutationStarted = $true
        if (-not (Test-NoIDAsrRuntimeValueEqual $record.Policy $guard)) {
            Write-NoIDAsrRuntimePolicy $RuleId $guard
        }
        Add-MpPreference -AttackSurfaceReductionRules_Ids $record.RuleId `
            -AttackSurfaceReductionRules_Actions ([int]$record.TemporaryAction) -ErrorAction Stop | Out-Null
        $actual = Get-NoIDAsrRuntimeValue Local $RuleId
        if (-not $actual.Exists -or $actual.Kind -cne 'DWord' -or [int]$actual.Data -ne $record.TemporaryAction) {
            throw 'Defender did not accept the scoped native ASR operation'
        }
    }
    finally {
        if ($mutationStarted) { Restore-NoIDAsrRuntimeRecord -Record $record -Confirm:$false }
        else { [IO.File]::Delete($path) }
    }
    # Defender publishes its runtime configuration asynchronously after the
    # native call. Let that notification settle before the caller's independent
    # full-map readback and completion result.
    Start-Sleep -Milliseconds 1000
}
