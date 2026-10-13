#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Prove native registry restore compatibility with pinned historical writers.
.DESCRIPTION
    Run only on a disposable Windows VM in an interactive user session.
    Export disposable keys through original 2.2.5 code, restore with the current
    reader, independently compare type/data/subtrees, and repeat the restore.
    A native deletion canary proves rejection is tested against real reg.exe.
    This gate covers generic registry exports, not every module backup schema.
.PARAMETER HistoricalRollbackPath
    An unchanged Core/Rollback.ps1 from the published v2.2.5 release or from
    the earlier 2.2.5 build 4. The exact source hash is checked against both
    pinned originals before loading any historical code.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$HistoricalRollbackPath,
    [Parameter(Mandatory = $true)][switch]$ConfirmDisposableVm,
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\Results\Windows11-Registry-Compatibility.json')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ConfirmDisposableVm -or $env:NOID_DISPOSABLE_VM -ne 'true' -or
    [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
    throw 'Run this gate in an interactive disposable Windows VM with both explicit VM guards'
}
# Resolve operator paths once. .NET file APIs and child processes use the
# process working directory, which Windows PowerShell does not move with Set-Location.
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
$historicalHash = (Get-FileHash -LiteralPath $HistoricalRollbackPath -Algorithm SHA256).Hash.ToLowerInvariant()
$historicalVersions = @{
    'e190c7e91a0815d7323f885c2f36cf9f53553c828cc79d67ca276ff1fe42a2df' = '2.2.5'
    '938f1a2b02f611d21d93574d36186bb237322eb7047dccc05521ba694083a474' = '2.2.5-build4'
}
if (-not $historicalVersions.ContainsKey($historicalHash)) {
    throw 'Historical registry writer is not one of the pinned original sources'
}
$RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$historicalVersion = $historicalVersions[$historicalHash]
$results = [Collections.Generic.List[object]]::new()
$testId = [Guid]::NewGuid().ToString('N')
$relativeRoot = 'Software\NoIDRegistryArtifactAudit_' + $testId
$providerRoot = 'HKCU:\' + $relativeRoot
$target = $providerRoot + '\Target'
$targetNative = 'HKEY_CURRENT_USER\' + $relativeRoot + '\Target'
$canaryNative = 'HKEY_CURRENT_USER\' + $relativeRoot + '\ForeignCanary'
$evidence = Join-Path ([IO.Path]::GetTempPath()) ('NoIDRegistryArtifacts_' + $testId)
$regExe = Join-Path $env:SystemRoot 'System32\reg.exe'
$null = New-Item -ItemType Directory -Path $evidence

Set-Item -Path Function:Write-Log -Value { param($Level,$Message,$Module) $null=$Level,$Message,$Module }
function Write-ErrorLog { param($Message,$Module,$ErrorRecord) $null=$Message,$Module,$ErrorRecord }
function Assert-AuditCondition {
    param([string]$Name,[bool]$Passed)
    $results.Add([PSCustomObject]@{Name=$Name;Passed=$Passed})
    if (-not $Passed) { throw $Name }
}
function Get-AuditRegistryState {
    param([string]$RelativePath)
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RelativePath)
    if ($null -eq $key) { return '<absent>' }
    try {
        $values = foreach ($name in @($key.GetValueNames() | Sort-Object)) {
            [ordered]@{
                Name=$name
                Kind=$key.GetValueKind($name).ToString()
                Data=$key.GetValue($name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            }
        }
        $children = foreach ($child in @($key.GetSubKeyNames() | Sort-Object)) {
            [ordered]@{Name=$child;State=Get-AuditRegistryState ($RelativePath+'\'+$child)}
        }
        return ([ordered]@{Values=@($values);Children=@($children)} | ConvertTo-Json -Depth 20 -Compress)
    }
    finally { $key.Dispose() }
}

$failure = $null
try {
    $outputDirectory = Split-Path ([IO.Path]::GetFullPath($OutputPath)) -Parent
    $null = New-Item -ItemType Directory -Path $outputDirectory -Force
    . $HistoricalRollbackPath
    $historicalBackup = (Get-Command Backup-RegistryKey).ScriptBlock
    $historicalBinding = (Get-Command Assert-ArtifactContentBinding).ScriptBlock
    . (Join-Path $RepoRoot 'Core\Rollback.ps1')
    $global:BackupBasePath = $evidence
    $global:CurrentModule = ''
    $global:BackupIndex = @()

    $canaryPath = $providerRoot+'\ForeignCanary'
    $null = New-Item -Path $canaryPath -Force
    foreach ($fixtureProfile in @('Empty','TypedValues','CurrentHeaderText')) {
        $writerVersion = $historicalVersion
        $writer = $historicalBackup
        if ($fixtureProfile -eq 'CurrentHeaderText') {
            $writerVersion = 'current'
            $writer = (Get-Command Backup-RegistryKey).ScriptBlock
        }
        $key = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($relativeRoot+'\Target')
        try {
            if ($fixtureProfile -ne 'Empty') {
                $key.SetValue('', 'default', [Microsoft.Win32.RegistryValueKind]::String)
                $key.SetValue('text', ('Quoted " value '+[char]0x00e4+[char]0x4e2d), [Microsoft.Win32.RegistryValueKind]::String)
                $key.SetValue('multiline', "first`r`n[-$canaryNative]`nlast", [Microsoft.Win32.RegistryValueKind]::String)
                $key.SetValue('carriageReturn', "first`rlast", [Microsoft.Win32.RegistryValueKind]::String)
                $key.SetValue('quote\name', ('first\"' + "`nlast"), [Microsoft.Win32.RegistryValueKind]::String)
                if ($fixtureProfile -eq 'CurrentHeaderText') {
                    # Old positive-header validation rejected this native value.
                    # Prove the current writer separately; do not label it old.
                    $key.SetValue('positiveHeader', "first`n[$canaryNative]`nlast", [Microsoft.Win32.RegistryValueKind]::String)
                }
                $key.SetValue('dword', -1, [Microsoft.Win32.RegistryValueKind]::DWord)
                $key.SetValue('qword', [long]::MaxValue, [Microsoft.Win32.RegistryValueKind]::QWord)
                $key.SetValue('expanded', '%TEMP%\example', [Microsoft.Win32.RegistryValueKind]::ExpandString)
                $key.SetValue('binary', [byte[]](0..255), [Microsoft.Win32.RegistryValueKind]::Binary)
                $key.SetValue('multi', [string[]]@('first','second'), [Microsoft.Win32.RegistryValueKind]::MultiString)
                $child = $key.CreateSubKey('Child[1]')
                $child.SetValue('text','child',[Microsoft.Win32.RegistryValueKind]::String)
                $child.Dispose()
            }
        }
        finally { $key.Dispose() }
        $before = Get-AuditRegistryState ($relativeRoot+'\Target')
        $path = & $writer -KeyPath $target -BackupName $fixtureProfile
        Assert-AuditCondition "$writerVersion creates $fixtureProfile backup" (-not [string]::IsNullOrWhiteSpace([string]$path))
        $sealedHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $artifact = [PSCustomObject]@{type='Registry';target=$target}
        Assert-ArtifactContentBinding -Artifact $artifact -ArtifactPath $path
        Assert-AuditCondition "Current reader accepts $writerVersion $fixtureProfile export" $true
        Remove-Item -LiteralPath $target -Recurse -Force
        Assert-AuditCondition "Current reader restores $writerVersion $fixtureProfile export" (Restore-FromBackup -BackupFile $path -Type Registry -ExpectedTarget $target)
        Assert-AuditCondition "$fixtureProfile independent type/data/subtree comparison" ((Get-AuditRegistryState ($relativeRoot+'\Target')) -ceq $before)
        Assert-AuditCondition "$fixtureProfile repeat restore" (Restore-FromBackup -BackupFile $path -Type Registry -ExpectedTarget $target)
        Assert-AuditCondition "$fixtureProfile repeat independent comparison" ((Get-AuditRegistryState ($relativeRoot+'\Target')) -ceq $before)
        Assert-AuditCondition "$fixtureProfile preserves sealed backup bytes" ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ceq $sealedHash)
        Assert-AuditCondition "$fixtureProfile preserves foreign canary" (Test-Path -LiteralPath $canaryPath)
        Remove-Item -LiteralPath $target -Recurse -Force
    }

    $null = New-Item -Path $target -Force
    $poisonPath = Join-Path $evidence 'foreign-delete.reg'
    @('Windows Registry Editor Version 5.00','',('['+$targetNative+']'),'',('[-'+$canaryNative+']'),'') |
        Set-Content -LiteralPath $poisonPath -Encoding Unicode
    $artifact = [PSCustomObject]@{type='Registry';target=$target}
    & $historicalBinding -Artifact $artifact -ArtifactPath $poisonPath
    Assert-AuditCondition "Positive control: $historicalVersion validator overlooks foreign deletion" $true
    $nativeProcess = Start-Process -FilePath $regExe -ArgumentList @('import', ('"'+$poisonPath+'"')) -Wait -PassThru -NoNewWindow -RedirectStandardOutput (Join-Path $evidence 'native-import.stdout') -RedirectStandardError (Join-Path $evidence 'native-import.stderr')
    Assert-AuditCondition 'Positive control: native import deletes only the disposable canary' ($nativeProcess.ExitCode -eq 0 -and -not (Test-Path -LiteralPath $canaryPath))
    $null = New-Item -Path $canaryPath -Force
    $rejected = $false
    try { Assert-ArtifactContentBinding -Artifact $artifact -ArtifactPath $poisonPath }
    catch { $rejected = $true }
    Assert-AuditCondition 'Current artifact validation rejects foreign deletion' $rejected
    Assert-AuditCondition 'Current direct restore rejects foreign deletion' (-not (Restore-FromBackup -BackupFile $poisonPath -Type Registry -ExpectedTarget $target))
    Assert-AuditCondition 'Current restore preserves the independent foreign canary' (Test-Path -LiteralPath $canaryPath)
}
catch { $failure = $_.Exception.Message }
finally {
    if (Test-Path -LiteralPath $providerRoot) { Remove-Item -LiteralPath $providerRoot -Recurse -Force }
    [ordered]@{
        Passed=($null -eq $failure)
        HistoricalVersion=$historicalVersion
        CurrentVersion=(Get-Content -LiteralPath (Join-Path $RepoRoot 'VERSION') -Raw).Trim()
        PowerShell=$PSVersionTable.PSVersion.ToString()
        HistoricalSourceSha256=(Get-FileHash -LiteralPath $HistoricalRollbackPath -Algorithm SHA256).Hash
        CurrentSourceSha256=(Get-FileHash -LiteralPath (Join-Path $RepoRoot 'Core\Rollback.ps1') -Algorithm SHA256).Hash
        Checks=@($results)
        Error=$failure
    } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding UTF8
}
if ($failure) { throw $failure }
