#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][switch]$ConfirmDisposableVm,
    [Parameter(Mandatory = $true)][string]$HistoricalBackupScriptPath,
    [string]$OutputPath = (Join-Path $PSScriptRoot '../Results/Windows11-SecurityTemplate-Compatibility.json')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $ConfirmDisposableVm -or $env:NOID_DISPOSABLE_VM -cne 'true' -or
    (Get-Process -Id $PID).SessionId -eq 0) {
    throw 'An elevated interactive disposable-VM session and explicit confirmation are required'
}
# The published v2.2.5 release and the earlier 2.2.5 build 4 contain this
# exact same writer.
$historicalHash = '4b22e15eedd8100ac05e0c3feda07366e4da920a33907173182d1c5947e79cd4'
if ((Get-FileHash -LiteralPath $HistoricalBackupScriptPath -Algorithm SHA256).Hash -ine $historicalHash) {
    throw 'Historical security-template writer does not match the original 2.2.5 source'
}
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. $HistoricalBackupScriptPath
. (Join-Path $repo 'Core/Rollback.ps1')
. (Join-Path $repo 'Modules/SecurityBaseline/Private/Restore-SecurityTemplate.ps1')
. (Join-Path $PSScriptRoot 'Windows11NativePolicyFingerprint.ps1')
Set-Item -Path Function:Write-Log -Value { param($Level, $Message, $Module) $null = $Level, $Message, $Module }

$id = [Guid]::NewGuid().ToString('N')
$temporaryDirectory = Join-Path $env:TEMP ('NoIDSecurityTemplateAudit_' + $id)
$canaryRoot = 'HKLM:\SOFTWARE\NoIDSecurityTemplateAudit_' + $id
$nativeCanary = 'MACHINE\SOFTWARE\NoIDSecurityTemplateAudit_' + $id + '\Canary'
$checks = [Collections.Generic.List[object]]::new()
$failure = $null
$sealedHash = $null
$temporaryDirectoryOwned = $false
$canaryOwned = $false

function Assert-CompatibilityCheck {
    param([string]$Name, [bool]$Passed)
    $checks.Add([pscustomobject]@{Name=$Name; Passed=$Passed})
    if (-not $Passed) { throw $Name }
}

function Get-NativePolicyHash {
    $state = Get-Windows11NativePolicyFingerprintState -TemporaryDirectory $temporaryDirectory
    $bytes = [Text.Encoding]::UTF8.GetBytes(($state | ConvertTo-Json -Depth 8 -Compress))
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return [Convert]::ToBase64String($hash.ComputeHash($bytes)) }
    finally { $hash.Dispose() }
}

try {
    $null = New-Item -ItemType Directory -Path $temporaryDirectory
    $temporaryDirectoryOwned = $true
    $null = New-Item -Path $canaryRoot
    $canaryOwned = $true
    $null = New-ItemProperty -LiteralPath $canaryRoot -Name Canary -PropertyType DWord -Value 1
    $before = Get-NativePolicyHash
    $backupPath = Join-Path $temporaryDirectory 'original-225.inf'
    $backup = Backup-SecurityTemplate -BackupPath $backupPath `
        -SecurityTemplatePath (Join-Path $repo 'Modules/SecurityBaseline/ParsedSettings/SecurityTemplates.json') -Confirm:$false
    Assert-CompatibilityCheck 'Original 2.2.5 writer creates a native filtered backup' ([bool]$backup.Success)
    $sealedHash = (Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash
    $artifact = [pscustomobject]@{type='SecurityBaseline'; name='SecurityTemplate'; target='SecurityTemplate'}
    Assert-ArtifactContentBinding -Artifact $artifact -ArtifactPath $backupPath
    Assert-CompatibilityCheck 'Current artifact reader accepts the unchanged historical backup' $true

    foreach ($iteration in 1..2) {
        $restored = Restore-SecurityTemplate -BackupPath $backupPath -Confirm:$false
        Assert-CompatibilityCheck "Historical template restores successfully, iteration $iteration" ([bool]$restored.Success)
        Assert-CompatibilityCheck "Independent native policies equal the prestate, iteration $iteration" ((Get-NativePolicyHash) -ceq $before)
        Assert-CompatibilityCheck "Sealed backup bytes are unchanged, iteration $iteration" ((Get-FileHash -LiteralPath $backupPath -Algorithm SHA256).Hash -ceq $sealedHash)
    }

    # Native positive controls use only a fresh test key. No real service,
    # privilege, account policy or existing registry key is placed in these INFs.
    foreach ($style in @('Ordinary', 'Indented')) {
        $header = if ($style -eq 'Ordinary') { '[Registry Values]' } else { '  [Registry Values]' }
        $fixture = Join-Path $temporaryDirectory ($style + '.inf')
        @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1',
            $header, ($nativeCanary + '=4,2')) | Set-Content -LiteralPath $fixture -Encoding Unicode
        Set-ItemProperty -LiteralPath $canaryRoot -Name Canary -Value 1
        $database = Join-Path $temporaryDirectory ($style + '.sdb')
        $nativeLog = Join-Path $temporaryDirectory ($style + '.log')
        $global:LASTEXITCODE = $null
        $null = & (Join-Path $env:SystemRoot 'System32/secedit.exe') /configure /db $database /cfg $fixture /log $nativeLog /quiet
        $nativeExitCode = $global:LASTEXITCODE
        Assert-CompatibilityCheck "Native $style registry-section control changes the dedicated canary" `
            ($null -ne $nativeExitCode -and $nativeExitCode -eq 0 -and (Get-ItemPropertyValue -LiteralPath $canaryRoot -Name Canary) -eq 2)
    }

    Set-ItemProperty -LiteralPath $canaryRoot -Name Canary -Value 1
    $poisonPath = Join-Path $temporaryDirectory 'foreign-section.inf'
    $poison = [IO.File]::ReadAllText($backupPath) + "`r`n  [Registry Values]`r`n" + $nativeCanary + '=4,2'
    [IO.File]::WriteAllText($poisonPath, $poison, [Text.Encoding]::Unicode)
    $rejected = $false
    try { Assert-ArtifactContentBinding -Artifact $artifact -ArtifactPath $poisonPath }
    catch { $rejected = $true }
    Assert-CompatibilityCheck 'Artifact binding rejects the indented foreign section' $rejected
    $rejected = $false
    try {
        $restored = Restore-SecurityTemplate -BackupPath $poisonPath -Confirm:$false -ErrorAction SilentlyContinue
        $rejected = -not [bool]$restored.Success
    }
    catch { $rejected = $true }
    Assert-CompatibilityCheck 'Direct restore rejects the indented foreign section' $rejected
    Assert-CompatibilityCheck 'Rejected native import preserves the dedicated canary' `
        ((Get-ItemPropertyValue -LiteralPath $canaryRoot -Name Canary) -eq 1)
    Assert-CompatibilityCheck 'Independent native policies remain unchanged after all controls' ((Get-NativePolicyHash) -ceq $before)
}
catch { $failure = $_.Exception.Message }
finally {
    if ($canaryOwned -and (Test-Path -LiteralPath $canaryRoot)) { Remove-Item -LiteralPath $canaryRoot -Recurse -Force }
    if ($temporaryDirectoryOwned -and (Test-Path -LiteralPath $temporaryDirectory)) { Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force }
    $outputFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $null = New-Item -ItemType Directory -Path (Split-Path $outputFile -Parent) -Force
    [ordered]@{
        Passed=($null -eq $failure); Checks=@($checks); Error=$failure
        HistoricalWriterSha256=$historicalHash; OriginalBackupSha256=$sealedHash
        CoreSha256=(Get-FileHash (Join-Path $repo 'Core/Rollback.ps1') -Algorithm SHA256).Hash
        ReaderSha256=(Get-FileHash (Join-Path $repo 'Modules/SecurityBaseline/Private/Get-SecurityTemplateBackupMap.ps1') -Algorithm SHA256).Hash
        RestoreSha256=(Get-FileHash (Join-Path $repo 'Modules/SecurityBaseline/Private/Restore-SecurityTemplate.ps1') -Algorithm SHA256).Hash
    } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $outputFile -Encoding UTF8
}
if ($null -ne $failure) { throw $failure }
