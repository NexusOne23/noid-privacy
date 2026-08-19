#Requires -Version 5.1

# Restore can dot-source this helper directly through Core/Rollback without
# importing Privacy.psm1 first. Initialize the module cache in both paths so
# StrictMode never turns an absent cache variable into a restore failure.
if (-not (Get-Variable -Name PrivacyUserContext -Scope Script -ErrorAction SilentlyContinue)) {
    $script:PrivacyUserContext = $null
}

function Get-PrivacyCurrentProcessUserSid {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $sid = [string][Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    if ([string]::IsNullOrWhiteSpace($sid)) {
        throw 'The current process has no resolvable Windows user SID'
    }
    return $sid
}

function Get-PrivacyUserContext {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [switch]$Refresh,
        [switch]$AllowNone
    )

    if ($script:PrivacyUserContext -and -not $Refresh) { return $script:PrivacyUserContext }

    $sessionId = [int][System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $resolvedIdentity = $null
    $lastResolutionError = $null
    $lastAttemptHadNoExplorer = $false

    # Get-Process -IncludeUserName can omit Explorer when owner lookup fails.
    # Resolve account and SID through the Win32_Process owner methods, validate
    # their return codes, and tolerate a bounded Explorer restart race.
    foreach ($attempt in 1..3) {
        $lastAttemptHadNoExplorer = $false
        try {
            $explorers = @(Get-CimInstance -ClassName Win32_Process `
                    -Filter "Name = 'explorer.exe'" -ErrorAction Stop |
                Where-Object { [int]$_.SessionId -eq $sessionId })
            if ($explorers.Count -eq 0) {
                $lastAttemptHadNoExplorer = $true
                throw "No interactive Explorer process is available in Windows session $sessionId"
            }
            $identities = [Collections.Generic.List[object]]::new()
            foreach ($explorer in $explorers) {
                $ownerSid = Invoke-CimMethod -InputObject $explorer -MethodName GetOwnerSid -ErrorAction Stop
                if ([uint32]$ownerSid.ReturnValue -ne 0 -or
                    [string]::IsNullOrWhiteSpace([string]$ownerSid.Sid)) {
                    throw "Explorer owner SID query failed with result $($ownerSid.ReturnValue)"
                }
                $owner = Invoke-CimMethod -InputObject $explorer -MethodName GetOwner -ErrorAction Stop
                if ([uint32]$owner.ReturnValue -ne 0 -or
                    [string]::IsNullOrWhiteSpace([string]$owner.User)) {
                    throw "Explorer owner account query failed with result $($owner.ReturnValue)"
                }
                $account = if ([string]::IsNullOrWhiteSpace([string]$owner.Domain)) {
                    [string]$owner.User
                }
                else {
                    "$($owner.Domain)\$($owner.User)"
                }
                $identities.Add([PSCustomObject]@{
                        Account = $account
                        Sid = [string]$ownerSid.Sid
                    })
            }
            $accounts = @($identities | ForEach-Object { [string]$_.Account } | Sort-Object -Unique)
            $sids = @($identities | ForEach-Object { [string]$_.Sid } | Sort-Object -Unique)
            if ($accounts.Count -ne 1 -or $sids.Count -ne 1) {
                throw "Interactive Explorer user identity is ambiguous in Windows session $sessionId"
            }
            $resolvedIdentity = [PSCustomObject]@{Account=$accounts[0];Sid=$sids[0]}
            break
        }
        catch {
            $lastResolutionError = $_.Exception.Message
            if ($attempt -lt 3) { Start-Sleep -Milliseconds (200 * $attempt) }
        }
    }
    if ($null -eq $resolvedIdentity) {
        if ($AllowNone -and $lastAttemptHadNoExplorer) { return $null }
        throw "Unable to resolve the interactive Explorer user after 3 attempts: $lastResolutionError"
    }

    $sid = [string]$resolvedIdentity.Sid
    if ($sid -notmatch '^S-1-(5-21|12-1)-[0-9-]+$') {
        throw 'Interactive account SID is not a supported local/domain/Microsoft/Entra user SID'
    }
    if (-not (Get-PSDrive -Name HKU -ErrorAction SilentlyContinue)) {
        $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS -Scope Global -ErrorAction Stop
    }
    $root = "HKU:\$sid"
    if (-not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'The interactive user registry hive is not loaded'
    }

    $script:PrivacyUserContext = [PSCustomObject]@{
        Account = [string]$resolvedIdentity.Account
        Sid = $sid
        SessionId = [int]$sessionId
        Root = $root
    }
    return $script:PrivacyUserContext
}
