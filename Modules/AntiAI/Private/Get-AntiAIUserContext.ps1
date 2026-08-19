#Requires -Version 5.1

function Get-AntiAIUserContext {
    <#
    .SYNOPSIS
        Resolves the interactive user's loaded registry hive.

    .DESCRIPTION
        An over-the-shoulder UAC elevation can run this module as a different
        administrator account. In that case HKCU belongs to the administrator,
        not to the standard user who owns the desktop. This function binds the
        user-scoped AntiAI targets to the Explorer owner in the current Windows
        session and returns that user's HKEY_USERS root.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    if ($script:AntiAIUserContext) {
        return $script:AntiAIUserContext
    }

    $currentSessionId = [int][System.Diagnostics.Process]::GetCurrentProcess().SessionId
    $resolvedSid = $null
    $lastResolutionError = $null
    # Get-Process -IncludeUserName can silently omit Explorer when owner lookup
    # fails. Resolve the stable SID through Win32_Process.GetOwnerSid and retry
    # across a bounded Explorer restart race, matching the Privacy module's
    # authority path.
    foreach ($attempt in 1..3) {
        try {
            $explorers = @(Get-CimInstance -ClassName Win32_Process `
                    -Filter "Name = 'explorer.exe'" -ErrorAction Stop |
                Where-Object { [int]$_.SessionId -eq $currentSessionId })
            if ($explorers.Count -eq 0) {
                throw "No interactive Explorer process is available in Windows session $currentSessionId"
            }
            $sids = @($explorers | ForEach-Object {
                    $ownerSid = Invoke-CimMethod -InputObject $_ -MethodName GetOwnerSid -ErrorAction Stop
                    if ([uint32]$ownerSid.ReturnValue -ne 0 -or
                        [string]::IsNullOrWhiteSpace([string]$ownerSid.Sid)) {
                        throw "Explorer owner SID query failed with result $($ownerSid.ReturnValue)"
                    }
                    [string]$ownerSid.Sid
                } | Sort-Object -Unique)
            if ($sids.Count -ne 1) {
                throw "Interactive Explorer user identity is ambiguous in Windows session $currentSessionId"
            }
            $resolvedSid = [string]$sids[0]
            break
        }
        catch {
            $lastResolutionError = $_.Exception.Message
            if ($attempt -lt 3) { Start-Sleep -Milliseconds (200 * $attempt) }
        }
    }
    if ([string]::IsNullOrWhiteSpace($resolvedSid)) {
        throw "Unable to resolve the interactive Explorer user after 3 attempts: $lastResolutionError"
    }

    $sid = $resolvedSid
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

    $script:AntiAIUserContext = [PSCustomObject]@{
        Sid  = $sid
        Root = $root
    }
    return $script:AntiAIUserContext
}
