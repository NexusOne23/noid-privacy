#Requires -Version 5.1

function Test-PrivacyRegistryValueMatch {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('DWord', 'QWord', 'String', 'ExpandString', 'MultiString', 'Binary')]
        [string]$Type,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Expected,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Actual
    )

    switch ($Type) {
        'DWord' { return $null -ne $Actual -and [int]$Actual -eq [int]$Expected }
        'QWord' { return $null -ne $Actual -and [long]$Actual -eq [long]$Expected }
        { $_ -in @('String', 'ExpandString') } {
            return $null -ne $Actual -and [string]$Actual -ceq [string]$Expected
        }
        'MultiString' {
            if ($Expected -isnot [string[]] -or $Actual -isnot [string[]]) { return $false }
            $expectedValues = [string[]]$Expected
            $actualValues = [string[]]$Actual
            if ($expectedValues.Count -ne $actualValues.Count) { return $false }
            for ($index = 0; $index -lt $expectedValues.Count; $index++) {
                if ([string]$expectedValues[$index] -cne [string]$actualValues[$index]) { return $false }
            }
            return $true
        }
        'Binary' {
            if ($Expected -isnot [byte[]] -or $Actual -isnot [byte[]]) { return $false }
            $expectedBytes = [byte[]]$Expected
            $actualBytes = [byte[]]$Actual
            if ($expectedBytes.Count -ne $actualBytes.Count) { return $false }
            for ($index = 0; $index -lt $expectedBytes.Count; $index++) {
                if ($expectedBytes[$index] -ne $actualBytes[$index]) { return $false }
            }
            return $true
        }
    }
    return $false
}

function Set-PrivacyRegistryTargets {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([int])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Snapshot
    )

    $null = Assert-PrivacyRegistrySnapshot -Snapshot $Snapshot
    if ([int]$Snapshot.SchemaVersion -ne 7) {
        throw 'Privacy Apply requires a decision-bound schema-7 snapshot'
    }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Apply $($Snapshot.TargetCount) sealed Privacy registry targets")) {
        return 0
    }

    # Preflight the UCPD-protected Widgets policy before the first mutation.
    # Backup normally classifies it NotApplicable while UCPD is active. This
    # second check closes the race where the driver starts after backup.
    $ucpdTarget = @($Snapshot.Entries | Where-Object {
            [string]$_.Path -ieq 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh' -and
            [string]$_.Name -ieq 'AllowNewsAndInterests'
        })
    if ($ucpdTarget.Count -gt 0) {
        $ucpd = Get-PrivacyUcpdProtectionState
        if (-not [bool]$ucpd.StateKnown -or [bool]$ucpd.Active) {
            throw 'Privacy Apply blocked before mutation because Windows UCPD now protects AllowNewsAndInterests'
        }
    }

    $written = 0
    foreach ($entry in @($Snapshot.Entries)) {
        $path = [string]$entry.Path
        $name = [string]$entry.Name
        $type = [string]$entry.ApplyType
        if (-not (Test-Path -LiteralPath $path -PathType Container)) {
            New-Item -Path $path -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        # Assign inside the switch instead of assigning the switch pipeline.
        # PowerShell enumerates collection output from a switch branch; an
        # intentionally empty string[] would therefore collapse to $null and
        # make post-write comparison report null versus the real empty
        # REG_MULTI_SZ. Direct assignment preserves the typed empty array.
        $value = $null
        switch ($type) {
            'DWord'       { $value = [int]$entry.ApplyValue }
            'QWord'       { $value = [long]$entry.ApplyValue }
            'Binary'      { $value = [byte[]]@($entry.ApplyValue) }
            'MultiString' { $value = [string[]]@($entry.ApplyValue) }
            default       { $value = [string]$entry.ApplyValue }
        }
        New-ItemProperty -LiteralPath $path -Name $name -PropertyType $type `
            -Value $value -Force -ErrorAction Stop | Out-Null

        $key = Get-Item -LiteralPath $path -ErrorAction Stop
        $actualType = $key.GetValueKind($name).ToString()
        $actual = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        if ($actualType -cne $type -or
            -not (Test-PrivacyRegistryValueMatch -Type $type -Expected $value -Actual $actual)) {
            throw "Privacy registry post-write mismatch: $path::$name"
        }
        $written++
    }
    if ($written -ne [int]$Snapshot.TargetCount) {
        throw "Privacy registry Apply count mismatch: expected $($Snapshot.TargetCount), wrote $written"
    }
    $null = Send-PrivacySearchPolicyChangeNotification -Entries @($Snapshot.Entries)

    # The documented WindowsSearch cmdlet is the native user surface which
    # makes the already-written BingSearchEnabled=0 preference visible to the
    # running Search UI immediately. Run it in the original Explorer token:
    # an elevated process can belong to a different administrator account.
    # The worker proves the call leaves the complete Search/SearchSettings
    # registry tree and every unrelated WindowsSearch API setting unchanged.
    $webSearchTargets = @($Snapshot.Entries | Where-Object {
            [string]$_.Path -match '(?i)\\Software\\Microsoft\\Windows\\CurrentVersion\\Search$' -and
            [string]$_.Name -ceq 'BingSearchEnabled'
        })
    if ($webSearchTargets.Count -ne 1 -or
        [string]$webSearchTargets[0].ApplyType -cne 'DWord' -or
        [int]$webSearchTargets[0].ApplyValue -ne 0) {
        throw 'Privacy Apply requires exactly one sealed BingSearchEnabled=0 target for native Search refresh'
    }
    $searchUser = Get-PrivacyUserContext -Refresh
    if ([string]$searchUser.Sid -cne [string]$Snapshot.InteractiveUserSid) {
        throw 'Interactive Privacy user changed before native WindowsSearch refresh'
    }
    $searchRefresh = Invoke-PrivacyWindowsSearchUserState `
        -User $searchUser `
        -Operation RefreshWebResults `
        -WebResultsEnabled:$false
    if (-not [bool]$searchRefresh.Success -or
        [bool]$searchRefresh.WebResultsEnabled -or
        -not [bool]$searchRefresh.RegistryStateUnchanged) {
        throw 'Native WindowsSearch refresh did not prove the sealed web-search state'
    }
    return $written
}
