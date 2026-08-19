function Backup-SecurityTemplateRegistryState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SecurityTemplatePath,

        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeStandaloneDelta
    )

    $result = [PSCustomObject]@{
        Success    = $false
        BackupPath = $BackupPath
        Count      = 0
        Errors     = @()
    }
    if (-not $PSCmdlet.ShouldProcess($BackupPath, 'Back up security-template registry value states')) {
        return $result
    }

    try {
        foreach ($requiredCommand in @('Get-RegistryHierarchyPrestate', 'Get-ExactRegistryValueName')) {
            if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
                throw "Required registry hierarchy helper is unavailable: $requiredCommand"
            }
        }
        $template = Get-Content -LiteralPath $SecurityTemplatePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $targets = [System.Collections.Generic.List[object]]::new()
        foreach ($gpoProperty in $template.PSObject.Properties) {
            $gpo = $gpoProperty.Value
            if (-not ($gpo.PSObject.Properties.Name -contains 'Registry Values')) { continue }
            foreach ($setting in $gpo.'Registry Values'.PSObject.Properties) {
                if ($setting.Name -eq 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser') {
                    # Captured by the dedicated UAC artifact so the selected
                    # Strict/SecureDesktop deviation has one restore owner.
                    continue
                }
                if ($setting.Name -notmatch '^MACHINE\\(.+)\\([^\\]+)$') {
                    throw "Unsupported security-template registry target: $($setting.Name)"
                }
                $targets.Add([PSCustomObject]@{
                        Path = 'HKLM:\' + $Matches[1]
                        Name = $Matches[2]
                    })
            }
        }
        if ($IncludeStandaloneDelta) {
            $targets.Add([PSCustomObject]@{
                    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    Name = 'LocalAccountTokenFilterPolicy'
                })
        }

        $states = [System.Collections.Generic.List[object]]::new()
        $absentAncestorKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($target in @($targets | Sort-Object Path, Name -Unique)) {
            $boundaryPath = if ([string]$target.Path -match '(?i)^HKLM:\\SOFTWARE(?:\\|$)') {
                'HKLM:\SOFTWARE'
            }
            elseif ([string]$target.Path -match '(?i)^HKLM:\\SYSTEM(?:\\|$)') {
                'HKLM:\SYSTEM'
            }
            else {
                throw "Unsupported security-template registry hierarchy: $($target.Path)"
            }
            foreach ($ancestorPath in @(Get-RegistryHierarchyPrestate `
                        -TargetPath ([string]$target.Path) -BoundaryPath $boundaryPath)) {
                $null = $absentAncestorKeys.Add([string]$ancestorPath)
            }
            $keyExisted = Test-Path -LiteralPath $target.Path
            $exists = $false
            $value = $null
            $type = $null
            $originalName = $null
            if ($keyExisted) {
                $key = Get-Item -LiteralPath $target.Path -ErrorAction Stop
                $exists = $key.GetValueNames() -contains $target.Name
                if ($exists) {
                    $originalName = Get-ExactRegistryValueName -Key $key -Name ([string]$target.Name)
                    $value = $key.GetValue($originalName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                    $type = $key.GetValueKind($originalName).ToString()
                }
            }
            $states.Add([PSCustomObject]@{
                    Path       = $target.Path
                    Name       = $target.Name
                    OriginalName = $originalName
                    KeyExisted = $keyExisted
                    Exists     = $exists
                    Value      = $value
                    Type       = $type
                })
        }

        $artifact = [PSCustomObject]@{
            SchemaVersion = 3
            TargetCount   = $states.Count
            AbsentAncestorKeys = @($absentAncestorKeys | Sort-Object)
            Values        = @($states)
        }
        [System.IO.File]::WriteAllText(
            $BackupPath,
            ($artifact | ConvertTo-Json -Depth 10),
            [System.Text.UTF8Encoding]::new($false)
        )
        $result.Count = $states.Count
        $result.Success = ($states.Count -gt 0 -and (Test-Path -LiteralPath $BackupPath -PathType Leaf))
        if (-not $result.Success) { throw 'Security-template registry state artifact is empty or missing' }
        $roundTrip = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ([int]$roundTrip.SchemaVersion -ne 3 -or
            [int]$roundTrip.TargetCount -ne $states.Count -or
            @($roundTrip.AbsentAncestorKeys).Count -ne $absentAncestorKeys.Count -or
            @($roundTrip.Values).Count -ne $states.Count) {
            throw 'Security-template registry state failed round-trip completeness validation'
        }
    }
    catch {
        $result.Success = $false
        $result.Errors += "Security-template registry state backup failed: $($_.Exception.Message)"
    }
    return $result
}
