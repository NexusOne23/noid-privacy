function Backup-UACStandardUserElevation {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    $result = [PSCustomObject]@{
        Success    = $false
        BackupPath = $BackupPath
        Errors     = @()
    }
    if (-not $PSCmdlet.ShouldProcess($BackupPath, 'Back up ConsentPromptBehaviorUser')) {
        return $result
    }

    $registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $valueName = 'ConsentPromptBehaviorUser'
    try {
        foreach ($requiredCommand in @('Get-RegistryHierarchyPrestate', 'Get-ExactRegistryValueName')) {
            if (-not (Get-Command $requiredCommand -ErrorAction SilentlyContinue)) {
                throw "Required registry hierarchy helper is unavailable: $requiredCommand"
            }
        }
        $absentAncestorKeys = @(Get-RegistryHierarchyPrestate `
                -TargetPath $registryPath -BoundaryPath 'HKLM:\SOFTWARE')
        $keyExisted = Test-Path -LiteralPath $registryPath
        $valueExisted = $false
        $value = $null
        $type = $null
        $originalName = $null

        if ($keyExisted) {
            $key = Get-Item -LiteralPath $registryPath -ErrorAction Stop
            $valueExisted = $key.GetValueNames() -contains $valueName
            if ($valueExisted) {
                $originalName = Get-ExactRegistryValueName -Key $key -Name $valueName
                $value = $key.GetValue($originalName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                $type = $key.GetValueKind($originalName).ToString()
            }
        }

        $data = [PSCustomObject]@{
            SchemaVersion = 3
            Path          = $registryPath
            Name          = $valueName
            OriginalName  = $originalName
            AbsentAncestorKeys = $absentAncestorKeys
            KeyExisted    = $keyExisted
            Exists        = $valueExisted
            Value         = $value
            Type          = $type
        }
        [System.IO.File]::WriteAllText(
            $BackupPath,
            ($data | ConvertTo-Json -Depth 5),
            [System.Text.UTF8Encoding]::new($false)
        )
        if (-not (Test-Path -LiteralPath $BackupPath -PathType Leaf)) {
            throw 'UAC backup artifact was not created'
        }
        $roundTrip = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop |
            ConvertFrom-Json -ErrorAction Stop
        if ([int]$roundTrip.SchemaVersion -ne 3 -or
            [string]$roundTrip.Path -cne $registryPath -or
            [string]$roundTrip.Name -cne $valueName -or
            @($roundTrip.AbsentAncestorKeys).Count -ne $absentAncestorKeys.Count -or
            $roundTrip.KeyExisted -isnot [bool] -or $roundTrip.Exists -isnot [bool] -or
            [bool]$roundTrip.KeyExisted -ne $keyExisted -or [bool]$roundTrip.Exists -ne $valueExisted -or
            ($valueExisted -and ([string]$roundTrip.OriginalName -cne $originalName -or
                    [string]$roundTrip.Type -cne $type -or
                    (ConvertTo-Json -InputObject $roundTrip.Value -Compress) -cne (ConvertTo-Json -InputObject $value -Compress))) -or
            (-not $valueExisted -and ($null -ne $roundTrip.OriginalName -or
                    $null -ne $roundTrip.Type -or $null -ne $roundTrip.Value))) {
            throw 'UAC backup failed round-trip validation'
        }
        $result.Success = $true
    }
    catch {
        $result.Errors += "ConsentPromptBehaviorUser backup failed: $($_.Exception.Message)"
    }
    return $result
}
