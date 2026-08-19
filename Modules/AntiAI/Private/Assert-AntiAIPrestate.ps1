#Requires -Version 5.1

function Assert-AntiAIPrestate {
    <#
    .SYNOPSIS
        Reconciles live AntiAI registry/URI state immediately before sealing.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        $Snapshot,

        [Parameter(Mandatory = $true)]
        [object[]]$UriSources
    )

    $null = Assert-AntiAIRegistrySnapshot -Snapshot $Snapshot
    foreach ($entry in @($Snapshot.Entries)) {
        $path = [string]$entry.Path
        $name = [string]$entry.Name
        $keyExists = Test-Path -LiteralPath $path -PathType Container -ErrorAction Stop
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
        if ($keyExists -ne [bool]$entry.KeyExisted -or
            $valueExists -ne [bool]$entry.Exists) {
            throw "AntiAI registry prestate existence changed during backup: $path::$name"
        }
        if ($valueExists) {
            $expectedJson = ConvertTo-Json -InputObject @($entry.Value) -Compress -Depth 20
            $actualJson = ConvertTo-Json -InputObject @($actualValue) -Compress -Depth 20
            if ($actualType -cne [string]$entry.Type -or $actualJson -cne $expectedJson) {
                throw "AntiAI registry prestate type/data changed during backup: $path::$name"
            }
        }
    }

    if ($UriSources.Count -ne 4) { throw 'AntiAI URI prestate requires exactly four source identities' }
    foreach ($source in $UriSources) {
        $artifacts = @($global:BackupIndex | Where-Object {
                [string]$_.Module -eq 'AntiAI' -and [string]$_.Name -eq [string]$source.Name
            })
        if ($artifacts.Count -ne 1 -or
            [string]$artifacts[0].Path -cne [string]$source.Path -or
            [string]$artifacts[0].Type -notin @('Registry', 'EmptyMarker')) {
            throw "AntiAI URI backup artifact is missing or ambiguous: $($source.Name)"
        }
        if ([string]$artifacts[0].Type -eq 'EmptyMarker') {
            if (Test-Path -LiteralPath $source.Path -ErrorAction Stop) {
                throw "AntiAI URI source appeared during backup: $($source.Path)"
            }
            continue
        }
        if (-not (Test-Path -LiteralPath $source.Path -PathType Container -ErrorAction Stop)) {
            throw "AntiAI URI source disappeared during backup: $($source.Path)"
        }

        $nativePath = ConvertTo-NativeRegistryPath -Path ([string]$source.Path)
        $operationId = [Guid]::NewGuid().ToString('N')
        $verificationFile = Join-Path $env:TEMP "NoID_AntiAI_URI_$operationId.reg"
        $stdoutFile = Join-Path $env:TEMP "NoID_AntiAI_URI_$operationId.out"
        $stderrFile = Join-Path $env:TEMP "NoID_AntiAI_URI_$operationId.err"
        try {
            $export = Start-Process -FilePath 'reg.exe' `
                -ArgumentList @('export', "`"$nativePath`"", "`"$verificationFile`"", '/y') `
                -Wait -NoNewWindow -PassThru -ErrorAction Stop `
                -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
            if ($export.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $verificationFile -PathType Leaf)) {
                $errorText = Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue
                throw "AntiAI URI reconciliation export failed with exit code $($export.ExitCode): $errorText"
            }
            $savedHash = (Get-FileHash -LiteralPath $artifacts[0].BackupFile -Algorithm SHA256 -ErrorAction Stop).Hash
            $liveHash = (Get-FileHash -LiteralPath $verificationFile -Algorithm SHA256 -ErrorAction Stop).Hash
            if ($savedHash -cne $liveHash) {
                throw "AntiAI URI source changed during backup: $($source.Path)"
            }
        }
        finally {
            Remove-Item -LiteralPath $verificationFile, $stdoutFile, $stderrFile -Force -ErrorAction SilentlyContinue
        }
    }
    return $true
}
