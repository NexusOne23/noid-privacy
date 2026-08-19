function Get-SealedAppliedAsrPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$SessionPath,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [array]$DeclaredRules
    )

    $resolvedSessionPath = [IO.Path]::GetFullPath($SessionPath)
    if (-not (Test-Path -LiteralPath $resolvedSessionPath -PathType Container)) {
        throw "Applied BAVR session does not exist: $resolvedSessionPath"
    }

    $manifestPath = Join-Path $resolvedSessionPath 'manifest.json'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Applied BAVR session manifest is missing: $manifestPath"
    }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$manifest.schemaVersion -ne 2) {
        throw "Applied BAVR session manifest schema is unsupported: $($manifest.schemaVersion)"
    }

    $asrModules = @($manifest.modules | Where-Object { [string]$_.name -ceq 'ASR' })
    if ($asrModules.Count -ne 1) {
        throw "Applied BAVR session must contain exactly one ASR module record; found $($asrModules.Count)"
    }
    $asrModule = $asrModules[0]
    if ([string]$asrModule.status -cne 'Success') {
        throw "Applied BAVR ASR module was not sealed as successful: $($asrModule.status)"
    }

    $artifacts = @($asrModule.artifacts | Where-Object {
            [string]$_.type -ceq 'ASR' -and
            [string]$_.name -ceq 'ASR_ActiveConfiguration' -and
            [string]$_.target -ceq 'DefenderASR'
        })
    if ($artifacts.Count -ne 1) {
        throw "Applied BAVR session must contain exactly one sealed ASR active-configuration artifact; found $($artifacts.Count)"
    }
    $artifact = $artifacts[0]
    if ([string]$artifact.relativePath -cne 'ASR\ASR_ActiveConfiguration.json') {
        throw "Applied BAVR ASR artifact has an unexpected relative path: $($artifact.relativePath)"
    }
    if ([string]$artifact.sha256 -cnotmatch '^[0-9a-f]{64}$') {
        throw 'Applied BAVR ASR artifact hash is missing or malformed'
    }

    $artifactPath = [IO.Path]::GetFullPath((Join-Path $resolvedSessionPath ([string]$artifact.relativePath)))
    $sessionPrefix = $resolvedSessionPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) +
        [IO.Path]::DirectorySeparatorChar
    if (-not $artifactPath.StartsWith($sessionPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Applied BAVR ASR artifact escapes the selected session directory'
    }
    if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
        throw "Applied BAVR ASR artifact is missing: $artifactPath"
    }
    $actualHash = (Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
    if ($actualHash -cne ([string]$artifact.sha256).ToLowerInvariant()) {
        throw 'Applied BAVR ASR artifact failed its manifest SHA-256 check'
    }

    $plan = Get-Content -LiteralPath $artifactPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([int]$plan.SchemaVersion -notin @(4, 5) -or
        [string]$plan.Target -cne 'WindowsClientDefenderASR' -or
        [string]$plan.PolicyPath -cne 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules') {
        throw 'Applied BAVR ASR artifact identity or schema is invalid'
    }

    $applicableRules = @($DeclaredRules | Where-Object {
            -not ($_.PSObject.Properties.Name -contains 'WindowsClientApplicable') -or
            [bool]$_.WindowsClientApplicable
        })
    $expectedIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($rule in $applicableRules) {
        $parsedId = [Guid]::Empty
        if (-not [Guid]::TryParse([string]$rule.GUID, [ref]$parsedId) -or
            -not $expectedIds.Add($parsedId.ToString('D'))) {
            throw "Declared ASR applicability inventory contains an invalid or duplicate GUID: $($rule.GUID)"
        }
    }

    $targets = @($plan.Targets)
    if ($targets.Count -ne $applicableRules.Count) {
        throw "Applied BAVR ASR target count does not match declared Windows-client scope: $($targets.Count)/$($applicableRules.Count)"
    }
    $actionMap = @{}
    foreach ($target in $targets) {
        $parsedId = [Guid]::Empty
        if (-not [Guid]::TryParse([string]$target.GUID, [ref]$parsedId)) {
            throw "Applied BAVR ASR target contains an invalid GUID: $($target.GUID)"
        }
        $normalizedId = $parsedId.ToString('D').ToLowerInvariant()
        if (-not $expectedIds.Contains($normalizedId)) {
            throw "Applied BAVR ASR target is outside the declared Windows-client scope: $normalizedId"
        }
        if ($actionMap.ContainsKey($normalizedId)) {
            throw "Applied BAVR ASR target is duplicated: $normalizedId"
        }
        $requestedAction = [int]$target.RequestedAction
        if ($requestedAction -notin @(0, 1, 2, 6)) {
            throw "Applied BAVR ASR target has an unsupported requested action: $normalizedId/$requestedAction"
        }
        $actionMap[$normalizedId] = $requestedAction
    }
    foreach ($expectedId in $expectedIds) {
        if (-not $actionMap.ContainsKey($expectedId.ToLowerInvariant())) {
            throw "Applied BAVR ASR plan is missing a declared Windows-client target: $expectedId"
        }
    }

    [PSCustomObject]@{
        SessionPath  = $resolvedSessionPath
        ArtifactPath = $artifactPath
        Targets      = $targets
        ActionMap    = $actionMap
    }
}
