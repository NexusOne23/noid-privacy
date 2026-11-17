#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $workflow = Get-Content -LiteralPath (Join-Path $repoRoot '.github/workflows/release-checksums.yml') -Raw -Encoding UTF8
    $resolver = [regex]::Match($workflow,
        '(?ms)^      - name: Resolve target tag\r?\n(?<step>.*?)(?=^      - name:)')
    if (-not $resolver.Success) { throw 'Release tag resolution step is missing' }
    $run = [regex]::Match($resolver.Groups['step'].Value, '(?ms)^        run: \|\r?\n(?<body>.*)')
    if (-not $run.Success) { throw 'Release tag resolution script is missing' }
    $script:TagResolverSource = [regex]::Replace($run.Groups['body'].Value, '(?m)^          ', '')

    function Invoke-TagResolverFixture {
        param([string]$Root, [string]$EventTag, [string]$InputTag)
        $scriptPath = Join-Path $Root 'resolve-tag.ps1'
        $outputPath = Join-Path $Root 'output.txt'
        # Model the runner's literal expression substitution, then execute the
        # real step. The step reads both tags from its environment, so no event
        # value may appear in the script source.
        $source = $script:TagResolverSource.Replace('${{ github.ref_name }}', $EventTag)
        $source = $source.Replace('${{ github.event.inputs.tag }}', $InputTag)
        $marker = (Join-Path $Root 'executed.txt').Replace("'", "''")
        $canaryFunction = 'function Write-NoIDCanary { [IO.File]::WriteAllText(''' + $marker + ''',''executed'') }'
        [IO.File]::WriteAllText($scriptPath, $canaryFunction + "`n" + $source + "`nexit 0`n",
            [Text.UTF8Encoding]::new($false))
        $previous = @{}
        foreach ($name in @('NOID_EVENT_TAG', 'NOID_INPUT_TAG', 'GITHUB_OUTPUT')) {
            $previous[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        }
        try {
            $env:NOID_EVENT_TAG = $EventTag
            $env:NOID_INPUT_TAG = $InputTag
            $env:GITHUB_OUTPUT = $outputPath
            & $scriptPath
            return $LASTEXITCODE
        }
        finally {
            foreach ($name in $previous.Keys) {
                [Environment]::SetEnvironmentVariable($name, $previous[$name], 'Process')
            }
        }
    }
}

Describe 'Release workflow input is data' {
    It 'resolves a valid <Kind> tag' -TestCases @(
        @{ Kind = 'push'; EventTag = 'v9.9.9'; InputTag = ''; Expected = 'v9.9.9' }
        @{ Kind = 'manual'; EventTag = 'main'; InputTag = 'v9.9.8'; Expected = 'v9.9.8' }
    ) {
        param($Kind, $EventTag, $InputTag, $Expected)
        $root = Join-Path $TestDrive $Kind
        $null = New-Item -ItemType Directory -Path $root
        Invoke-TagResolverFixture -Root $root -EventTag $EventTag -InputTag $InputTag | Should -Be 0
        (Get-Content -LiteralPath (Join-Path $root 'output.txt') -Raw).Trim() | Should -BeExactly "tag=$Expected"
    }

    It 'rejects executable syntax in the <Kind> tag without executing it' -TestCases @(
        @{ Kind = 'push' }
        @{ Kind = 'manual' }
    ) {
        param($Kind)
        $root = Join-Path $TestDrive "injection-$Kind"
        $null = New-Item -ItemType Directory -Path $root
        $marker = Join-Path $root 'executed.txt'
        # This payload is also a syntactically valid Git ref (no spaces, colon,
        # square brackets or other forbidden ref characters).
        $payload = 'v$(Write-NoIDCanary)9.9.9'
        $eventTag = if ($Kind -eq 'push') { $payload } else { 'main' }
        $inputTag = if ($Kind -eq 'manual') { $payload } else { '' }
        $result = Invoke-TagResolverFixture -Root $root -EventTag $eventTag -InputTag $inputTag
        Test-Path -LiteralPath $marker | Should -BeFalse
        $result | Should -Be 1
        Test-Path -LiteralPath (Join-Path $root 'output.txt') | Should -BeFalse
    }
}
