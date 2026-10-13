#Requires -Version 5.1

BeforeAll {
    $script:Repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    function Get-NoIDFunctionCallNames {
        param([string]$Path)
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
        if (@($parseErrors).Count -gt 0) { throw "Parse errors in $Path" }
        $functions = @{}
        foreach ($definition in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
            $functions[$definition.Name] = @($definition.Body.FindAll({
                        param($node) $node -is [System.Management.Automation.Language.CommandAst]
                    }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
        }
        return $functions
    }
}

Describe 'User-token worker processes load every helper they call' {
    It '<File> worker <Worker> needs Core/Runtime.ps1 exactly when it reaches the registry helpers' -TestCases @(
        @{ File = 'Modules/Privacy/Private/PrivacyWindowsSearch.ps1'; Worker = 'Invoke-PrivacyWindowsSearchWorker' }
        @{ File = 'Modules/Privacy/Private/PrivacyUserAppx.ps1'; Worker = 'Invoke-PrivacyUserAppxRemovalWorker' }
        @{ File = 'Modules/AdvancedSecurity/Private/AdvancedSecurityWinInet.ps1'; Worker = 'Invoke-AdvancedSecurityWinInetWorker' }
    ) {
        param($File, $Worker)
        $path = Join-Path $script:Repo $File
        $functions = Get-NoIDFunctionCallNames -Path $path
        $functions.ContainsKey($Worker) | Should -BeTrue

        # Follow calls to functions defined in the same file: that is all the
        # worker process has, because it dot-sources only this file.
        $reachable = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $pending = [System.Collections.Generic.Queue[string]]::new()
        $pending.Enqueue($Worker)
        while ($pending.Count -gt 0) {
            $name = $pending.Dequeue()
            if (-not $reachable.Add($name)) { continue }
            foreach ($called in $functions[$name]) {
                if ($functions.ContainsKey($called)) { $pending.Enqueue($called) }
            }
        }
        $usesRegistryHelpers = @($reachable | ForEach-Object { $functions[$_] } | Where-Object {
                $_ -in @('Test-NoIDRegistryKey', 'New-NoIDRegistryKey')
            }).Count -gt 0
        $source = Get-Content -LiteralPath $path -Raw -Encoding UTF8
        if ($usesRegistryHelpers) {
            $source = Get-Content -LiteralPath $path -Raw -Encoding UTF8
            $source | Should -Match "\. '\`$escapedRuntime'" -Because "$Worker runs in its own process and calls the Core/Runtime.ps1 registry helpers"
            # The runtime path the worker command receives must name the real file.
            $runtimeVariable = [regex]::Match($source, '(?m)^\$script:(?<name>\w+RuntimePath) = ').Groups['name'].Value
            $runtimeVariable | Should -Not -BeNullOrEmpty
            . $path
            $runtimePath = Get-Variable -Name $runtimeVariable -Scope Script -ValueOnly
            [System.IO.Path]::GetFullPath($runtimePath) |
                Should -Be ([System.IO.Path]::GetFullPath((Join-Path (Join-Path $script:Repo 'Core') 'Runtime.ps1')))
        }
    }
}

Describe 'User-worker exchange directory cleanup' {
    BeforeAll {
        . (Join-Path (Join-Path (Join-Path (Join-Path $script:Repo 'Modules') 'Privacy') 'Private') 'PrivacyWindowsSearch.ps1')
    }

    It 'removes only the two known worker files and then the empty directory' {
        $exchange = Join-Path $TestDrive ('exchange-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $exchange
        $result = Join-Path $exchange 'result.json'
        Set-Content -LiteralPath $result -Value '{}'
        Set-Content -LiteralPath ($result + '.tmp') -Value '{}'
        Remove-PrivacyWorkerExchangeDirectory -Path $exchange -ResultPath $result -Confirm:$false
        Test-Path -LiteralPath $exchange | Should -BeFalse
    }

    It 'refuses to delete unexpected content instead of deleting it recursively' {
        $exchange = Join-Path $TestDrive ('exchange-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $exchange
        $foreign = Join-Path $exchange 'foreign.txt'
        Set-Content -LiteralPath $foreign -Value 'keep'
        { Remove-PrivacyWorkerExchangeDirectory -Path $exchange -ResultPath (Join-Path $exchange 'result.json') -Confirm:$false } |
            Should -Throw
        Test-Path -LiteralPath $foreign | Should -BeTrue
    }

    It 'rejects a missing exchange directory before reading a worker result' {
        { Assert-PrivacyWorkerExchangeDirectory -Path (Join-Path $TestDrive 'absent-exchange') } |
            Should -Throw '*missing or was replaced by a reparse point*'
    }

    It 'removes a planted directory junction as a link only' -Skip:($env:OS -ne 'Windows_NT') {
        $target = Join-Path $TestDrive ('target-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $target
        Set-Content -LiteralPath (Join-Path $target 'precious.txt') -Value 'keep'
        $exchange = Join-Path $TestDrive ('exchange-' + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Junction -Path $exchange -Value $target
        { Remove-PrivacyWorkerExchangeDirectory -Path $exchange -ResultPath (Join-Path $exchange 'result.json') -Confirm:$false } |
            Should -Throw '*replaced by a reparse point*'
        Test-Path -LiteralPath $exchange | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $target 'precious.txt') | Should -BeTrue
        { Assert-PrivacyWorkerExchangeDirectory -Path $target } | Should -Not -Throw
    }
}
