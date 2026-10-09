#Requires -Version 5.1

BeforeAll {
    $script:RepoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $script:FrameworkPath = Join-Path $script:RepoRoot 'Core/Framework.ps1'
    $script:RollbackPath = Join-Path $script:RepoRoot 'Core/Rollback.ps1'
    $script:ProductionModules = @(
        'SecurityBaseline'
        'ASR'
        'DNS'
        'Privacy'
        'AntiAI'
        'EdgeHardening'
        'AdvancedSecurity'
    )

    function Get-NoIDParsedAst {
        param([Parameter(Mandatory = $true)][string]$Path)

        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $Path,
            [ref]$tokens,
            [ref]$parseErrors
        )
        if (@($parseErrors).Count -gt 0) {
            throw "PowerShell parser errors in $Path"
        }
        return $ast
    }
}

Describe 'Framework imported-module dependency bridge' {
    It 'matches every direct Core or Utils dependency used by all seven modules exactly' {
        $frameworkAst = Get-NoIDParsedAst -Path $script:FrameworkPath
        $bridgeAssignment = @($frameworkAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                    $node.Left.Extent.Text -ceq '$script:NoIDModuleDependencyFunctionNames'
                }, $true))
        $bridgeAssignment.Count | Should -Be 1
        $actualBridgeNames = @($bridgeAssignment[0].Right.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
                }, $true) | ForEach-Object { [string]$_.Value }) | Sort-Object -Unique

        $coreFunctionNames = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        foreach ($supportDirectory in @('Core', 'Utils')) {
            foreach ($supportFile in Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot $supportDirectory) `
                    -Filter '*.ps1' -File -ErrorAction Stop) {
                $supportAst = Get-NoIDParsedAst -Path $supportFile.FullName
                foreach ($functionAst in $supportAst.FindAll({
                            param($node)
                            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
                        }, $true)) {
                    $null = $coreFunctionNames.Add([string]$functionAst.Name)
                }
            }
        }

        $expectedBridgeNames = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        foreach ($moduleName in $script:ProductionModules) {
            $moduleDirectory = Join-Path (Join-Path $script:RepoRoot 'Modules') $moduleName
            foreach ($moduleFile in Get-ChildItem -LiteralPath $moduleDirectory -File -Recurse -ErrorAction Stop |
                    Where-Object { $_.Extension -in @('.ps1', '.psm1') }) {
                $moduleAst = Get-NoIDParsedAst -Path $moduleFile.FullName
                foreach ($commandAst in $moduleAst.FindAll({
                            param($node)
                            $node -is [System.Management.Automation.Language.CommandAst]
                        }, $true)) {
                    $commandName = $commandAst.GetCommandName()
                    if ($commandName -and $coreFunctionNames.Contains($commandName)) {
                        $null = $expectedBridgeNames.Add($commandName)
                    }
                }
            }
        }

        $expected = @($expectedBridgeNames) | Sort-Object
        ($actualBridgeNames -join '|') | Should -BeExactly ($expected -join '|')
        $actualBridgeNames.Count | Should -BeGreaterThan 0 `
            -Because 'the bridge must remain derived from the current direct dependency graph instead of a stale hand-counted literal'

        $bridgeCalls = @($frameworkAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst] -and
                    $node.GetCommandName() -ceq 'Initialize-NoIDModuleDependencyBridge'
                }, $true))
        $bridgeCalls.Count | Should -Be 7
    }

    It 'binds helpers only into the imported module and preserves their source script scope' {
        $frameworkAst = Get-NoIDParsedAst -Path $script:FrameworkPath
        $bridgeFunction = @($frameworkAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq 'Initialize-NoIDModuleDependencyBridge'
                }, $true))
        $bridgeFunction.Count | Should -Be 1
        . ([ScriptBlock]::Create($bridgeFunction[0].Extent.Text))

        $script:NoIDModuleDependencyFunctionNames = @(
            'Get-NoIDBridgeProbeValue'
            'Write-NoIDBridgeProbeLog'
        )
        $script:NoIDBridgeProbeValue = 'source-script-scope'
        $script:NoIDBridgeProbeLog = @()
        function Get-NoIDBridgeProbeValue { return $script:NoIDBridgeProbeValue }
        function Write-NoIDBridgeProbeLog { param([string]$Message); $script:NoIDBridgeProbeLog += $Message }

        $probeModule = New-Module -Name 'NoIDDependencyBridgeProbe' -ScriptBlock {
            function Invoke-NoIDDependencyBridgeProbe {
                Write-NoIDBridgeProbeLog -Message 'module-called-helper'
                return Get-NoIDBridgeProbeValue
            }
            Export-ModuleMember -Function Invoke-NoIDDependencyBridgeProbe
        }
        try {
            & $probeModule { [bool](Get-Command Get-NoIDBridgeProbeValue -ErrorAction SilentlyContinue) } |
                Should -BeFalse

            Initialize-NoIDModuleDependencyBridge -ImportedModule $probeModule

            & $probeModule { [bool](Get-Command Get-NoIDBridgeProbeValue -CommandType Function -ErrorAction SilentlyContinue) } |
                Should -BeTrue
            & $probeModule { Invoke-NoIDDependencyBridgeProbe } | Should -BeExactly 'source-script-scope'
            @($script:NoIDBridgeProbeLog) | Should -Be @('module-called-helper')
            Test-Path Function:global:Get-NoIDBridgeProbeValue | Should -BeFalse
            Test-Path Function:global:Write-NoIDBridgeProbeLog | Should -BeFalse
        }
        finally {
            Remove-Module NoIDDependencyBridgeProbe -Force -ErrorAction SilentlyContinue
        }
    }

    It 'bridges the sealed AdvancedSecurity restore import before invoking module helpers' {
        $rollbackAst = Get-NoIDParsedAst -Path $script:RollbackPath
        $commands = @($rollbackAst.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.CommandAst]
                }, $true))
        $advancedImport = @($commands | Where-Object {
                $_.GetCommandName() -ceq 'Import-Module' -and
                $_.Extent.Text -match '\$advSecModulePath'
            })
        $restoreBridge = @($commands | Where-Object {
                $_.GetCommandName() -ceq 'Initialize-NoIDModuleDependencyBridge'
            })
        $advancedRestore = @($commands | Where-Object {
                $_.GetCommandName() -ceq 'Restore-AdvancedSecuritySettings'
            })

        $advancedImport.Count | Should -Be 1
        $restoreBridge.Count | Should -Be 1
        $advancedRestore.Count | Should -Be 1
        $restoreBridge[0].Extent.Text | Should -Match (
            '-ImportedModule\s+\(Get-Module\s+-Name\s+AdvancedSecurity\s+-ErrorAction\s+Stop\)'
        )
        $advancedImport[0].Extent.EndOffset | Should -BeLessThan $restoreBridge[0].Extent.StartOffset
        $restoreBridge[0].Extent.EndOffset | Should -BeLessThan $advancedRestore[0].Extent.StartOffset
    }
}
