#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $installer = Join-Path $repo 'install.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -gt 0) { throw 'install.ps1 does not parse' }
    $definition = @($ast.FindAll({
                param($node)
                $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq 'Test-SafeInstallPath'
            }, $true))
    if ($definition.Count -ne 1) { throw 'Test-SafeInstallPath definition not found' }
    . ([scriptblock]::Create($definition[0].Extent.Text))
    $script:ColorError = 'Red'
    function Write-ColorOutput { param($Message, $Color) $null = $Message, $Color }
}

Describe 'Installer destination safety' -Skip:($env:OS -ne 'Windows_NT') {
    It 'accepts <Label>' -TestCases @(
        @{ Label = 'the default profile folder'; Path = { Join-Path $env:USERPROFILE 'NoIDPrivacy' } }
        @{ Label = 'the dedicated Program Files folder'; Path = { Join-Path $env:ProgramFiles 'NoIDPrivacy' } }
    ) {
        param($Label, $Path)
        $null = $Label
        Test-SafeInstallPath -Path (& $Path) | Should -BeTrue
    }

    It 'rejects <Label>' -TestCases @(
        @{ Label = 'the Program Files root'; Path = { $env:ProgramFiles } }
        @{ Label = 'another Program Files product'; Path = { Join-Path $env:ProgramFiles 'Common Files' } }
        @{ Label = 'a nested Program Files folder'; Path = { Join-Path (Join-Path $env:ProgramFiles 'NoIDPrivacy') 'Nested' } }
        @{ Label = 'the Windows directory'; Path = { $env:WINDIR } }
        @{ Label = 'a drive root'; Path = { $env:SystemDrive + '\' } }
        @{ Label = 'the user profile root'; Path = { $env:USERPROFILE } }
    ) {
        param($Label, $Path)
        $null = $Label
        Test-SafeInstallPath -Path (& $Path) | Should -BeFalse
    }
}
