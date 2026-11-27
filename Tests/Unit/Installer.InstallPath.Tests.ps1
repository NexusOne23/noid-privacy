#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $installer = Join-Path $repo 'install.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($installer, [ref]$tokens, [ref]$parseErrors)
    if (@($parseErrors).Count -gt 0) { throw 'install.ps1 does not parse' }
    $script:InstallerSource = Get-Content -LiteralPath $installer -Raw -Encoding UTF8
    foreach ($functionName in @('Test-SafeInstallPath', 'Get-InstallerLegacyProfilePaths')) {
        $definition = @($ast.FindAll({
                    param($node)
                    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                    $node.Name -ceq $functionName
                }, $true))
        if ($definition.Count -ne 1) { throw "$functionName definition not found" }
        . ([scriptblock]::Create($definition[0].Extent.Text))
    }
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

    It 'rejects installing into the elevated account profile when the signed-in desktop user differs' {
        $currentSid = [string][Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $otherDesktopSid = if ($currentSid -ceq 'S-1-5-21-1-2-3-1001') { 'S-1-5-21-1-2-3-1002' } else { 'S-1-5-21-1-2-3-1001' }
        Test-SafeInstallPath -Path (Join-Path $env:USERPROFILE 'NoIDPrivacy') -DesktopUserSid $otherDesktopSid |
            Should -BeFalse
        Test-SafeInstallPath -Path (Join-Path $env:ProgramFiles 'NoIDPrivacy') -DesktopUserSid $otherDesktopSid |
            Should -BeTrue
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

Describe 'Installer Administrator protection and module-path helpers' {
    It 'discovers earlier NoIDPrivacy folders across desktop and shadow profiles without duplicates' {
        $desktopProfile = Join-Path $TestDrive 'Users\Alex'
        $shadowProfile = Join-Path $TestDrive 'Users\ADMIN_Alex'
        $currentInstall = Join-Path $TestDrive 'ProgramFiles\NoIDPrivacy'
        foreach ($folder in @(
                (Join-Path $desktopProfile 'NoIDPrivacy'),
                (Join-Path $shadowProfile 'NoIDPrivacy'),
                $currentInstall
            )) {
            $null = New-Item -Path $folder -ItemType Directory -Force
            Set-Content -LiteralPath (Join-Path $folder 'NoIDPrivacy.ps1') -Value '# fixture' -Encoding UTF8
        }

        $legacyPaths = @(Get-InstallerLegacyProfilePaths -CurrentInstallPath $currentInstall `
            -ProfileRoots @($shadowProfile, $desktopProfile, $desktopProfile))

        $legacyPaths.Count | Should -Be 2
        $legacyPaths | Should -Contain ([IO.Path]::GetFullPath((Join-Path $desktopProfile 'NoIDPrivacy')))
        $legacyPaths | Should -Contain ([IO.Path]::GetFullPath((Join-Path $shadowProfile 'NoIDPrivacy')))
    }

    It 'sanitizes inherited PowerShell 7 PSModulePath before checksum and archive operations' {
        $initIndex = $script:InstallerSource.IndexOf('Initialize-InstallerPowerShellModulePath')
        $callIndex = $script:InstallerSource.IndexOf("`nInitialize-InstallerPowerShellModulePath")
        $hashIndex = $script:InstallerSource.IndexOf('Get-FileHash -LiteralPath $FilePath')
        $initIndex | Should -BeGreaterThan -1
        $callIndex | Should -BeGreaterThan $initIndex
        $hashIndex | Should -BeGreaterThan $callIndex
    }
}
