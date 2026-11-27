#Requires -Version 5.1
BeforeAll {
    $script:FrameworkRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $tokens = $null; $errors = $null
    $script:FrameworkAst = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $script:FrameworkRoot 'Core/Framework.ps1'), [ref]$tokens, [ref]$errors)
    if ($errors.Count) { throw 'Framework parse failed' }
    foreach ($name in @('Get-NoIDUserProfileFolders', 'Test-NoIDEngineLocation')) {
        $function = $script:FrameworkAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name }, $true)
        . ([scriptblock]::Create($function.Extent.Text))
    }
    Set-Item -Path Function:Write-Log -Value { param($Level, $Message, $Module); $null = $Level, $Message, $Module }
    $script:DesktopSid = 'S-1-5-21-1-2-3-1001'
    $script:HiddenAdminSid = 'S-1-5-21-1-2-3-1002'
    $script:Profiles = @(
        [PSCustomObject]@{ Sid = $script:DesktopSid; Path = 'C:\Users\Alex' }
        [PSCustomObject]@{ Sid = $script:HiddenAdminSid; Path = 'C:\Users\ADMIN_Alex' }
    )
}

Describe 'Engine location for the desktop account' {
    It 'refuses an engine in the hidden Administrator protection profile' {
        Test-NoIDEngineLocation -EngineRoot 'C:\Users\ADMIN_Alex\NoIDPrivacy' -DesktopSid $script:DesktopSid `
            -ProfileFolders $script:Profiles 6>$null | Should -BeFalse
    }

    It 'refuses an engine in the elevated process profile even when ProfileList omits the shadow account' {
        $desktopOnlyProfiles = @([PSCustomObject]@{ Sid = $script:DesktopSid; Path = 'C:\Users\Alex' })
        Test-NoIDEngineLocation -EngineRoot 'C:\Users\ADMIN_Alex\NoIDPrivacy' -DesktopSid $script:DesktopSid `
            -ProfileFolders $desktopOnlyProfiles -CurrentProcessSid $script:HiddenAdminSid `
            -CurrentUserProfile 'C:\Users\ADMIN_Alex' 6>$null | Should -BeFalse
    }

    It 'accepts <Root>' -TestCases @(
        @{ Root = 'C:\Program Files\NoIDPrivacy' }
        @{ Root = 'C:\Users\Alex\NoIDPrivacy' }
        @{ Root = 'C:\Users\Alex\Downloads\NoIDPrivacy-v2.3.3' }
        @{ Root = 'C:\Users\Public\NoIDPrivacy' }
        @{ Root = 'D:\Tools\NoIDPrivacy' }
    ) {
        param($Root)
        Test-NoIDEngineLocation -EngineRoot $Root -DesktopSid $script:DesktopSid -ProfileFolders $script:Profiles |
            Should -BeTrue
    }

    It 'does not mistake a profile whose name starts like the desktop profile for it' {
        $profiles = @($script:Profiles) + [PSCustomObject]@{ Sid = 'S-1-5-21-1-2-3-1003'; Path = 'C:\Users\Alex2' }
        Test-NoIDEngineLocation -EngineRoot 'C:\Users\Alex2\NoIDPrivacy' -DesktopSid $script:DesktopSid `
            -ProfileFolders $profiles 6>$null | Should -BeFalse
    }

    It 'leaves a run without a resolvable desktop account to the modules' {
        Test-NoIDEngineLocation -EngineRoot 'C:\Users\ADMIN_Alex\NoIDPrivacy' -DesktopSid $null `
            -ProfileFolders $script:Profiles | Should -BeTrue
    }

    It 'does not block when the profile list cannot be read' {
        Mock Get-NoIDUserProfileFolders { throw 'registry unavailable' }
        Test-NoIDEngineLocation -EngineRoot 'C:\Users\ADMIN_Alex\NoIDPrivacy' -DesktopSid $script:DesktopSid |
            Should -BeTrue
    }

    It 'is checked before any module runs' {
        $prerequisites = $script:FrameworkAst.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-FrameworkPrerequisites' }, $true)
        $prerequisites.Extent.Text | Should -Match 'Test-NoIDEngineLocation -EngineRoot \$script:FrameworkRoot'
    }
}
