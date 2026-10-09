#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Core/Validator.ps1')
    Set-Item -Path function:Write-Log -Value {
        param($Level, $Message, $Module, $Exception)
        $null = $Level, $Message, $Module, $Exception
    }
    function ConvertTo-FolderSecurity {
        param([Parameter(Mandatory)][string]$Sddl)
        $security = [Security.AccessControl.DirectorySecurity]::new()
        $security.SetSecurityDescriptorSddlForm($Sddl)
        $security
    }
    function Get-AccountName {
        param([Parameter(Mandatory)][string]$Sid)
        [Security.Principal.SecurityIdentifier]::new($Sid).Translate([Security.Principal.NTAccount]).Value
    }
    # Windows 11 defaults as read from a 26H2 installation (Get-Acl .Sddl).
    # ProgramData: SYSTEM/Administrators (F), CREATOR OWNER (OI)(CI)(IO)(F),
    # Users (OI)(CI)(RX) and (CI)(WD,AD,WEA,WA).
    $script:ProgramDataDefault = 'O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)'
    # C:\ adds Authenticated Users (OI)(CI)(IO)(M) and (AD), and an app
    # capability with read access only.
    $script:DriveDefault = 'O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:SYD:PAI' +
        '(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)' +
        '(A;;0x1000a1;;;S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176)'
}

Describe 'Shared data folder replacement risk' {
    It 'reports nothing for the Windows default <Label> permissions' -TestCases @(
        @{Label='ProgramData'; Name='ProgramDataDefault'},
        @{Label='drive root'; Name='DriveDefault'}
    ) {
        param($Label, $Name)
        $null = $Label
        $security = ConvertTo-FolderSecurity -Sddl (Get-Variable -Name $Name -Scope Script -ValueOnly)
        @(Get-NoIDFolderReplacementRisk -Path 'C:\ProgramData' -Security $security).Count | Should -Be 0
    }

    It 'names the account and right of an added <Grant> grant' -TestCases @(
        @{Grant='Users Modify'; Ace='(A;OICI;0x1301bf;;;BU)'; Sid='S-1-5-32-545'; Rights='Modify'},
        @{Grant='Everyone full control'; Ace='(A;OICI;FA;;;WD)'; Sid='S-1-1-0'; Rights='FullControl'},
        @{Grant='GENERIC_ALL'; Ace='(A;;GA;;;AU)'; Sid='S-1-5-11'; Rights='FullControl'},
        @{Grant='delete-child'; Ace='(A;CI;0x40;;;BU)'; Sid='S-1-5-32-545'; Rights='DeleteSubdirectoriesAndFiles'}
    ) {
        param($Grant, $Ace, $Sid, $Rights)
        $null = $Grant
        $security = ConvertTo-FolderSecurity -Sddl ($script:ProgramDataDefault + $Ace)
        $finding = @(Get-NoIDFolderReplacementRisk -Path 'C:\ProgramData' -Security $security)
        $finding.Count | Should -Be 1
        $finding[0].Kind | Should -BeExactly 'Permission'
        $finding[0].Path | Should -BeExactly 'C:\ProgramData'
        $finding[0].Account | Should -BeExactly (Get-AccountName -Sid $Sid)
        $finding[0].Rights | Should -BeExactly $Rights
    }

    It 'merges several grants for one account into one finding' {
        $sid = 'S-1-5-21-1-2-3-1001'
        $security = ConvertTo-FolderSecurity -Sddl ($script:ProgramDataDefault + "(A;;0x10000;;;$sid)(A;;0xc0000;;;$sid)")
        $finding = @(Get-NoIDFolderReplacementRisk -Path 'C:\' -Security $security)
        $finding.Count | Should -Be 1
        # An unresolvable SID is reported as the SID itself.
        $finding[0].Account | Should -BeExactly $sid
        $finding[0].Rights | Should -BeExactly 'Delete, ChangePermissions, TakeOwnership'
    }

    It 'reports an owner outside SYSTEM, Administrators and TrustedInstaller' {
        $security = ConvertTo-FolderSecurity -Sddl ($script:ProgramDataDefault -replace '^O:SY', 'O:S-1-5-21-1-2-3-1001')
        $finding = @(Get-NoIDFolderReplacementRisk -Path 'C:\ProgramData' -Security $security)
        $finding.Count | Should -Be 1
        $finding[0].Kind | Should -BeExactly 'Owner'
        $finding[0].Account | Should -BeExactly 'S-1-5-21-1-2-3-1001'
    }

    It 'ignores deny, inherit-only and trusted grants' {
        $security = ConvertTo-FolderSecurity -Sddl ($script:ProgramDataDefault + '(D;OICI;FA;;;WD)(A;OICIIO;FA;;;BU)(A;OICI;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)')
        @(Get-NoIDFolderReplacementRisk -Path 'C:\ProgramData' -Security $security).Count | Should -Be 0
    }
}

Describe 'Shared data folder check in the prerequisites' {
    BeforeEach {
        Mock Assert-NoIDPowerShellRuntime {}
        Mock Test-IsAdministrator { $true }
        Mock Get-WindowsVersion { [pscustomobject]@{ IsSupported=$true; Version='fixture' } }
        Mock Get-AvailableDiskSpace { 10GB }
        Mock Get-SystemInfo { [pscustomobject]@{} }
        Mock Write-Log {}
    }

    It 'warns once per finding with folder, account and right, and never blocks' {
        Mock Get-NoIDSharedDataFolderRisk {
            [pscustomobject]@{ Path='C:\ProgramData'; Kind='Permission'; Account='BUILTIN\Users'; Rights='Modify' }
            [pscustomobject]@{ Path='C:\'; Kind='Owner'; Account='PC\user'; Rights='' }
        }
        $result = Test-Prerequisites
        $result.Success | Should -BeTrue
        $result.Warnings.Count | Should -Be 2
        $result.Warnings[0] | Should -BeExactly ('BUILTIN\Users can delete or replace items in C:\ProgramData (Modify). ' +
            'Programs that keep files under this folder can be tampered with by that account; NoID Privacy verifies its own files and is not affected.')
        $result.Warnings[1] | Should -BeExactly ('PC\user owns C:\ and can change its permissions. ' +
            'Programs that keep files under this folder can be tampered with by that account; NoID Privacy verifies its own files and is not affected.')
        Should -Invoke Write-Log -Exactly 2 -ParameterFilter { $Level -eq 'WARNING' -and $Module -eq 'Validator' }
    }

    It 'stays silent and passes when the permissions cannot be read' {
        Mock Get-NoIDSharedDataFolderRisk { throw 'fixture: access denied' }
        $result = Test-Prerequisites
        $result.Success | Should -BeTrue
        $result.Warnings.Count | Should -Be 0
        Should -Invoke Write-Log -Exactly 0 -ParameterFilter { $Level -eq 'WARNING' }
        Should -Invoke Write-Log -Exactly 1 -ParameterFilter { $Level -eq 'DEBUG' -and $Message -like '*fixture: access denied*' }
    }

    It 'reads ProgramData and every parent folder of this machine' -Skip:($env:OS -ne 'Windows_NT') {
        Mock Get-NoIDFolderReplacementRisk {}
        $null = @(Get-NoIDSharedDataFolderRisk)
        $programData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
        Should -Invoke Get-NoIDFolderReplacementRisk -Exactly 1 -ParameterFilter { $Path -eq $programData }
        Should -Invoke Get-NoIDFolderReplacementRisk -Exactly 1 -ParameterFilter { $Path -eq [IO.Path]::GetPathRoot($programData) }
    }
}
