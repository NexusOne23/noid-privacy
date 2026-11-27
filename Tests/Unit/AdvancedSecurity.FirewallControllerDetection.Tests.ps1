#Requires -Version 5.1
BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/Get-FirewallControllerStatus.ps1')
    Set-Item -Path Function:Get-AdvancedSecurityInteractiveUser -Value { param([switch]$AllowNone); $null = $AllowNone }
    $script:DesktopHive = 'HKU:\S-1-5-21-1-2-3-1001'
}

Describe 'Firewall controller detection reads the signed-in user''s installs' {
    BeforeEach {
        Mock Get-Service { throw [Microsoft.PowerShell.Commands.ServiceCommandException]::new('not installed') }
        Mock Get-Process { throw [Microsoft.PowerShell.Commands.ProcessCommandException]::new('not running') }
        Mock Get-ItemProperty { @() }
    }

    It 'finds a per-user install in the desktop hive when the elevated HKCU is another account' {
        Mock Get-AdvancedSecurityInteractiveUser { [PSCustomObject]@{ HiveRoot = $script:DesktopHive } }
        Mock Get-ItemProperty -ParameterFilter { $Path -like "$script:DesktopHive\*" } {
            @([PSCustomObject]@{ DisplayName = 'Windows Firewall Control' })
        }
        $status = Get-FirewallControllerStatus
        $status.Detected | Should -BeTrue
        $status.Products | Should -Be @('Windows Firewall Control')
        $status.DetectionComplete | Should -BeTrue
        Should -Invoke Get-ItemProperty -Times 1 -Exactly -ParameterFilter { $Path -like 'HKCU:\*' }
    }

    It 'keeps the elevated HKCU and both machine roots when no desktop user is signed in' {
        Mock Get-AdvancedSecurityInteractiveUser { $null }
        $status = Get-FirewallControllerStatus
        $status.Detected | Should -BeFalse
        $status.DetectionComplete | Should -BeTrue
        Should -Invoke Get-ItemProperty -Times 3 -Exactly
    }

    It 'reports incomplete detection instead of failing when the desktop user cannot be resolved' {
        Mock Get-AdvancedSecurityInteractiveUser { throw 'Explorer owner is ambiguous' }
        $status = Get-FirewallControllerStatus
        $status.DetectionComplete | Should -BeFalse
        ($status.Errors -join ' ') | Should -Match 'Explorer owner is ambiguous'
        Should -Invoke Get-ItemProperty -Times 3 -Exactly
    }
}
