#Requires -Version 5.1

BeforeDiscovery {
    $script:RuntimeElevated = $false
    if ($env:OS -eq 'Windows_NT') {
        $script:RuntimeElevated = [Security.Principal.WindowsPrincipal]::new(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}

BeforeAll {
    $script:RuntimeRepo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $script:RuntimeRepo 'Core/Validator.ps1')
    Set-Item -Path function:Write-Log -Value {
        param($Level, $Message, $Module, $Exception)
        $null = $Level, $Message, $Module, $Exception
    }
}

Describe 'Native x86 startup rejection before machine-state processing' -Skip:($env:OS -ne 'Windows_NT') {
    It 'rejects <Label> at its entrypoint' -TestCases @(
        @{Label='CLI Apply';Entry='NoIDPrivacy.ps1';Extra=@('-Module','DNS','-DryRun','-ConfigPath','missing-runtime-fixture.json');Expected=2},
        @{Label='CLI Restore';Entry='NoIDPrivacy.ps1';Extra=@('-RestoreSessionPath','missing-session-fixture');Expected=2},
        @{Label='interactive menu';Entry='NoIDPrivacy-Interactive.ps1';Extra=@();Expected=1},
        @{Label='standalone verifier';Entry='Tools/Verify-Complete-Hardening.ps1';Extra=@();Expected=1}
    ) {
        param($Label, $Entry, $Extra, $Expected)
        $null = $Label
        $engine = Join-Path $env:SystemRoot 'SysWOW64/WindowsPowerShell/v1.0/powershell.exe'
        Test-Path -LiteralPath $engine -PathType Leaf | Should -BeTrue
        $arguments = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',
            (Join-Path $script:RuntimeRepo $Entry)) + $Extra
        $process = [Diagnostics.Process]::new()
        $process.StartInfo.FileName = $engine
        $process.StartInfo.Arguments = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
        $process.StartInfo.WorkingDirectory = $TestDrive
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        try {
            $process.Start() | Should -BeTrue
            $finished = $process.WaitForExit(30000)
            if (-not $finished) { $process.Kill(); $process.WaitForExit() }
            $output = $process.StandardOutput.ReadToEnd() + $process.StandardError.ReadToEnd()
            $finished | Should -BeTrue -Because 'startup must reject the host before any prompt or machine query'
            $process.ExitCode | Should -Be $Expected
            $output | Should -Match '64-bit Windows PowerShell 5.1 is required'
            $output | Should -Not -Match 'Loading NoID Privacy Framework|NOID_(RESULT|VERIFY)_JSON='
        }
        finally { $process.Dispose() }
    }
}

Describe 'Supported hardening and restore PowerShell runtime' {
    It 'classifies <Label> explicitly' -TestCases @(
        @{Label='Windows PowerShell 5.1 x64';Table=@{PSVersion=[version]'5.1';PSEdition='Desktop'};Bits64=$true;Expected=$true},
        @{Label='patched Windows PowerShell 5.1 x64';Table=@{PSVersion=[version]'5.1.26100.8737';PSEdition='Desktop'};Bits64=$true;Expected=$true},
        @{Label='Windows PowerShell 5.1 x86';Table=@{PSVersion=[version]'5.1';PSEdition='Desktop'};Bits64=$false;Expected=$false},
        @{Label='Windows PowerShell 5.0';Table=@{PSVersion=[version]'5.0';PSEdition='Desktop'};Bits64=$true;Expected=$false},
        @{Label='PowerShell 6';Table=@{PSVersion=[version]'6.0';PSEdition='Core'};Bits64=$true;Expected=$false},
        @{Label='PowerShell 7';Table=@{PSVersion=[version]'7.4.19';PSEdition='Core'};Bits64=$true;Expected=$false},
        @{Label='wrong edition with version 5.1';Table=@{PSVersion=[version]'5.1';PSEdition='Core'};Bits64=$true;Expected=$false},
        @{Label='new version with Desktop edition';Table=@{PSVersion=[version]'7.4';PSEdition='Desktop'};Bits64=$true;Expected=$false},
        @{Label='missing edition';Table=@{PSVersion=[version]'5.1'};Bits64=$true;Expected=$false},
        @{Label='missing version';Table=@{PSEdition='Desktop'};Bits64=$true;Expected=$false},
        @{Label='string version';Table=@{PSVersion='5.1';PSEdition='Desktop'};Bits64=$true;Expected=$false}
    ) {
        param($Label, $Table, $Bits64, $Expected)
        $null = $Label
        Test-NoIDPowerShellRuntime -VersionTable $Table -Is64BitProcess $Bits64 | Should -Be $Expected
    }

    It 'rejects an unsupported runtime before inspecting platform or registry state' {
        Mock Test-NoIDPowerShellRuntime { $false }
        Mock Test-IsAdministrator { throw 'Must reject runtime before platform queries' }
        Mock Get-WindowsVersion { throw 'Must reject runtime before registry queries' }
        Mock Get-SystemInfo { throw 'Must reject runtime before platform queries' }
        $result = Test-Prerequisites
        $result.Success | Should -BeFalse
        $result.Errors.Count | Should -Be 1
        $result.Errors[0] | Should -Match '64-bit Windows PowerShell 5.1'
        $result.SystemInfo | Should -BeNullOrEmpty
        Should -Invoke Get-WindowsVersion -Exactly 0
        Should -Invoke Get-SystemInfo -Exactly 0
        Should -Invoke Test-IsAdministrator -Exactly 0
    }
}

Describe 'Race-free registry key helpers' {
    BeforeAll {
        . (Join-Path $script:RuntimeRepo 'Core/Runtime.ps1')
    }

    It 'maps <Path> to <Hive> and <SubKey>' -TestCases @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft'; Hive = 'LocalMachine'; SubKey = 'SOFTWARE\Policies\Microsoft' }
        @{ Path = 'HKLM:\'; Hive = 'LocalMachine'; SubKey = '' }
        @{ Path = 'HKCU:\Software\NoID'; Hive = 'CurrentUser'; SubKey = 'Software\NoID' }
        @{ Path = 'HKU:\S-1-5-21-1-2-3-1001\Software'; Hive = 'Users'; SubKey = 'S-1-5-21-1-2-3-1001\Software' }
        @{ Path = 'Registry::HKEY_USERS\S-1-5-18'; Hive = 'Users'; SubKey = 'S-1-5-18' }
        @{ Path = 'Registry::HKLM\SYSTEM\\CurrentControlSet\'; Hive = 'LocalMachine'; SubKey = 'SYSTEM\CurrentControlSet' }
        @{ Path = 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE'; Hive = 'LocalMachine'; SubKey = 'SOFTWARE' }
    ) {
        param($Path, $Hive, $SubKey)
        $location = ConvertTo-NoIDRegistryLocation -LiteralPath $Path
        [string]$location.Hive | Should -BeExactly $Hive
        $location.SubKey | Should -BeExactly $SubKey
    }

    It 'rejects <Path> instead of guessing a hive' -TestCases @(
        @{ Path = 'C:\Windows' }
        @{ Path = 'HKXX:\Software' }
        @{ Path = 'Registry::HKEY_PERFORMANCE_DATA' }
        @{ Path = 'SOFTWARE\Policies' }
    ) {
        param($Path)
        $candidate = $Path
        { ConvertTo-NoIDRegistryLocation -LiteralPath $candidate } | Should -Throw '*Not a supported registry path*'
    }

    It 'uses native single-key lookups instead of the enumerating provider paths' {
        $source = Get-Content (Join-Path $script:RuntimeRepo 'Core/Runtime.ps1') -Raw -Encoding UTF8
        $source | Should -Match '\$baseKey\.OpenSubKey\(\$location\.SubKey, \$false\)'
        $source | Should -Match '\$baseKey\.CreateSubKey\(\$location\.SubKey, \$true\)'
        $hierarchy = Get-Content (Join-Path $script:RuntimeRepo 'Modules/SecurityBaseline/Private/Get-RegistryHierarchyPrestate.ps1') -Raw -Encoding UTF8
        $hierarchy | Should -Match 'Test-NoIDRegistryKey -LiteralPath \$cursor'
        $hierarchy | Should -Not -Match 'Test-Path[^\r\n]+-PathType Container'
    }

    Context 'Windows registry' -Skip:($env:OS -ne 'Windows_NT') {
        BeforeEach {
            $script:TestRoot = 'HKCU:\Software\NoIDPrivacy-RuntimeTest-' + [guid]::NewGuid().ToString('N')
        }
        AfterEach {
            if (Test-Path -LiteralPath $script:TestRoot) {
                Remove-Item -LiteralPath $script:TestRoot -Recurse -Force
            }
        }

        It 'creates a nested key atomically and reports existence exactly' {
            $nested = "$script:TestRoot\Level1\Level2"
            Test-NoIDRegistryKey -LiteralPath $nested | Should -BeFalse
            New-NoIDRegistryKey -LiteralPath $nested
            Test-NoIDRegistryKey -LiteralPath $nested | Should -BeTrue
            Test-NoIDRegistryKey -LiteralPath "$script:TestRoot\Level1" | Should -BeTrue
            Test-NoIDRegistryKey -LiteralPath "$script:TestRoot\Missing" | Should -BeFalse
            New-NoIDRegistryKey -LiteralPath $nested
            @(Get-ChildItem -LiteralPath "$script:TestRoot\Level1").Count | Should -Be 1
        }

        It 'honours WhatIf when creating a key' {
            $nested = "$script:TestRoot\WhatIf"
            New-NoIDRegistryKey -LiteralPath $nested -WhatIf
            Test-NoIDRegistryKey -LiteralPath $nested | Should -BeFalse
        }

        It 'answers for a missing key while sibling keys are created and deleted concurrently' {
            New-NoIDRegistryKey -LiteralPath $script:TestRoot
            $nativeRoot = $script:TestRoot.Substring(6)
            $churn = Start-Job -ScriptBlock {
                $root = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($using:nativeRoot, $true)
                $churnTimer = [Diagnostics.Stopwatch]::StartNew()
                while ($churnTimer.Elapsed.TotalSeconds -lt 6) {
                    foreach ($index in 0..6) {
                        $root.CreateSubKey("Sibling$index").Dispose()
                        $root.DeleteSubKey("Sibling$index", $false)
                    }
                }
                $root.Dispose()
            }
            try {
                Start-Sleep -Milliseconds 1500
                $errors = 0
                for ($index = 0; $index -lt 2000; $index++) {
                    try {
                        if (Test-NoIDRegistryKey -LiteralPath "$script:TestRoot\Missing\Child") { $errors++ }
                    }
                    catch { $errors++ }
                }
                $errors | Should -Be 0
            }
            finally {
                $null = Receive-Job -Job $churn -Wait -AutoRemoveJob
            }
        }
    }
}

Describe 'Protected policy registry keys' {
    BeforeAll {
        . (Join-Path $script:RuntimeRepo 'Core/Runtime.ps1')
        $script:DriverRanking = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking'
    }

    It 'classifies <Path> as protected=<Expected>' -TestCases @(
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking'; Expected = $true }
        @{ Path = 'HKLM:\software\policies\microsoft\windows nt\printers\driverranking'; Expected = $true }
        @{ Path = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking\'; Expected = $true }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers'; Expected = $false }
        @{ Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking\Child'; Expected = $false }
        @{ Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking'; Expected = $false }
        @{ Path = 'HKU:\S-1-5-21-1-2-3-1001\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DriverRanking'; Expected = $false }
    ) {
        param($Path, $Expected)
        Test-NoIDProtectedPolicyRegistryKey -LiteralPath $Path | Should -Be $Expected
    }

    It 'refuses keys outside the closed list and missing keys before any native call' {
        Mock Initialize-NoIDProtectedPolicyRegistry { throw 'native opener must not load' }
        { Open-NoIDProtectedPolicyRegistryKey -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft' } |
            Should -Throw '*Not a protected policy registry key*'
        Mock Test-NoIDRegistryKey { $false }
        { Open-NoIDProtectedPolicyRegistryKey -LiteralPath $script:DriverRanking } |
            Should -Throw '*Protected policy registry key does not exist*'
        Should -Invoke Initialize-NoIDProtectedPolicyRegistry -Times 0 -Exactly
    }

    It 'writes typed data through the opened key and always disposes it' {
        $script:ProtectedKey = [pscustomobject]@{ Calls = [Collections.Generic.List[string]]::new() }
        $script:ProtectedKey | Add-Member ScriptMethod SetValue {
            param($name, $value, $kind)
            $this.Calls.Add("set $name $($value.GetType().Name) $value $kind")
        }
        $script:ProtectedKey | Add-Member ScriptMethod DeleteValue {
            param($name, $throwOnMissing)
            $this.Calls.Add("delete $name $throwOnMissing")
        }
        $script:ProtectedKey | Add-Member ScriptMethod Dispose { $this.Calls.Add('dispose') }
        Mock Open-NoIDProtectedPolicyRegistryKey { $script:ProtectedKey }

        Set-NoIDProtectedPolicyRegistryValue -LiteralPath $script:DriverRanking -Name 'Policy' -Value 1 -Kind DWord
        Set-NoIDProtectedPolicyRegistryValue -LiteralPath $script:DriverRanking -Name 'Unsigned' -Value 4294967295 -Kind DWord
        Remove-NoIDProtectedPolicyRegistryValue -LiteralPath $script:DriverRanking -Name 'Policy'
        { Set-NoIDProtectedPolicyRegistryValue -LiteralPath $script:DriverRanking -Name 'Wide' -Value 4294967296 -Kind DWord } |
            Should -Throw '*REG_DWORD value is out of range*'

        @($script:ProtectedKey.Calls) | Should -Be @(
            'set Policy Int32 1 DWord', 'dispose',
            'set Unsigned Int32 -1 DWord', 'dispose',
            'delete Policy True', 'dispose'
        )
    }

    It 'honours WhatIf without opening the key' {
        Mock Open-NoIDProtectedPolicyRegistryKey { throw 'must not open' }
        Set-NoIDProtectedPolicyRegistryValue -LiteralPath $script:DriverRanking -Name 'Policy' -Value 1 -Kind DWord -WhatIf
        Remove-NoIDProtectedPolicyRegistryValue -LiteralPath $script:DriverRanking -Name 'Policy' -WhatIf
        Should -Invoke Open-NoIDProtectedPolicyRegistryKey -Times 0 -Exactly
    }

    It 'opens with backup/restore semantics and returns the restore privilege to its prior state' {
        $source = Get-Content (Join-Path $script:RuntimeRepo 'Core/Runtime.ps1') -Raw -Encoding UTF8
        $source | Should -Match 'REG_OPTION_BACKUP_RESTORE = 0x0004'
        $source | Should -Match '"SeRestorePrivilege"'
        $source | Should -Match 'Marshal\.GetLastWin32Error\(\) == ERROR_NOT_ALL_ASSIGNED'
        $source | Should -Match 'disposition != REG_OPENED_EXISTING_KEY'
        $source | Should -Match 'if \(previous\.PrivilegeCount == 1\)'
        $source | Should -Not -Match 'RegSetKeySecurity|SetAccessControl|Set-Acl|SeTakeOwnershipPrivilege'
    }

    Context 'Windows registry' -Skip:(-not $script:RuntimeElevated) {
        BeforeAll {
            # Get-Acl -LiteralPath does not resolve registry paths on Windows PowerShell 5.1.
            function Get-ProtectedTestSddl {
                $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:ProtectedSubKey,
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
                    [Security.AccessControl.RegistryRights]::ReadPermissions)
                try { return $key.GetAccessControl().GetSecurityDescriptorSddlForm('All') } finally { $key.Dispose() }
            }
        }

        BeforeEach {
            $script:ProtectedSubKey = 'SOFTWARE\NoIDPrivacy-RuntimeTest-' + [guid]::NewGuid().ToString('N')
            $script:ProtectedPath = "HKLM:\$script:ProtectedSubKey"
            New-NoIDRegistryKey -LiteralPath $script:ProtectedPath
            # Model the Windows DACL: SYSTEM full control, Administrators read only.
            $acl = [Security.AccessControl.RegistrySecurity]::new()
            $acl.SetAccessRuleProtection($true, $false)
            foreach ($rule in @(
                    @{ Sid = 'S-1-5-18'; Rights = [Security.AccessControl.RegistryRights]::FullControl }
                    @{ Sid = 'S-1-5-32-544'; Rights = [Security.AccessControl.RegistryRights]::ReadKey }
                )) {
                $acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new(
                        [Security.Principal.SecurityIdentifier]::new($rule.Sid), $rule.Rights,
                        [Security.AccessControl.InheritanceFlags]::ContainerInherit,
                        [Security.AccessControl.PropagationFlags]::None,
                        [Security.AccessControl.AccessControlType]::Allow))
            }
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:ProtectedSubKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [Security.AccessControl.RegistryRights]::ChangePermissions)
            try { $key.SetAccessControl($acl) } finally { $key.Dispose() }
            $script:ProtectedSddl = Get-ProtectedTestSddl
            $script:ProtectedSddl | Should -Match '^O:.*D:P'
        }
        AfterEach {
            # The owner (Administrators) keeps WRITE_DAC; reopen the key for cleanup.
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:ProtectedSubKey,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
                [Security.AccessControl.RegistryRights]::ChangePermissions -bor [Security.AccessControl.RegistryRights]::ReadPermissions)
            if ($null -ne $key) {
                try {
                    $acl = $key.GetAccessControl()
                    $acl.AddAccessRule([Security.AccessControl.RegistryAccessRule]::new(
                            [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'),
                            [Security.AccessControl.RegistryRights]::FullControl,
                            [Security.AccessControl.InheritanceFlags]::ContainerInherit,
                            [Security.AccessControl.PropagationFlags]::None,
                            [Security.AccessControl.AccessControlType]::Allow))
                    $key.SetAccessControl($acl)
                }
                finally { $key.Dispose() }
                [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($script:ProtectedSubKey, $false)
            }
        }

        It 'writes and deletes a value that the elevated token cannot write directly' {
            { [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($script:ProtectedSubKey, $true) } |
                Should -Throw
            $privilegeBefore = @(whoami.exe /priv /fo csv | Where-Object { $_ -match '"SeRestorePrivilege"' })
            Initialize-NoIDProtectedPolicyRegistry
            $key = [NoIDPrivacy.ProtectedPolicyRegistry]::OpenExistingLocalMachineKey($script:ProtectedSubKey)
            try { $key.SetValue('Probe', 7, [Microsoft.Win32.RegistryValueKind]::DWord) } finally { $key.Dispose() }
            (Get-ItemProperty -LiteralPath $script:ProtectedPath -Name Probe).Probe | Should -Be 7
            $key = [NoIDPrivacy.ProtectedPolicyRegistry]::OpenExistingLocalMachineKey($script:ProtectedSubKey)
            try { $key.DeleteValue('Probe', $true) } finally { $key.Dispose() }
            @((Get-Item -LiteralPath $script:ProtectedPath).GetValueNames()) | Should -Not -Contain 'Probe'
            Get-ProtectedTestSddl | Should -BeExactly $script:ProtectedSddl
            @(whoami.exe /priv /fo csv | Where-Object { $_ -match '"SeRestorePrivilege"' }) | Should -Be $privilegeBefore
        }
    }
}

Describe 'Interactive console detection for process exit codes' {
    BeforeAll {
        . (Join-Path $script:RuntimeRepo 'Core/Runtime.ps1')
    }

    It 'classifies <Label> as interactive=<Expected>' -TestCases @(
        @{ Label = 'plain console'; Arguments = @(); Expected = $true }
        @{ Label = 'console with profile options'; Arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass'); Expected = $true }
        @{ Label = '-File script'; Arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'NoIDPrivacy.ps1', '-Module', 'All'); Expected = $false }
        @{ Label = 'abbreviated -f'; Arguments = @('-f', 'NoIDPrivacy.ps1'); Expected = $false }
        @{ Label = '-Command'; Arguments = @('-NoProfile', '-Command', '& .\NoIDPrivacy.ps1'); Expected = $false }
        @{ Label = 'abbreviated -c'; Arguments = @('-c', 'exit 3'); Expected = $false }
        @{ Label = '-EncodedCommand'; Arguments = @('-NonInteractive', '-EncodedCommand', 'ZQB4AGkAdAA='); Expected = $false }
        @{ Label = 'positional command'; Arguments = @('.\NoIDPrivacy.ps1'); Expected = $false }
        @{ Label = 'standard input'; Arguments = @('-'); Expected = $false }
        @{ Label = '-NoExit with command'; Arguments = @('-NoExit', '-Command', '& .\NoIDPrivacy.ps1'); Expected = $true }
        @{ Label = 'abbreviated -noe'; Arguments = @('-noe', '-File', 'NoIDPrivacy.ps1'); Expected = $true }
        @{ Label = 'window style value is not a command'; Arguments = @('-WindowStyle', 'Hidden'); Expected = $true }
        @{ Label = '-File after NoExit-like argument'; Arguments = @('-File', 'x.ps1', '-NoExit'); Expected = $false }
    ) {
        param($Label, $Arguments, $Expected)
        $null = $Label
        Test-NoIDInteractiveConsoleSession -CommandLineArguments $Arguments | Should -Be $Expected
    }
}

Describe 'Local network connection probe' {
    BeforeAll {
        . (Join-Path $script:RuntimeRepo 'Core/Runtime.ps1')
        # Pester mocks need an existing command; Linux PowerShell has no NetTCPIP.
        if (-not (Get-Command Get-NetRoute -ErrorAction SilentlyContinue)) {
            function global:Get-NetRoute { [CmdletBinding()] param($PolicyStore) $null = $PolicyStore; throw 'Get-NetRoute stub was not mocked' }
        }
        if (-not (Get-Command Get-NetIPInterface -ErrorAction SilentlyContinue)) {
            function global:Get-NetIPInterface { [CmdletBinding()] param($InterfaceIndex, $AddressFamily) $null = $InterfaceIndex, $AddressFamily; throw 'Get-NetIPInterface stub was not mocked' }
        }
    }

    It 'reports <Label> as connected=<Expected>' -TestCases @(
        @{ Label = 'an IPv4 default route on a connected interface'; Routes = @(@{ Prefix = '0.0.0.0/0'; Index = 5; Family = 'IPv4' }); Connected = @(5); Expected = $true }
        @{ Label = 'an IPv6-only default route on a connected interface'; Routes = @(@{ Prefix = '::/0'; Index = 7; Family = 'IPv6' }); Connected = @(7); Expected = $true }
        @{ Label = 'a default route only on a disconnected interface'; Routes = @(@{ Prefix = '0.0.0.0/0'; Index = 5; Family = 'IPv4' }); Connected = @(); Expected = $false }
        @{ Label = 'only on-link routes (APIPA, cable unplugged)'; Routes = @(@{ Prefix = '169.254.0.0/16'; Index = 5; Family = 'IPv4' }, @{ Prefix = 'fe80::/64'; Index = 5; Family = 'IPv6' }); Connected = @(5); Expected = $false }
        @{ Label = 'an empty routing table'; Routes = @(); Connected = @(); Expected = $false }
    ) {
        param($Label, $Routes, $Connected, $Expected)
        $null = $Label
        $script:ProbeRoutes = @($Routes | ForEach-Object {
                [pscustomobject]@{ DestinationPrefix = $_.Prefix; InterfaceIndex = $_.Index; AddressFamily = $_.Family }
            })
        $script:ProbeConnected = @($Connected)
        Mock Get-NetRoute { $script:ProbeRoutes }
        Mock Get-NetIPInterface {
            [pscustomobject]@{
                # The real parameter is UInt32[]; Windows PowerShell 5.1 cannot cast
                # a typed array to [int], so read its single element.
                InterfaceIndex = @($InterfaceIndex)[0]
                ConnectionState = if ($script:ProbeConnected -contains [int]@($InterfaceIndex)[0]) { 'Connected' } else { 'Disconnected' }
            }
        }
        Test-NoIDNetworkConnection | Should -Be $Expected
        Should -Invoke Get-NetRoute -Times 1 -Exactly -ParameterFilter { $PolicyStore -eq 'ActiveStore' }
    }

    It 'treats an unreadable routing table as online so that network validation still runs' {
        Mock Get-NetRoute { throw 'NetTCPIP provider unavailable' }
        Test-NoIDNetworkConnection | Should -BeTrue
    }
}

Describe 'Race-free scheduled task helpers' {
    BeforeAll {
        . (Join-Path $script:RuntimeRepo 'Core/Runtime.ps1')
        # Pester mocks need an existing command; Linux PowerShell has no ScheduledTasks.
        if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            function global:Get-ScheduledTask { [CmdletBinding()] param([string]$TaskPath, [string]$TaskName) $null = $TaskPath, $TaskName; throw 'Get-ScheduledTask stub was not mocked' }
        }
        function script:New-TaskEnumerationRaceError {
            # The error Get-ScheduledTask reports when another program deletes a
            # task during its enumeration.
            [System.Management.Automation.ErrorRecord]::new(
                [Exception]::new('The system cannot find the file specified.'),
                'HRESULT 0x80070002,Get-ScheduledTask',
                [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
        }
    }

    It 'recognises HRESULT 0x80070002 by error ID or exception code' {
        Test-NoIDFileNotFoundError -ErrorRecord (New-TaskEnumerationRaceError) | Should -BeTrue
        $comMissing = [System.Management.Automation.ErrorRecord]::new(
            [IO.FileNotFoundException]::new('missing task'), 'System.IO.FileNotFoundException',
            [System.Management.Automation.ErrorCategory]::OperationStopped, $null)
        Test-NoIDFileNotFoundError -ErrorRecord $comMissing | Should -BeTrue
        $wrapped = [System.Management.Automation.ErrorRecord]::new(
            [Exception]::new('outer', [IO.FileNotFoundException]::new('inner')), 'Wrapped',
            [System.Management.Automation.ErrorCategory]::NotSpecified, $null)
        Test-NoIDFileNotFoundError -ErrorRecord $wrapped | Should -BeTrue
        $notFoundQuery = [System.Management.Automation.ErrorRecord]::new(
            [Exception]::new('No MSFT_ScheduledTask objects found'), 'CmdletizationQuery_NotFound_TaskName,Get-ScheduledTask',
            [System.Management.Automation.ErrorCategory]::ObjectNotFound, $null)
        Test-NoIDFileNotFoundError -ErrorRecord $notFoundQuery | Should -BeFalse
    }

    It 'repeats an enumeration that a concurrent task deletion broke and returns every task once' {
        $script:TaskQueries = 0
        Mock Start-Sleep {}
        Mock Get-ScheduledTask {
            $script:TaskQueries++
            [pscustomobject]@{ TaskPath = '\'; TaskName = "Partial$script:TaskQueries" }
            if ($script:TaskQueries -lt 3) { throw (New-TaskEnumerationRaceError) }
            [pscustomobject]@{ TaskPath = '\'; TaskName = 'Second' }
        }
        $tasks = @(Get-NoIDScheduledTask)
        $script:TaskQueries | Should -Be 3
        ($tasks.TaskName -join ',') | Should -BeExactly 'Partial3,Second'
    }

    It 'passes TaskPath and TaskName through and returns a single task unwrapped' {
        Mock Get-ScheduledTask { [pscustomobject]@{ TaskPath = $TaskPath; TaskName = $TaskName; State = 'Ready' } }
        $task = Get-NoIDScheduledTask -TaskPath '\Microsoft\Windows\NoID\' -TaskName 'Task'
        $task.TaskName | Should -BeExactly 'Task'
        Should -Invoke Get-ScheduledTask -Times 1 -Exactly -ParameterFilter {
            $TaskPath -ceq '\Microsoft\Windows\NoID\' -and $TaskName -ceq 'Task'
        }
    }

    It 'throws any other error at once' {
        Mock Start-Sleep {}
        Mock Get-ScheduledTask { throw 'Task Scheduler service unavailable' }
        { Get-NoIDScheduledTask } | Should -Throw '*service unavailable*'
        Should -Invoke Get-ScheduledTask -Times 1 -Exactly
    }

    It 'throws the race error after five attempts' {
        Mock Start-Sleep {}
        Mock Get-ScheduledTask { throw (New-TaskEnumerationRaceError) }
        { Get-NoIDScheduledTask } | Should -Throw '*cannot find the file*'
        Should -Invoke Get-ScheduledTask -Times 5 -Exactly
    }

    It 'leaves no name-based enumeration in the transient worker task lifecycles' {
        foreach ($relative in @(
                'Modules/Privacy/Private/PrivacyUserAppx.ps1',
                'Modules/Privacy/Private/PrivacyWindowsSearch.ps1',
                'Modules/AdvancedSecurity/Private/AdvancedSecurityWinInet.ps1')) {
            $source = Get-Content (Join-Path $script:RuntimeRepo $relative) -Raw -Encoding UTF8
            $source | Should -Match 'Get-NoIDScheduledTaskState -TaskName \$taskName'
            $source | Should -Match 'Unregister-NoIDScheduledTask -TaskName \$taskName -Confirm:\$false'
            $source | Should -Not -Match '(?m)^[^#\r\n]*\b(Get|Unregister)-ScheduledTask\b'
        }
    }

    Context 'Windows Task Scheduler' -Skip:(-not $script:RuntimeElevated) {
        It 'reads and deletes one task while other tasks are registered and deleted concurrently' {
            $taskName = 'NoIDPrivacy-RuntimeTest-' + [guid]::NewGuid().ToString('N')
            $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit 0'
            $null = Register-ScheduledTask -TaskName $taskName -Action $action -User 'SYSTEM' -Force
            $churn = Start-Job -ScriptBlock {
                $service = New-Object -ComObject 'Schedule.Service'
                $service.Connect()
                $root = $service.GetFolder('\')
                $definition = $service.NewTask(0)
                $churnAction = $definition.Actions.Create(0)
                $churnAction.Path = 'cmd.exe'
                $churnAction.Arguments = '/c exit 0'
                $churnTimer = [Diagnostics.Stopwatch]::StartNew()
                while ($churnTimer.Elapsed.TotalSeconds -lt 8) {
                    $name = 'NoIDPrivacy-RuntimeChurn-' + [guid]::NewGuid().ToString('N')
                    $null = $root.RegisterTask($name, $definition.XmlText, 6, 'SYSTEM', $null, 5)
                    $root.DeleteTask($name, 0)
                }
            }
            try {
                Start-Sleep -Milliseconds 1500
                $states = @(for ($index = 0; $index -lt 200; $index++) { Get-NoIDScheduledTaskState -TaskName $taskName })
                @($states | Where-Object { $_ -cne 'Ready' }).Count | Should -Be 0
                Unregister-NoIDScheduledTask -TaskName $taskName -Confirm:$false | Should -BeTrue
                Get-NoIDScheduledTaskState -TaskName $taskName | Should -BeNullOrEmpty
                Unregister-NoIDScheduledTask -TaskName $taskName -Confirm:$false | Should -BeFalse
            }
            finally {
                $null = Receive-Job -Job $churn -Wait -AutoRemoveJob
                $null = Unregister-NoIDScheduledTask -TaskName $taskName -Confirm:$false
            }
        }
    }
}
