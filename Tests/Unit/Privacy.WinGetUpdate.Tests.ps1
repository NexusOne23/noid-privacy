#Requires -Version 5.1

BeforeAll {
    $repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    Import-Module (Join-Path $repo 'Modules/Privacy/Privacy.psm1') -Force
    InModuleScope Privacy {
        function script:Write-Log { param($Level,$Message,$Module) $null=$Level,$Message,$Module }
    }
}
AfterAll { Remove-Module Privacy -Force }

Describe 'Privacy updates App Installer without an administrator-only dependency installer' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        InModuleScope Privacy {
            $script:UpdatePath=Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\winget.exe'
            $script:InstallerVersion='1.21.10120.0'
            $script:InstallerFamily='Microsoft.DesktopAppInstaller_8wekyb3d8bbwe'
            $script:AdvanceVersion=$true; $script:NewClientExit=0; $script:NewerDependency=$false
            Mock Get-AppxPackage {
                if($Name -ceq 'Microsoft.DesktopAppInstaller') {
                    return [pscustomobject]@{Name=$Name;PackageFamilyName=$script:InstallerFamily;Version=$script:InstallerVersion;InstallLocation='C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_Test'}
                }
                if($script:NewerDependency -and $Name -ceq 'Microsoft.VCLibs.140.00') {
                    return [pscustomobject]@{Name=$Name;Architecture='X64';Version='14.0.40000.0'}
                }
            }
            Mock Get-PrivacyWinGetReleaseFile {
                if($Path.EndsWith('.msixbundle')) { [IO.File]::WriteAllText($Path,'package fixture'); return }
                Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
                $zip=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
                try {
                    foreach($entry in @('x64/Microsoft.VCLibs.140.00_14.0.33519.0_x64.appx','x64/Microsoft.VCLibs.140.00.UWPDesktop_14.0.33728.0_x64.appx','x64/Microsoft.WindowsAppRuntime.1.8_8000.616.304.0_x64.appx')) {
                        $stream=$zip.CreateEntry($entry).Open()
                        try{$stream.WriteByte(42)}finally{$stream.Dispose()}
                    }
                    $null=$zip.CreateEntry('../../must-not-extract.txt')
                } finally { $zip.Dispose() }
            }
            Mock Add-AppxPackage {
                foreach($dependency in $DependencyPath) {
                    if(-not [IO.File]::Exists($dependency) -or -not $dependency.EndsWith('_x64.appx')) { throw 'Unexpected dependency payload' }
                }
                if($script:AdvanceVersion) { $script:InstallerVersion='1.29.290.0' }
            }
            Mock Invoke-PrivacyBoundedProcess { $script:NewClientExit }
        }
    }

    It 'deploys the bundle with all required user-scoped MSIX dependencies' {
        InModuleScope Privacy {
            $result=Update-PrivacyWinGet -FilePath $script:UpdatePath -Confirm:$false
            $result.PreviousVersion | Should -Be '1.21.10120.0'
            $result.Version | Should -Be '1.29.290.0'
            $result.Path | Should -Be $script:UpdatePath
            Should -Invoke Add-AppxPackage -Times 1 -Exactly -ParameterFilter {
                @($DependencyPath).Count -eq 3 -and $Path.EndsWith('.msixbundle') -and
                $ForceTargetApplicationShutdown -and -not $AllowUnsigned -and -not $ForceUpdateFromAnyVersion
            }
            Should -Invoke Invoke-PrivacyBoundedProcess -Times 1 -Exactly -ParameterFilter { $ArgumentList[0] -ceq '--version' -and $TimeoutSeconds -eq 15 }
            Should -Invoke Get-PrivacyWinGetReleaseFile -Times 1 -Exactly -ParameterFilter {
                [string]$Uri -ceq 'https://github.com/microsoft/winget-cli/releases/download/v1.29.290/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle' -and
                $ExpectedBytes -eq 216783252 -and $Sha256 -ceq '6824b6e9484ab24687d99a0c829d2bcbcc7849a70a4d0f596fc43c89d20dff15'
            }
        }
    }
    It 'preserves an already newer x64 dependency' {
        InModuleScope Privacy {
            $script:NewerDependency=$true
            $null=Update-PrivacyWinGet -FilePath $script:UpdatePath -Confirm:$false
            Should -Invoke Add-AppxPackage -Times 1 -Exactly -ParameterFilter { @($DependencyPath).Count -eq 2 -and -not @($DependencyPath|Where-Object { $_ -like '*Microsoft.VCLibs.140.00_*' }).Count }
        }
    }
    It 'rejects an unexpected executable before downloading or deploying' {
        InModuleScope Privacy {
            { Update-PrivacyWinGet -FilePath $env:ComSpec -Confirm:$false } | Should -Throw '*registered Microsoft App Installer executable*'
            Should -Invoke Get-PrivacyWinGetReleaseFile -Times 0 -Exactly
            Should -Invoke Add-AppxPackage -Times 0 -Exactly
        }
    }
    It 'rejects an App Installer registration with another publisher family' {
        InModuleScope Privacy {
            $script:InstallerFamily='Microsoft.DesktopAppInstaller_otherpublisher'
            { Update-PrivacyWinGet -FilePath $script:UpdatePath -Confirm:$false } | Should -Throw '*exactly one Microsoft App Installer registration*'
            Should -Invoke Get-PrivacyWinGetReleaseFile -Times 0 -Exactly
        }
    }
    It 'never downgrades a client beyond the reviewed repair version' {
        InModuleScope Privacy {
            $script:InstallerVersion='1.30.0.0'
            { Update-PrivacyWinGet -FilePath $script:UpdatePath -Confirm:$false } | Should -Throw '*already at or above*'
            Should -Invoke Get-PrivacyWinGetReleaseFile -Times 0 -Exactly
            Should -Invoke Add-AppxPackage -Times 0 -Exactly
        }
    }
    It 'does not certify an update without a newer registered package' {
        InModuleScope Privacy {
            $script:AdvanceVersion=$false
            { Update-PrivacyWinGet -FilePath $script:UpdatePath -Confirm:$false } | Should -Throw '*did not advance*'
        }
    }
    It 'rejects a newer package whose CLI does not start' {
        InModuleScope Privacy {
            $script:NewClientExit=1
            { Update-PrivacyWinGet -FilePath $script:UpdatePath -Confirm:$false } | Should -Throw '*Updated WinGet did not start*'
        }
    }
    It 'does not download or deploy a cancelled update' {
        InModuleScope Privacy {
            { Update-PrivacyWinGet -FilePath $script:UpdatePath -WhatIf } | Should -Throw '*cancelled*'
            Should -Invoke Get-PrivacyWinGetReleaseFile -Times 0 -Exactly
            Should -Invoke Add-AppxPackage -Times 0 -Exactly
        }
    }
}

Describe 'Privacy verifies update downloads before deployment' -Skip:($env:OS -ne 'Windows_NT') {
    BeforeEach {
        InModuleScope Privacy {
            Mock Invoke-WebRequest { [IO.File]::WriteAllBytes($OutFile,[byte[]]@(1,2,3)) }
        }
    }
    It 'accepts exactly the expected size and SHA-256' {
        InModuleScope Privacy -Parameters @{File=(Join-Path $TestDrive 'valid.bin')} {
            param($File)
            $downloadPath=[string]$File
            { Get-PrivacyWinGetReleaseFile -Uri 'https://example.invalid/fixture' -Path $downloadPath -ExpectedBytes 3 -Sha256 '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81' } | Should -Not -Throw
        }
    }
    It 'rejects a same-size altered payload' {
        InModuleScope Privacy -Parameters @{File=(Join-Path $TestDrive 'bad-hash.bin')} {
            param($File)
            $downloadPath=[string]$File
            { Get-PrivacyWinGetReleaseFile -Uri 'https://example.invalid/fixture' -Path $downloadPath -ExpectedBytes 3 -Sha256 ('0'*64) } | Should -Throw '*pinned size/SHA-256*'
        }
    }
    It 'rejects a truncated payload even with its matching hash' {
        InModuleScope Privacy -Parameters @{File=(Join-Path $TestDrive 'bad-size.bin')} {
            param($File)
            $downloadPath=[string]$File
            { Get-PrivacyWinGetReleaseFile -Uri 'https://example.invalid/fixture' -Path $downloadPath -ExpectedBytes 4 -Sha256 '039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81' } | Should -Throw '*pinned size/SHA-256*'
        }
    }
}

Describe 'Privacy captures bounded native metadata output' -Skip:($env:OS -ne 'Windows_NT') {
    It 'captures native command output without losing its exit code' {
        InModuleScope Privacy {
            $native=Invoke-PrivacyBoundedProcess -FilePath $env:ComSpec -ArgumentList @('/d','/c','echo','NoID-source-output') -TimeoutSeconds 15 -CaptureOutput
            $native.ExitCode | Should -Be 0
            $native.Output.Trim() | Should -Be 'NoID-source-output'
            $native.ErrorOutput | Should -Be ''
        }
    }
}
