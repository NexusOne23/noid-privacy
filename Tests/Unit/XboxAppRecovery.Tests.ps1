#Requires -Version 5.1

BeforeAll {
    $repoRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repoRoot 'Core\XboxComponents.ps1')
    . (Join-Path $repoRoot 'Core\XboxAppRecovery.ps1')
    function Test-NoIDNetworkConnection {return $true}
    function Invoke-PrivacyBoundedProcess {param($FilePath,[string[]]$ArgumentList,$TimeoutSeconds) $null=$FilePath,$ArgumentList,$TimeoutSeconds}
    function Update-PrivacyWinGet {
        [CmdletBinding(SupportsShouldProcess=$true)]
        param($FilePath)
        if ($PSCmdlet.ShouldProcess($FilePath, 'Update App Installer')) { throw 'App Installer update must be mocked' }
    }
}

Describe 'Xbox app recovery identity and registration checks' {
    It 'rejects an app outside the Xbox catalog before querying Windows' {
        Mock Get-AppxPackage {throw 'Unexpected query'}
        foreach ($name in @('Microsoft.SomeGame','Microsoft.GamingServices')) {
            {Get-NoIDXboxUserAppState -Name $name} | Should -Throw '*outside the closed catalog*'
        }
        Should -Invoke Get-AppxPackage -Exactly 0
    }

    It 'rejects lookalike publishers and unhealthy package registrations' {
        Mock Get-AppxPackage {[pscustomobject]@{Name='Microsoft.GamingApp';PackageFamilyName='Microsoft.GamingApp_otherpublisher';Status='Ok'}}
        {Get-NoIDXboxUserAppState -Name Microsoft.GamingApp} | Should -Throw '*publisher*'
        Mock Get-AppxPackage {[pscustomobject]@{Name='Microsoft.GamingApp';PackageFamilyName='Microsoft.GamingApp_8wekyb3d8bbwe';Status='Modified'}}
        $state=Get-NoIDXboxUserAppState -Name Microsoft.GamingApp
        $state.Present | Should -BeTrue
        $state.Healthy | Should -BeFalse
    }

    It 'propagates query errors instead of interpreting them as absent apps' {
        Mock Get-AppxPackage {throw 'Provider unavailable'}
        {Get-NoIDXboxUserAppState -Name Microsoft.GamingApp} | Should -Throw '*Provider unavailable*'
    }

    It 'refuses to run a path selected from an invalid App Installer identity' {
        Mock Get-AppxPackage {[pscustomobject]@{Name='Microsoft.DesktopAppInstaller';PackageFamilyName='Microsoft.DesktopAppInstaller_otherpublisher';Status='Ok';InstallLocation=$TestDrive}}
        {Get-NoIDXboxRegisteredWinGetPath} | Should -Throw '*healthy Microsoft App Installer*'
    }

    It 'bounds each process by the remaining overall recovery deadline' {
        $timer=[pscustomobject]@{Elapsed=[timespan]::FromSeconds(25)}
        Get-NoIDXboxRecoveryTimeout -Timer $timer -LimitSeconds 30 -MaximumSeconds 600 | Should -Be 5
        $timer.Elapsed=[timespan]::FromSeconds(30)
        {Get-NoIDXboxRecoveryTimeout -Timer $timer -LimitSeconds 30 -MaximumSeconds 600} | Should -Throw '*overall deadline*'
    }
}

Describe 'Closed Xbox app recovery routes' {
    BeforeEach {
        $script:AppState=@{}
        foreach($app in (Get-NoIDXboxComponentCatalog).Apps){$script:AppState[$app.Name]=[pscustomobject]@{Present=$false;Healthy=$false}}
        Mock Assert-NoIDXboxAppUserContext {}
        Mock Get-NoIDXboxUserAppState {
            param($Name)
            $state=$script:AppState[$Name]
            [pscustomobject]@{Present=[bool]$state.Present;Healthy=[bool]$state.Healthy}
        }
        Mock Add-AppxPackage {throw 'Family is not staged'}
        Mock Test-NoIDNetworkConnection {return $true}
        Mock Get-NoIDXboxRegisteredWinGetPath {return 'C:\TrustedAppInstaller\winget.exe'}
        Mock Invoke-PrivacyBoundedProcess {
            param($FilePath,$ArgumentList,$TimeoutSeconds)
            $null=$FilePath,$TimeoutSeconds
            if($ArgumentList[0] -ceq 'install'){
                $app=@((Get-NoIDXboxComponentCatalog).Apps|Where-Object StoreId -CEQ $ArgumentList[2])
                if($app.Count -ne 1){throw 'Unexpected Store product'}
                $script:AppState[$app[0].Name]=[pscustomobject]@{Present=$true;Healthy=$true}
            }
            return 0
        }
        Mock Update-PrivacyWinGet {}
    }

    It 'does no installation or network work when all apps are healthy' {
        foreach($name in @($script:AppState.Keys)){$script:AppState[$name]=[pscustomobject]@{Present=$true;Healthy=$true}}
        $result=Invoke-NoIDXboxCurrentUserAppRecovery -ExpectedSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1 -Confirm:$false
        $result.Success | Should -BeTrue
        @($result.Entries|Where-Object Outcome -EQ AlreadyPresent).Count | Should -Be 6
        Should -Invoke Add-AppxPackage -Exactly 0
        Should -Invoke Test-NoIDNetworkConnection -Exactly 0
        Should -Invoke Invoke-PrivacyBoundedProcess -Exactly 0
    }

    It 'stops before any app change when the original-user token check fails' {
        Mock Assert-NoIDXboxAppUserContext {throw 'Wrong desktop token'}
        {Invoke-NoIDXboxCurrentUserAppRecovery -ExpectedSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1 -Confirm:$false} | Should -Throw '*desktop token*'
        Should -Invoke Add-AppxPackage -Exactly 0
        Should -Invoke Invoke-PrivacyBoundedProcess -Exactly 0
    }

    It 'registers available local families without forcing running applications to close' {
        Mock Add-AppxPackage {
            param($MainPackage)
            $app=@((Get-NoIDXboxComponentCatalog).Apps|Where-Object PackageFamilyName -CEQ $MainPackage)[0]
            $script:AppState[$app.Name]=[pscustomobject]@{Present=$true;Healthy=$true}
        }
        $result=Invoke-NoIDXboxCurrentUserAppRecovery -ExpectedSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1 -Confirm:$false
        $result.Success | Should -BeTrue
        @($result.Entries|Where-Object Outcome -EQ RegisteredLocally).Count | Should -Be 6
        Should -Invoke Add-AppxPackage -Exactly 6 -ParameterFilter {$RegisterByFamilyName -and -not $ForceApplicationShutdown -and -not $ForceTargetApplicationShutdown}
        Should -Invoke Invoke-PrivacyBoundedProcess -Exactly 0
    }

    It 'uses only the three fixed Store products and tolerates unavailable retired components' {
        $result=Invoke-NoIDXboxCurrentUserAppRecovery -ExpectedSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1 -Confirm:$false
        $result.Success | Should -BeTrue
        @($result.Entries|Where-Object Outcome -EQ InstalledFromStore).Count | Should -Be 3
        @($result.Entries|Where-Object Outcome -EQ OptionalUnavailable).Count | Should -Be 3
        Should -Invoke Invoke-PrivacyBoundedProcess -Exactly 3 -ParameterFilter {
            $ArgumentList[0] -ceq 'install' -and $ArgumentList[2] -cin @('9MV0B5HZVK9Z','9NZKPSTSNW4P','9WZDNCRD1HKW') -and
            $ArgumentList -contains '--exact' -and $ArgumentList -contains 'msstore' -and $ArgumentList -contains '--disable-interactivity'
        }
        Should -Invoke Invoke-PrivacyBoundedProcess -Exactly 0 -ParameterFilter {$ArgumentList -contains '9MWPM2CQNLHN'}
        Should -Invoke Add-AppxPackage -Exactly 0 -ParameterFilter {$MainPackage -ceq 'Microsoft.GamingServices_8wekyb3d8bbwe'}
    }

    It 'reports missing required apps offline without launching a Store process' {
        Mock Test-NoIDNetworkConnection {return $false}
        $result=Invoke-NoIDXboxCurrentUserAppRecovery -ExpectedSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1 -Confirm:$false
        $result.Success | Should -BeFalse
        @($result.Entries|Where-Object Outcome -EQ NeedsNetwork).Count | Should -Be 3
        Should -Invoke Invoke-PrivacyBoundedProcess -Exactly 0
    }

    It 'requires healthy readback even when the Store process exits successfully' {
        Mock Invoke-PrivacyBoundedProcess {return 0}
        $result=Invoke-NoIDXboxCurrentUserAppRecovery -ExpectedSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1 -Confirm:$false
        $result.Success | Should -BeFalse
        @($result.Entries|Where-Object {$_.Required -and $_.Outcome -ceq 'Failed'}).Count | Should -Be 3
        Should -Invoke Invoke-PrivacyBoundedProcess -Exactly 1 -ParameterFilter {$ArgumentList[0] -ceq 'source'}
    }

    It 'does not treat an unhealthy optional installed component as an acceptable absence' {
        $script:AppState['Microsoft.Xbox.TCUI']=[pscustomobject]@{Present=$true;Healthy=$false}
        $result=Invoke-NoIDXboxCurrentUserAppRecovery -ExpectedSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1 -Confirm:$false
        $result.Success | Should -BeFalse
        ($result.Entries|Where-Object Name -CEQ Microsoft.Xbox.TCUI).Outcome | Should -BeExactly Failed
    }

    It 'honors WhatIf before app or Store execution' {
        {Invoke-NoIDXboxCurrentUserAppRecovery -ExpectedSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1 -WhatIf} | Should -Throw '*not confirmed*'
        Should -Invoke Add-AppxPackage -Exactly 0
        Should -Invoke Invoke-PrivacyBoundedProcess -Exactly 0
    }
    It 'retains a bounded useful diagnostic when Windows returns an oversized error' {
        Mock Add-AppxPackage {throw ('Registration failed: '+('x'*10000))}
        Mock Test-NoIDNetworkConnection {$false}
        $result=Invoke-NoIDXboxCurrentUserAppRecovery -ExpectedSid 'S-1-5-21-1-2-3-1001' -ExpectedSessionId 1 -Confirm:$false
        $result.Success | Should -BeFalse
        $failed=@($result.Entries|Where-Object Required)
        $failed.Count | Should -Be 3
        foreach($entry in $failed){
            $entry.Outcome | Should -BeExactly 'NeedsNetwork'
            $entry.Error.Length | Should -Be 8192
            $entry.Error | Should -Match '^Local registration: Registration failed: x+\.\.\.$'
        }
        @($result.Entries|Where-Object {-not $_.Required -and $_.Error}).Count | Should -Be 0
    }
}
