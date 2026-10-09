#Requires -Version 5.1

BeforeAll {
    $repoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repoRoot 'Core\Runtime.ps1')
    . (Join-Path $repoRoot 'Core\XboxComponents.ps1')
    . (Join-Path $repoRoot 'Core\XboxSettings.ps1')
    . (Join-Path $repoRoot 'Core\XboxAppWorker.ps1')
    function Get-XboxWorkerResult {
        [pscustomobject][ordered]@{
            SchemaVersion=1;UserSid='S-1-5-21-1-2-3-1001';SessionId=1;Success=$true
            Entries=@((Get-NoIDXboxComponentCatalog).Apps | ForEach-Object {
                [pscustomobject][ordered]@{
                    Name=$_.Name;Required=$_.RequiredWhenEnabled;Outcome='AlreadyPresent'
                    BeforePresent=$true;Present=$true;Healthy=$true;Error=''
                }
            })
        }
    }
    function Assert-Result { param($Record)
        Assert-NoIDXboxRecoveryResult -Record $Record -UserSid 'S-1-5-21-1-2-3-1001' -SessionId 1
    }
}

Describe 'Closed Xbox worker result contract' {
    It 'accepts complete success and a JSON round trip' {
        {Assert-Result (Get-XboxWorkerResult)} | Should -Not -Throw
        {Assert-Result (ConvertFrom-Json (ConvertTo-Json (Get-XboxWorkerResult) -Depth 12))} | Should -Not -Throw
    }
    It 'rejects a different user or session and non-integer schema fields' {
        foreach($field in @('UserSid','SessionId','SchemaVersion')) {
            $result=Get-XboxWorkerResult
            $result.$field=[string]$result.$field+'2'
            {Assert-Result $result} | Should -Throw
        }
    }
    It 'rejects missing duplicate foreign and enlarged result scopes' {
        foreach($change in @('Missing','Duplicate','Foreign','Field','Metadata')) {
            $result=Get-XboxWorkerResult
            switch($change) {
                'Missing' {$result.Entries=@($result.Entries[0])}
                'Duplicate' {$result.Entries[1]=$result.Entries[0]}
                'Foreign' {$result.Entries[0].Name='Microsoft.SomeGame'}
                'Field' {$result|Add-Member NoteProperty Command 'bad'}
                'Metadata' {$result.Entries[0]|Add-Member NoteProperty Command 'bad'}
            }
            {Assert-Result $result} | Should -Throw
        }
    }
    It 'requires measured healthy state for every successful installed app' {
        foreach($change in @('Missing','Unhealthy','Untyped','Invented','Error')) {
            $result=Get-XboxWorkerResult
            switch($change) {
                'Missing' {$result.Entries[0].Present=$false;$result.Entries[0].Healthy=$false}
                'Unhealthy' {$result.Entries[0].Healthy=$false}
                'Untyped' {$result.Entries[0].Healthy='true'}
                'Invented' {$result.Entries[0].BeforePresent=$false}
                'Error' {$result.Entries[0].Error='failure'}
            }
            {Assert-Result $result} | Should -Throw
        }
    }
    It 'allows retired optional absence but never required absence or an invented Store product' {
        $result=Get-XboxWorkerResult
        $entry=$result.Entries|Where-Object Name -CEQ Microsoft.XboxApp
        $entry.Outcome='OptionalUnavailable';$entry.Present=$false;$entry.Healthy=$false
        {Assert-Result $result} | Should -Not -Throw
        $entry.Required=$true
        {Assert-Result $result} | Should -Throw
        $entry.Required=$false;$entry.Outcome='InstalledFromStore';$entry.Present=$true;$entry.Healthy=$true
        {Assert-Result $result} | Should -Throw
    }
    It 'preserves partial failures and rejects a false success summary' {
        $result=Get-XboxWorkerResult
        $entry=$result.Entries[0];$entry.Outcome='Failed';$entry.Present=$null;$entry.Healthy=$null;$entry.BeforePresent=$null
        $result.Success=$false
        {Assert-Result $result} | Should -Not -Throw
        $result.Success=$true
        {Assert-Result $result} | Should -Throw '*summary*'
    }
    It 'detects stale worker success through independent package readback' {
        Mock Get-NoIDXboxComponentSnapshot {
            [pscustomobject]@{Apps=@((Get-NoIDXboxComponentCatalog).Apps|ForEach-Object {
                [pscustomobject]@{Name=$_.Name;Present=($_.Name -cne 'Microsoft.GamingApp');Healthy=($_.Name -cne 'Microsoft.GamingApp')}
            })}
        }
        $result=Confirm-NoIDXboxRecoveryResult -Record (Get-XboxWorkerResult) -UserSid 'S-1-5-21-1-2-3-1001'
        $result.Success | Should -BeFalse
        $result.Entries[0].Outcome | Should -Be 'Failed'
        {Assert-Result $result} | Should -Not -Throw
    }
    It 'preserves the original installation failure when independent readback also fails' {
        Mock Get-NoIDXboxComponentSnapshot {
            [pscustomobject]@{Apps=@((Get-NoIDXboxComponentCatalog).Apps|ForEach-Object {
                [pscustomobject]@{Name=$_.Name;Present=($_.Name -cne 'Microsoft.GamingApp');Healthy=($_.Name -cne 'Microsoft.GamingApp')}
            })}
        }
        $record=Get-XboxWorkerResult
        $record.Success=$false
        $entry=$record.Entries|Where-Object Name -CEQ Microsoft.GamingApp
        $entry.Outcome='Failed';$entry.Error='Store attempt exited 123';$entry.Present=$false;$entry.Healthy=$false
        $result=Confirm-NoIDXboxRecoveryResult -Record $record -UserSid 'S-1-5-21-1-2-3-1001'
        ($result.Entries|Where-Object Name -CEQ Microsoft.GamingApp).Error | Should -Match 'Store attempt exited 123.*independent'
        {Assert-Result $result} | Should -Not -Throw
        $entry.Error='x' * 8192
        $result=Confirm-NoIDXboxRecoveryResult -Record $record -UserSid 'S-1-5-21-1-2-3-1001'
        {Assert-Result $result} | Should -Not -Throw
        ($result.Entries|Where-Object Name -CEQ Microsoft.GamingApp).Error.Length | Should -BeLessOrEqual 8192
    }

    It 'bounds parsing and never returns invalid JSON content in errors' {
        $stream=[IO.MemoryStream]::new()
        try {
            $exchange=[pscustomobject]@{Stream=$stream}
            {Read-NoIDXboxRecoveryExchange $exchange} | Should -Throw '*size*'
            $bytes=[Text.Encoding]::UTF8.GetBytes('private-invalid-content')
            $stream.Write($bytes,0,$bytes.Length)
            {Read-NoIDXboxRecoveryExchange $exchange} | Should -Throw '*not valid UTF-8 JSON*'
            $stream.SetLength(262145)
            {Read-NoIDXboxRecoveryExchange $exchange} | Should -Throw '*size*'
        }finally{$stream.Dispose()}
    }
}

Describe 'Xbox original-user worker orchestration' {
    BeforeEach {
        $script:WorkerResult=Get-XboxWorkerResult
        $script:WorkerUser=[pscustomobject]@{Sid='S-1-5-21-1-2-3-1001';SessionId=1}
        $script:WorkerStream=[IO.MemoryStream]::new()
        Mock Get-PrivacyUserContext {$script:WorkerUser}
        Mock Assert-NoIDXboxUnmanagedDevice {}
        Mock Get-NoIDXboxComponentSnapshot {[pscustomobject]@{RemovalBlocked=$false}}
        Mock New-NoIDXboxRecoveryExchange {[pscustomobject]@{Directory='C:\Unused';ResultPath='C:\Unused\result.json';Stream=$script:WorkerStream}}
        Mock New-NoIDHiddenWorkerTaskAction {[pscustomobject]@{
            Action=(New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument '-NoProfile')
            Principal=(New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest)
            LauncherDirectory='C:\UnusedLauncher'
        }}
        Mock Register-ScheduledTask {}
        Mock Start-ScheduledTask {}
        Mock Get-NoIDScheduledTaskState {'Ready'}
        Mock Get-ScheduledTaskInfo {[pscustomobject]@{LastRunTime=[DateTime]::UtcNow;LastTaskResult=0}}
        Mock Read-NoIDXboxRecoveryExchange {$script:WorkerResult}
        Mock Confirm-NoIDXboxRecoveryResult {$script:WorkerResult}
        Mock Stop-ScheduledTask {}
        Mock Unregister-NoIDScheduledTask {}
        Mock Remove-NoIDHiddenWorkerLauncher {}
        Mock Remove-PrivacyWorkerExchangeDirectory {}
        Mock Start-Sleep {}
    }
    AfterEach {$script:WorkerStream.Dispose()}

    It 'runs the original-user job and cleans all temporary resources after verified success' {
        $result=Invoke-NoIDXboxAppRecovery -User $script:WorkerUser -Confirm:$false
        $result.Success | Should -BeTrue
        Should -Invoke New-NoIDHiddenWorkerTaskAction -Exactly 1 -ParameterFilter {$UserSid -ceq 'S-1-5-21-1-2-3-1001' -and $SessionId -eq 1}
        Should -Invoke Confirm-NoIDXboxRecoveryResult -Exactly 1
        Should -Invoke Unregister-NoIDScheduledTask -Exactly 1
        Should -Invoke Remove-NoIDHiddenWorkerLauncher -Exactly 1
        Should -Invoke Remove-PrivacyWorkerExchangeDirectory -Exactly 1
        $script:WorkerStream.CanRead | Should -BeFalse
    }
    It 'cleans up a failed dispatcher and does not trust or independently bless its output' {
        Mock Get-ScheduledTaskInfo {[pscustomobject]@{LastRunTime=[DateTime]::UtcNow;LastTaskResult=87}}
        {Invoke-NoIDXboxAppRecovery -User $script:WorkerUser -Confirm:$false} | Should -Throw '*could not complete*'
        Should -Invoke Read-NoIDXboxRecoveryExchange -Exactly 0
        Should -Invoke Confirm-NoIDXboxRecoveryResult -Exactly 0
        Should -Invoke Unregister-NoIDScheduledTask -Exactly 1
        Should -Invoke Remove-PrivacyWorkerExchangeDirectory -Exactly 1
    }
    It 'returns a verified partial failure when task exit status agrees' {
        $script:WorkerResult.Success=$false;$script:WorkerResult.Entries[0].Outcome='Failed'
        Mock Get-ScheduledTaskInfo {[pscustomobject]@{LastRunTime=[DateTime]::UtcNow;LastTaskResult=1}}
        (Invoke-NoIDXboxAppRecovery -User $script:WorkerUser -Confirm:$false).Success | Should -BeFalse
        Should -Invoke Confirm-NoIDXboxRecoveryResult -Exactly 1
        Should -Invoke Remove-NoIDHiddenWorkerLauncher -Exactly 1
    }
    It 'refuses an active reinstall blocker before creating a task or exchange' {
        Mock Get-NoIDXboxComponentSnapshot {[pscustomobject]@{RemovalBlocked=$true}}
        {Invoke-NoIDXboxAppRecovery -User $script:WorkerUser -Confirm:$false} | Should -Throw '*blocks Xbox*'
        Should -Invoke New-NoIDXboxRecoveryExchange -Exactly 0
        Should -Invoke Start-ScheduledTask -Exactly 0
    }
    It 'preserves the still-running task and evidence if termination cannot be confirmed' {
        Mock Start-ScheduledTask {throw 'Start call failed after scheduling'}
        Mock Get-NoIDScheduledTaskState {'Running'}
        Mock Stop-ScheduledTask {throw 'Stop failed'}
        try {
            Invoke-NoIDXboxAppRecovery -User $script:WorkerUser -Confirm:$false
            throw 'Expected quiescence failure'
        }catch{
            $_.Exception.Message | Should -Match 'could not be stopped'
            $_.Exception.Data['WorkerQuiesced'] | Should -BeFalse
        }
        Should -Invoke Unregister-NoIDScheduledTask -Exactly 0
        Should -Invoke Remove-NoIDHiddenWorkerLauncher -Exactly 0
        Should -Invoke Remove-PrivacyWorkerExchangeDirectory -Exactly 0
    }
    It 'does not create temporary resources under WhatIf' {
        Invoke-NoIDXboxAppRecovery -User $script:WorkerUser -WhatIf
        Should -Invoke New-NoIDXboxRecoveryExchange -Exactly 0
        Should -Invoke Start-ScheduledTask -Exactly 0
    }
    It 'retains worker resources when Windows reports <Label> state' -TestCases @(
        @{Label='unknown';TaskState='Unknown'}
        @{Label='missing';TaskState=$null}
        @{Label='unrecognized';TaskState='Unexpected'}
    ) {
        param($TaskState)
        $script:UncertainWorkerState=$TaskState
        Mock Get-NoIDScheduledTaskState {$script:UncertainWorkerState}
        try {
            Invoke-NoIDXboxAppRecovery -User $script:WorkerUser -Confirm:$false
            throw 'Expected quiescence failure'
        } catch {
            $_.Exception.Message | Should -Match 'could not be stopped'
            $_.Exception.Data['WorkerQuiesced'] | Should -BeFalse
        }
        Should -Invoke Read-NoIDXboxRecoveryExchange -Exactly 0
        Should -Invoke Confirm-NoIDXboxRecoveryResult -Exactly 0
        Should -Invoke Unregister-NoIDScheduledTask -Exactly 0
        Should -Invoke Remove-NoIDHiddenWorkerLauncher -Exactly 0
        Should -Invoke Remove-PrivacyWorkerExchangeDirectory -Exactly 0
    }
}
