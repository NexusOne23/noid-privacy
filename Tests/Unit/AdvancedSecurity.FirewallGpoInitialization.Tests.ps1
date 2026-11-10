#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityFirewallGpoStore.ps1')
    Initialize-AdvancedSecurityFirewallGpoStore
}

Describe 'AdvancedSecurity first writable opening of an empty native GPO' {
    It 'accepts the exact native header appearing from complete policy and metadata absence' {
        $header = [Text.Encoding]::ASCII.GetBytes("[General]`r`n")
        [NoIDPrivacy.FirewallGpoStore]::IsEmptyGptInitialization($null, $null, $null, $header) | Should -BeTrue
    }

    It 'rejects <Change> as native initialization' -TestCases @(
        @{ Change='existing policy' }, @{ Change='existing metadata' }, @{ Change='new policy' },
        @{ Change='still absent' }, @{ Change='empty file' }, @{ Change='different newline' },
        @{ Change='revision' }, @{ Change='extension' }, @{ Change='user metadata' },
        @{ Change='trailing bytes' }, @{ Change='UTF-8 BOM' }
    ) {
        param($Change)
        $beforePolicy=$null; $beforeVersion=$null; $afterPolicy=$null
        $afterVersion=[Text.Encoding]::ASCII.GetBytes("[General]`r`n")
        switch ($Change) {
            'existing policy' { $beforePolicy=[byte[]]@(80,82,101,103,1,0,0,0) }
            'existing metadata' { $beforeVersion=$afterVersion }
            'new policy' { $afterPolicy=[byte[]]@(80,82,101,103,1,0,0,0) }
            'still absent' { $afterVersion=$null }
            'empty file' { $afterVersion=[byte[]]@() }
            'different newline' { $afterVersion=[Text.Encoding]::ASCII.GetBytes("[General]`n") }
            'revision' { $afterVersion=[Text.Encoding]::ASCII.GetBytes("[General]`r`nVersion=0`r`n") }
            'extension' { $afterVersion=[Text.Encoding]::ASCII.GetBytes("[General]`r`ngPCMachineExtensionNames= `r`n") }
            'user metadata' { $afterVersion=[Text.Encoding]::ASCII.GetBytes("[General]`r`ngPCUserExtensionNames= `r`n") }
            'trailing bytes' { $afterVersion += [byte]0 }
            'UTF-8 BOM' { $afterVersion=[byte[]]@(239,187,191)+$afterVersion }
        }
        [NoIDPrivacy.FirewallGpoStore]::IsEmptyGptInitialization($beforePolicy, $beforeVersion, $afterPolicy, $afterVersion) | Should -BeFalse
    }
}
