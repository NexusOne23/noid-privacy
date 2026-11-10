#Requires -Version 5.1

BeforeAll {
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityFirewallRules.ps1')
    . (Join-Path $repo 'Modules/AdvancedSecurity/Private/AdvancedSecurityFirewallWfp.ps1')
}

Describe 'Shields Up replaces individual inbound WFP block filters' {
    BeforeEach {
        Set-StrictMode -Version Latest
        $script:Definition = Get-AdvancedSecurityFirewallDefinitions -Feature AdminShares
        $script:Rule = [pscustomobject]@{
            PolicyStoreSourceType='GroupPolicy'; Group='NoIDPrivacy.ManagedFirewallMirror.v1'
            EnforcementStatus=@('DisabledInProfile', 'Enforced')
        }
        $items = foreach ($family in @('V4', 'V6')) {
            @"
<item>
 <displayData><name>Native profile block</name><description>Native profile block</description></displayData>
 <flags><item>FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT</item><item>FWPM_FILTER_FLAG_HAS_FILTER_ORIGIN</item></flags>
 <providerKey>FWPM_PROVIDER_MPSSVC_WF</providerKey><subLayerKey>FWPM_SUBLAYER_MPSSVC_WF</subLayerKey>
 <layerKey>FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_$family</layerKey><action><type>FWP_ACTION_BLOCK</type></action>
 <filterCondition />
</item>
"@
        }
        $script:Evidence = [pscustomobject]@{
            CurrentProfileMask=4; Profiles=@{}
            Filters=[xml]('<wfpdiag><filters>' + ($items -join '') + '</filters></wfpdiag>')
        }
        foreach ($fwProfile in @('Domain', 'Private', 'Public')) {
            $script:Evidence.Profiles[$fwProfile] = [pscustomobject]@{
                Enabled=$true; HasExcludedInterfaces=$false
                BlockAllInboundTraffic=($fwProfile -ceq 'Public'); DefaultInboundAction=0
            }
        }
        $script:Ipv6 = $script:Evidence.Filters.SelectSingleNode('/wfpdiag/filters/item[layerKey="FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6"]')
    }

    It 'requires both native profile state and compiled blocks: <Case>' -TestCases @(
        @{Case='active Public';Expected=$true},
        @{Case='explicit empty condition count';Expected=$true},
        @{Case='contradictory condition count';Expected=$false},
        @{Case='Any with only Public active';Expected=$true},
        @{Case='Public with another active profile';Expected=$true},
        @{Case='Any with an unshielded active profile';Expected=$false},
        @{Case='Any with both active profiles shielded';Expected=$true},
        @{Case='outbound rule';Expected=$false},
        @{Case='missing native shield state';Expected=$false},
        @{Case='string shield state';Expected=$false},
        @{Case='default Allow';Expected=$false},
        @{Case='disabled profile';Expected=$false},
        @{Case='excluded interface';Expected=$false},
        @{Case='disabled rule';Expected=$false},
        @{Case='missing IPv6';Expected=$false},
        @{Case='missing condition container';Expected=$false},
        @{Case='additional condition';Expected=$false},
        @{Case='disabled filter';Expected=$false},
        @{Case='foreign provider';Expected=$false},
        @{Case='allow filter';Expected=$false},
        @{Case='missing active enforcement';Expected=$false}
    ) {
        param($Case, $Expected)
        switch -Exact ($Case) {
            'explicit empty condition count' { $script:Ipv6.SelectSingleNode('filterCondition').SetAttribute('numItems','0') }
            'contradictory condition count' { $script:Ipv6.SelectSingleNode('filterCondition').SetAttribute('numItems','1') }
            'Any with only Public active' { $script:Definition.Profile='Any' }
            'Public with another active profile' { $script:Evidence.CurrentProfileMask=6 }
            'Any with an unshielded active profile' {
                $script:Definition.Profile='Any';$script:Evidence.CurrentProfileMask=6
            }
            'Any with both active profiles shielded' {
                $script:Definition.Profile='Any';$script:Evidence.CurrentProfileMask=6
                $script:Evidence.Profiles.Private.BlockAllInboundTraffic=$true
            }
            'outbound rule' { $script:Definition=Get-AdvancedSecurityFirewallDefinitions -Feature Finger }
            'missing native shield state' { $script:Evidence.Profiles.Public.PSObject.Properties.Remove('BlockAllInboundTraffic') }
            'string shield state' { $script:Evidence.Profiles.Public.BlockAllInboundTraffic='True' }
            'default Allow' { $script:Evidence.Profiles.Public.DefaultInboundAction=1 }
            'disabled profile' { $script:Evidence.Profiles.Public.Enabled=$false }
            'excluded interface' { $script:Evidence.Profiles.Public.HasExcludedInterfaces=$true }
            'disabled rule' { $script:Rule.EnforcementStatus+= 'DisabledObject' }
            'missing IPv6' { $null=$script:Ipv6.ParentNode.RemoveChild($script:Ipv6) }
            'missing condition container' { $null=$script:Ipv6.RemoveChild($script:Ipv6.SelectSingleNode('filterCondition')) }
            'additional condition' {
                $condition=$script:Evidence.Filters.CreateElement('item')
                $condition.InnerXml='<fieldKey>FWPM_CONDITION_IP_LOCAL_PORT</fieldKey><matchType>FWP_MATCH_EQUAL</matchType><conditionValue><type>FWP_UINT16</type><uint16>80</uint16></conditionValue>'
                $null=$script:Ipv6.SelectSingleNode('filterCondition').AppendChild($condition)
            }
            'disabled filter' { $script:Ipv6.SelectSingleNode('flags/item').InnerText='FWPM_FILTER_FLAG_DISABLED' }
            'foreign provider' { $script:Ipv6.providerKey='OtherProvider' }
            'allow filter' { $script:Ipv6.action.type='FWP_ACTION_PERMIT' }
            'missing active enforcement' { $script:Rule.EnforcementStatus=@('DisabledInProfile') }
        }
        Test-AdvancedSecurityFirewallGpoEnforcement -Definition $script:Definition -Rule $script:Rule -Evidence $script:Evidence |
            Should -Be $Expected
    }
}

Describe 'Independent evidence for contradictory GPO firewall status' {
    BeforeEach {
        Set-StrictMode -Version Latest
        $script:Definition = Get-AdvancedSecurityFirewallDefinitions -Feature Finger
        $script:Rule = [pscustomobject]@{
            PolicyStoreSourceType='GroupPolicy'; Group='NoIDPrivacy.ManagedFirewallMirror.v1'
            EnforcementStatus=@('DisabledInProfile', 'ProfileInactive', 'Enforced')
        }
        $items = foreach ($family in @('V4', 'V6')) {
            @"
<item>
 <displayData><name>$($script:Definition.DisplayName)</name><description>$($script:Definition.Description)</description></displayData>
 <flags><item>FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT</item><item>FWPM_FILTER_FLAG_HAS_FILTER_ORIGIN</item></flags>
 <providerKey>FWPM_PROVIDER_MPSSVC_WF</providerKey><subLayerKey>FWPM_SUBLAYER_MPSSVC_WF</subLayerKey>
 <layerKey>FWPM_LAYER_ALE_AUTH_CONNECT_$family</layerKey><action><type>FWP_ACTION_BLOCK</type></action>
 <filterCondition>
  <item><fieldKey>FWPM_CONDITION_IP_PROTOCOL</fieldKey><matchType>FWP_MATCH_EQUAL</matchType><conditionValue><type>FWP_UINT8</type><uint8>6</uint8></conditionValue></item>
  <item><fieldKey>FWPM_CONDITION_IP_REMOTE_PORT</fieldKey><matchType>FWP_MATCH_EQUAL</matchType><conditionValue><type>FWP_UINT16</type><uint16>79</uint16></conditionValue></item>
 </filterCondition>
</item>
"@
        }
        $script:Evidence = [pscustomobject]@{
            CurrentProfileMask=4
            Profiles=@{}
            Filters=[xml]('<wfpdiag><filters><item><displayData><name>Unrelated filter</name></displayData></item>' + ($items -join '') + '</filters></wfpdiag>')
        }
        foreach ($fwProfile in @('Domain', 'Private', 'Public')) {
            $script:Evidence.Profiles[$fwProfile] = [pscustomobject]@{Enabled=$true;HasExcludedInterfaces=$false}
        }
        $script:Ipv6 = $script:Evidence.Filters.SelectSingleNode('/wfpdiag/filters/item[layerKey="FWPM_LAYER_ALE_AUTH_CONNECT_V6"]')
    }

    It 'requires complete independent evidence: <Case>' -TestCases @(
        @{Case='valid active GPO';Expected=$true},
        @{Case='indexed filter';Expected=$true},
        @{Case='inactive Public only';Expected=$true},
        @{Case='no active network';Expected=$true},
        @{Case='disabled profile';Expected=$false},
        @{Case='excluded interface';Expected=$false},
        @{Case='missing profile';Expected=$false},
        @{Case='unknown profile mask';Expected=$false},
        @{Case='local rule';Expected=$false},
        @{Case='unowned GPO';Expected=$false},
        @{Case='disabled rule';Expected=$false},
        @{Case='missing active enforcement';Expected=$false},
        @{Case='contradictory inactivity';Expected=$false},
        @{Case='missing IPv6';Expected=$false},
        @{Case='wrong IPv6 port';Expected=$false},
        @{Case='wrong protocol';Expected=$false},
        @{Case='wrong direction';Expected=$false},
        @{Case='allow filter';Expected=$false},
        @{Case='foreign provider';Expected=$false},
        @{Case='foreign sublayer';Expected=$false},
        @{Case='missing description';Expected=$false},
        @{Case='restricted extra condition';Expected=$false},
        @{Case='duplicate port condition';Expected=$false},
        @{Case='not-equal port';Expected=$false},
        @{Case='wrong condition type';Expected=$false},
        @{Case='disabled filter';Expected=$false},
        @{Case='missing condition value';Expected=$false}
    ) {
        param($Case, $Expected)
        $port = $script:Ipv6.SelectSingleNode('filterCondition/item[fieldKey="FWPM_CONDITION_IP_REMOTE_PORT"]')
        switch -Exact ($Case) {
            'indexed filter' {
                $flag=$script:Evidence.Filters.CreateElement('item');$flag.InnerText='FWPM_FILTER_FLAG_INDEXED'
                $null=$script:Ipv6.flags.AppendChild($flag)
            }
            'inactive Public only' {
                $script:Definition.Profile='Public';$script:Evidence.CurrentProfileMask=2
                $script:Rule.EnforcementStatus=@('DisabledInProfile','ProfileInactive')
                $script:Evidence.Filters=[xml]'<wfpdiag><filters /></wfpdiag>'
            }
            'no active network' {
                $script:Evidence.CurrentProfileMask=0
                $script:Rule.EnforcementStatus=@('DisabledInProfile','ProfileInactive')
                $script:Evidence.Filters=[xml]'<wfpdiag><filters /></wfpdiag>'
            }
            'disabled profile' { $script:Evidence.Profiles.Public.Enabled=$false }
            'excluded interface' { $script:Evidence.Profiles.Public.HasExcludedInterfaces=$true }
            'missing profile' { $script:Evidence.Profiles.Remove('Public') }
            'unknown profile mask' { $script:Evidence.CurrentProfileMask=8 }
            'local rule' { $script:Rule.PolicyStoreSourceType='Local' }
            'unowned GPO' { $script:Rule.Group='Someone else' }
            'disabled rule' { $script:Rule.EnforcementStatus+= 'DisabledObject' }
            'missing active enforcement' { $script:Rule.EnforcementStatus=@('DisabledInProfile','ProfileInactive') }
            'contradictory inactivity' { $script:Evidence.CurrentProfileMask=0 }
            'missing IPv6' { $null=$script:Ipv6.ParentNode.RemoveChild($script:Ipv6) }
            'wrong IPv6 port' { $port.conditionValue.uint16='80' }
            'wrong protocol' { $script:Ipv6.SelectSingleNode('filterCondition/item[fieldKey="FWPM_CONDITION_IP_PROTOCOL"]/conditionValue/uint8').InnerText='17' }
            'wrong direction' { $script:Ipv6.layerKey='FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6' }
            'allow filter' { $script:Ipv6.action.type='FWP_ACTION_PERMIT' }
            'foreign provider' { $script:Ipv6.providerKey='OtherProvider' }
            'foreign sublayer' { $script:Ipv6.subLayerKey='OtherSublayer' }
            'missing description' { $null=$script:Ipv6.displayData.RemoveChild($script:Ipv6.SelectSingleNode('displayData/description')) }
            'restricted extra condition' { $null=$script:Ipv6.filterCondition.AppendChild($port.CloneNode($true)) }
            'duplicate port condition' {
                $protocol=$script:Ipv6.SelectSingleNode('filterCondition/item[fieldKey="FWPM_CONDITION_IP_PROTOCOL"]')
                $null=$protocol.ParentNode.ReplaceChild($port.CloneNode($true),$protocol)
            }
            'not-equal port' { $port.matchType='FWP_MATCH_NOT_EQUAL' }
            'wrong condition type' { $port.conditionValue.type='FWP_UINT32' }
            'disabled filter' { $script:Ipv6.SelectSingleNode('flags/item').InnerText='FWPM_FILTER_FLAG_DISABLED' }
            'missing condition value' { $null=$port.RemoveChild($port.SelectSingleNode('conditionValue')) }
        }
        Test-AdvancedSecurityFirewallGpoEnforcement -Definition $script:Definition -Rule $script:Rule -Evidence $script:Evidence |
            Should -Be $Expected
    }
}
