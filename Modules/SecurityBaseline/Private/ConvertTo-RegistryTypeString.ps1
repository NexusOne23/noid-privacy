<#
.SYNOPSIS
    Convert a RegistryValueKind to its canonical REG_* type string

.DESCRIPTION
    Single shared mapping used by Backup-RegistryPolicies and
    Assert-SecurityBaselinePrestate so the two sites cannot silently drift
    apart when a new RegistryValueKind case is added.

.PARAMETER Kind
    The Microsoft.Win32.RegistryValueKind to convert

.OUTPUTS
    String with the canonical REG_* type name; throws on unsupported kinds
#>

function ConvertTo-RegistryTypeString {
    param([Microsoft.Win32.RegistryValueKind]$Kind)
    switch ($Kind.ToString()) {
        'DWord'        { 'REG_DWORD' }
        'QWord'        { 'REG_QWORD' }
        'String'       { 'REG_SZ' }
        'ExpandString' { 'REG_EXPAND_SZ' }
        'Binary'       { 'REG_BINARY' }
        'MultiString'  { 'REG_MULTI_SZ' }
        default { throw "Unsupported registry value kind: $Kind" }
    }
}
