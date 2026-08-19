function ConvertTo-DnsCanonicalAddress {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Address
    )

    $parsedAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$parsedAddress)) {
        throw "Invalid IP address: $Address"
    }
    return $parsedAddress.ToString()
}
