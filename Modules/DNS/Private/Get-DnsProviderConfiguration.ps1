function Get-DnsProviderConfiguration {
    <#
    .SYNOPSIS
        Load and validate the canonical DNS provider configuration.
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param()

    $configPath = Join-Path $script:ModuleRoot 'Config\Providers.json'
    if (-not (Test-Path -LiteralPath $configPath -PathType Leaf)) {
        throw "Providers.json not found at: $configPath"
    }
    $configuration = Get-Content -LiteralPath $configPath -Raw -Encoding UTF8 -ErrorAction Stop |
        ConvertFrom-Json -ErrorAction Stop
    if ([string]$configuration.version -ne '1.0.0' -or -not $configuration.PSObject.Properties['providers']) {
        throw 'Providers.json has an unsupported schema'
    }

    $requiredProviders = @('cloudflare', 'quad9', 'adguard')
    $actualProviders = @($configuration.providers.PSObject.Properties.Name | Sort-Object)
    if (@(Compare-Object -ReferenceObject ($requiredProviders | Sort-Object) -DifferenceObject $actualProviders).Count -gt 0) {
        throw 'Providers.json must declare exactly Cloudflare, Quad9, and AdGuard'
    }

    $seenAddresses = @{}
    foreach ($providerKey in $requiredProviders) {
        $provider = $configuration.providers.$providerKey
        foreach ($property in @('intentToken', 'name', 'description', 'ipv4', 'ipv6', 'doh', 'features', 'jurisdiction', 'best_for', 'documentation')) {
            if (-not $provider.PSObject.Properties[$property]) {
                throw "DNS provider '$providerKey' is missing required property '$property'"
            }
        }
        foreach ($textProperty in @('intentToken', 'name', 'description', 'jurisdiction', 'best_for', 'documentation')) {
            if ([string]::IsNullOrWhiteSpace([string]$provider.$textProperty)) {
                throw "DNS provider '$providerKey' has an empty '$textProperty' value"
            }
        }
        $expectedIntentToken = switch ($providerKey) {
            'cloudflare' { 'Cloudflare' }
            'quad9' { 'Quad9' }
            'adguard' { 'AdGuard' }
        }
        if ([string]$provider.intentToken -cne $expectedIntentToken) {
            throw "DNS provider '$providerKey' has an invalid canonical intentToken"
        }
        if (@($provider.features).Count -eq 0 -or
            @($provider.features | Where-Object { [string]::IsNullOrWhiteSpace([string]$_) }).Count -gt 0) {
            throw "DNS provider '$providerKey' has an invalid feature list"
        }

        foreach ($familyDefinition in @(
                [PSCustomObject]@{ Name = 'ipv4'; Family = [System.Net.Sockets.AddressFamily]::InterNetwork },
                [PSCustomObject]@{ Name = 'ipv6'; Family = [System.Net.Sockets.AddressFamily]::InterNetworkV6 }
            )) {
            $familyConfig = $provider.($familyDefinition.Name)
            foreach ($position in @('primary', 'secondary')) {
                if (-not $familyConfig.PSObject.Properties[$position]) {
                    throw "DNS provider '$providerKey' is missing $($familyDefinition.Name).$position"
                }
                $parsedAddress = $null
                $address = [string]$familyConfig.$position
                if (-not [System.Net.IPAddress]::TryParse($address, [ref]$parsedAddress) -or
                    $parsedAddress.AddressFamily -ne $familyDefinition.Family) {
                    throw "DNS provider '$providerKey' has an invalid $($familyDefinition.Name) address: $address"
                }
                $canonicalAddress = $parsedAddress.ToString()
                if ($seenAddresses.ContainsKey($canonicalAddress)) {
                    throw "Providers.json contains a duplicate resolver address: $address"
                }
                $seenAddresses[$canonicalAddress] = $true
            }
        }

        if ($provider.doh.supported -isnot [bool] -or -not [bool]$provider.doh.supported) {
            throw "DNS provider '$providerKey' must explicitly support DoH"
        }
        $dohUri = $null
        if (-not $provider.doh.PSObject.Properties['template'] -or
            -not [Uri]::TryCreate([string]$provider.doh.template, [UriKind]::Absolute, [ref]$dohUri) -or
            $dohUri.Scheme -ne 'https') {
            throw "DNS provider '$providerKey' has an invalid HTTPS DoH template"
        }
        $documentationUri = $null
        if (-not [Uri]::TryCreate([string]$provider.documentation, [UriKind]::Absolute, [ref]$documentationUri) -or
            $documentationUri.Scheme -ne 'https') {
            throw "DNS provider '$providerKey' has an invalid documentation URL"
        }
    }

    if ([string]$configuration.default_provider -notin $requiredProviders) {
        throw 'Providers.json has an invalid default_provider'
    }
    return $configuration
}
