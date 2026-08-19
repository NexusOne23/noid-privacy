function Initialize-DnsInterfaceDohNativeApi {
    [CmdletBinding()]
    param()

    if ('NoIDPrivacy.DnsInterfaceNative' -as [type]) {
        return
    }

    # Microsoft documents DNS_INTERFACE_SETTINGS3, DNS_SERVER_PROPERTY and
    # DNS_DOH_SERVER_SETTINGS as the supported per-interface DoH surface. The
    # interop layer is deliberately narrow: it reads and writes only the
    # NameServer + DNS_SETTING_DOH fields selected in Flags.
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace NoIDPrivacy {
    public sealed class DnsDohPropertyState {
        public uint Version { get; set; }
        public uint ServerIndex { get; set; }
        public uint Type { get; set; }
        public ulong Flags { get; set; }
        public string Template { get; set; }
        public ushort Port { get; set; }
    }

    public sealed class DnsInterfaceState {
        public string NameServer { get; set; }
        public DnsDohPropertyState[] Properties { get; set; }
    }

    public static class DnsInterfaceNative {
        [StructLayout(LayoutKind.Sequential)]
        private struct DNS_DOH_SERVER_SETTINGS {
            public IntPtr Template;
            public ulong Flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DNS_SERVER_PROPERTY {
            public uint Version;
            public uint ServerIndex;
            public uint Type;
            public IntPtr Property;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DNS_INTERFACE_SETTINGS3 {
            public uint Version;
            public ulong Flags;
            public IntPtr Domain;
            public IntPtr NameServer;
            public IntPtr SearchList;
            public uint RegistrationEnabled;
            public uint RegisterAdapterName;
            public uint EnableLLMNR;
            public uint QueryAdapterName;
            public IntPtr ProfileNameServer;
            public uint DisableUnconstrainedQueries;
            public IntPtr SupplementalSearchList;
            public uint cServerProperties;
            public IntPtr ServerProperties;
            public uint cProfileServerProperties;
            public IntPtr ProfileServerProperties;
        }

        [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint SetInterfaceDnsSettings(
            Guid Interface, ref DNS_INTERFACE_SETTINGS3 Settings);

        [DllImport("iphlpapi.dll", CharSet = CharSet.Unicode)]
        private static extern uint GetInterfaceDnsSettings(
            Guid Interface, ref DNS_INTERFACE_SETTINGS3 Settings);

        [DllImport("iphlpapi.dll")]
        private static extern void FreeInterfaceDnsSettings(
            ref DNS_INTERFACE_SETTINGS3 Settings);

        public static DnsInterfaceState Read(Guid interfaceGuid, bool ipv6) {
            // The supported builds require DNS_SETTING_IPV6 to select the
            // IPv6 family. This is live-validated because Microsoft's getter
            // page otherwise documents only the IPv4/default invocation.
            var settings = new DNS_INTERFACE_SETTINGS3 {
                Version = 3,
                Flags = ipv6 ? 0x0001UL : 0UL
            };
            uint result = GetInterfaceDnsSettings(interfaceGuid, ref settings);
            if (result != 0) {
                throw new Win32Exception((int)result, "GetInterfaceDnsSettings failed");
            }
            try {
                if (settings.cServerProperties > 64) {
                    throw new InvalidOperationException("DNS interface property count exceeds the bounded contract");
                }
                var properties = new List<DnsDohPropertyState>();
                int propertySize = Marshal.SizeOf(typeof(DNS_SERVER_PROPERTY));
                for (int index = 0; index < settings.cServerProperties; index++) {
                    var property = (DNS_SERVER_PROPERTY)Marshal.PtrToStructure(
                        IntPtr.Add(settings.ServerProperties, propertySize * index),
                        typeof(DNS_SERVER_PROPERTY));
                    ulong flags = 0;
                    string template = null;
                    ushort port = 0;
                    if (property.Type == 1) {
                        var doh = (DNS_DOH_SERVER_SETTINGS)Marshal.PtrToStructure(
                            property.Property, typeof(DNS_DOH_SERVER_SETTINGS));
                        flags = doh.Flags;
                        template = doh.Template == IntPtr.Zero
                            ? null : Marshal.PtrToStringUni(doh.Template);
                    }
                    else {
                        throw new InvalidOperationException("Unsupported DNS server property type: " + property.Type);
                    }
                    properties.Add(new DnsDohPropertyState {
                        Version = property.Version,
                        ServerIndex = property.ServerIndex,
                        Type = property.Type,
                        Flags = flags,
                        Template = template,
                        Port = port
                    });
                }
                return new DnsInterfaceState {
                    NameServer = settings.NameServer == IntPtr.Zero
                        ? null : Marshal.PtrToStringUni(settings.NameServer),
                    Properties = properties.ToArray()
                };
            }
            finally {
                FreeInterfaceDnsSettings(ref settings);
            }
        }

        public static void Write(
            Guid interfaceGuid,
            string[] servers,
            bool ipv6,
            DnsDohPropertyState[] requestedProperties,
            ulong propertySelection) {
            if (servers == null || servers.Length == 0) {
                throw new ArgumentException("At least one DNS server is required");
            }
            if (requestedProperties == null) {
                requestedProperties = new DnsDohPropertyState[0];
            }

            var allocations = new List<IntPtr>();
            try {
                IntPtr nameServer = Marshal.StringToHGlobalUni(String.Join(",", servers));
                allocations.Add(nameServer);
                IntPtr properties = IntPtr.Zero;
                int propertySize = Marshal.SizeOf(typeof(DNS_SERVER_PROPERTY));
                if (requestedProperties.Length > 0) {
                    properties = Marshal.AllocHGlobal(propertySize * requestedProperties.Length);
                    allocations.Add(properties);
                }

                for (int index = 0; index < requestedProperties.Length; index++) {
                    var requested = requestedProperties[index];
                    IntPtr template = IntPtr.Zero;
                    if (requested.Template != null) {
                        template = Marshal.StringToHGlobalUni(requested.Template);
                        allocations.Add(template);
                    }
                    IntPtr propertyPointer;
                    if (requested.Type == 1) {
                        var doh = new DNS_DOH_SERVER_SETTINGS {
                            Template = template,
                            Flags = requested.Flags
                        };
                        propertyPointer = Marshal.AllocHGlobal(
                            Marshal.SizeOf(typeof(DNS_DOH_SERVER_SETTINGS)));
                        allocations.Add(propertyPointer);
                        Marshal.StructureToPtr(doh, propertyPointer, false);
                    }
                    else {
                        throw new ArgumentException("Unsupported DNS server property type");
                    }
                    var property = new DNS_SERVER_PROPERTY {
                        Version = requested.Version,
                        ServerIndex = requested.ServerIndex,
                        Type = requested.Type,
                        Property = propertyPointer
                    };
                    Marshal.StructureToPtr(
                        property,
                        IntPtr.Add(properties, propertySize * index),
                        false);
                }

                if (propertySelection != 0x1000UL) {
                    throw new ArgumentException("Invalid secure-DNS property selection");
                }

                var settings = new DNS_INTERFACE_SETTINGS3 {
                    Version = 3,
                    // The property index resolves against NameServer, so the
                    // native call atomically supplies the resolver list and
                    // its explicit secure-DNS properties.
                    Flags = 0x0002UL | propertySelection | (ipv6 ? 0x0001UL : 0UL),
                    NameServer = nameServer,
                    cServerProperties = (uint)requestedProperties.Length,
                    ServerProperties = properties
                };
                uint result = SetInterfaceDnsSettings(interfaceGuid, ref settings);
                if (result != 0) {
                    throw new Win32Exception((int)result,
                        "SetInterfaceDnsSettings failed (Win32 " + result + ")");
                }
            }
            finally {
                for (int index = allocations.Count - 1; index >= 0; index--) {
                    Marshal.FreeHGlobal(allocations[index]);
                }
            }
        }
    }
}
'@ -Language CSharp -ErrorAction Stop
}

function Get-DnsInterfaceDohState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$InterfaceGuid,
        [Parameter(Mandatory = $true)][ValidateSet(2, 23)][int]$AddressFamily
    )

    Initialize-DnsInterfaceDohNativeApi
    $guid = [Guid]::Empty
    if (-not [Guid]::TryParse($InterfaceGuid.Trim([char[]]@('{', '}')), [ref]$guid)) {
        throw "Invalid DNS interface GUID: $InterfaceGuid"
    }
    $native = [NoIDPrivacy.DnsInterfaceNative]::Read($guid, ($AddressFamily -eq 23))
    $servers = @()
    if (-not [string]::IsNullOrWhiteSpace([string]$native.NameServer)) {
        foreach ($server in @([regex]::Split(([string]$native.NameServer).Trim(), '[,\s]+') | Where-Object { $_ })) {
            $servers += ConvertTo-DnsCanonicalAddress -Address ([string]$server)
        }
    }
    if (@($native.Properties).Count -gt 0 -and $servers.Count -eq 0) {
        throw "Native interface secure-DNS properties have no resolver list: $InterfaceGuid/$AddressFamily"
    }
    $properties = @(foreach ($property in @($native.Properties | Sort-Object ServerIndex)) {
            # ENABLE_AUTO derives the effective template from Windows' global
            # endpoint registration. Canonicalize that derived output to null,
            # which is the documented input required for exact replay.
            $usesAutomaticMetadata = (
                [int]$property.Type -eq 1 -and ([uint64]$property.Flags -band 0x0001) -ne 0
            )
            $canonicalTemplate = if ($usesAutomaticMetadata) {
                $null
            }
            else { [string]$property.Template }
            [PSCustomObject]@{
                Version     = [int]$property.Version
                ServerIndex = [int]$property.ServerIndex
                Type        = [int]$property.Type
                Flags       = [uint64]$property.Flags
                Template    = $canonicalTemplate
                Port        = [int]$property.Port
            }
        })
    return [PSCustomObject]@{
        AddressFamily = $AddressFamily
        NameServers   = @($servers)
        Properties    = @($properties)
    }
}

function ConvertTo-DnsInterfaceDohTargetState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet(2, 23)][int]$AddressFamily,
        [Parameter(Mandatory = $true)][string[]]$NameServers,
        [Parameter(Mandatory = $true)][string]$DohTemplate,
        [Parameter(Mandatory = $true)][bool]$AllowFallbackToUdp
    )

    $servers = @($NameServers | ForEach-Object { ConvertTo-DnsCanonicalAddress -Address ([string]$_) })
    if ($servers.Count -eq 0 -or @($servers | Sort-Object -Unique).Count -ne $servers.Count) {
        throw 'Native interface DoH target requires a non-empty, duplicate-free server list'
    }
    $templateUri = $null
    if (-not [Uri]::TryCreate($DohTemplate, [UriKind]::Absolute, [ref]$templateUri) -or
        $templateUri.Scheme -ne 'https') {
        throw 'Native interface DoH target requires a valid HTTPS template'
    }
    $flags = if ($AllowFallbackToUdp) { [uint64]0x0006 } else { [uint64]0x0002 }
    return [PSCustomObject]@{
        AddressFamily = $AddressFamily
        NameServers   = @($servers)
        Properties    = @(for ($index = 0; $index -lt $servers.Count; $index++) {
                [PSCustomObject]@{
                    Version = 1; ServerIndex = $index; Type = 1
                    Flags = $flags; Template = $DohTemplate
                    Port = 0
                }
            })
    }
}

function Test-DnsInterfaceDohStateExact {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)]$Expected
    )
    return (($Actual | ConvertTo-Json -Compress -Depth 8) -ceq
        ($Expected | ConvertTo-Json -Compress -Depth 8))
}

function Set-DnsInterfaceDohState {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)][string]$InterfaceGuid,
        [Parameter(Mandatory = $true)][ValidateSet(2, 23)][int]$AddressFamily,
        [Parameter(Mandatory = $true)][string[]]$NameServers,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Properties
    )

    Initialize-DnsInterfaceDohNativeApi
    $guid = [Guid]::Empty
    if (-not [Guid]::TryParse($InterfaceGuid.Trim([char[]]@('{', '}')), [ref]$guid)) {
        throw "Invalid DNS interface GUID: $InterfaceGuid"
    }
    if (-not $PSCmdlet.ShouldProcess(
            "$InterfaceGuid/$AddressFamily",
            'Set exact native per-interface secure-DNS properties')) {
        return $false
    }
    $canonicalServers = @($NameServers | ForEach-Object {
            $parsed = [System.Net.IPAddress]::Parse([string]$_)
            $expectedFamily = if ($AddressFamily -eq 2) {
                [System.Net.Sockets.AddressFamily]::InterNetwork
            }
            else { [System.Net.Sockets.AddressFamily]::InterNetworkV6 }
            if ($parsed.AddressFamily -ne $expectedFamily) {
                throw "DNS interface server belongs to the wrong family: $_"
            }
            $parsed.ToString()
        })
    if ($canonicalServers.Count -eq 0 -or
        @($canonicalServers | Sort-Object -Unique).Count -ne $canonicalServers.Count) {
        throw 'DNS interface state requires a non-empty, duplicate-free server list'
    }

    $seenIndexes = @{}
    $nativeProperties = [System.Collections.Generic.List[NoIDPrivacy.DnsDohPropertyState]]::new()
    foreach ($property in @($Properties | Sort-Object ServerIndex)) {
        $index = [int]$property.ServerIndex
        $flags = [uint64]$property.Flags
        if ([int]$property.Version -ne 1 -or
            $index -lt 0 -or $index -ge $canonicalServers.Count -or
            $seenIndexes.ContainsKey($index)) {
            throw 'DNS interface DoH property identity is invalid or duplicated'
        }
        $seenIndexes[$index] = $true
        $propertyType = [int]$property.Type
        $unsupportedFlagMask = [uint64]::MaxValue - [uint64]0x3F
        if ($propertyType -ne 1 -or ($flags -band $unsupportedFlagMask) -ne 0) {
            throw "DNS interface secure-property type/flags are unsupported: type=$propertyType flags=$flags"
        }
        $template = [string]$property.Template
        $port = [int]$property.Port
        if ($propertyType -eq 1) {
            $enableAuto = ($flags -band 0x0001) -ne 0
            $enableTemplate = ($flags -band 0x0002) -ne 0
            if ($enableAuto -eq $enableTemplate -or $port -ne 0) {
                throw "DNS interface DoH property has unsupported flags/port: $flags/$port"
            }
            $template = if ($enableAuto) { $null } else { $template }
            $uri = $null
            if ($enableTemplate -and
                ([string]::IsNullOrWhiteSpace($template) -or
                 -not [Uri]::TryCreate($template, [UriKind]::Absolute, [ref]$uri) -or
                 $uri.Scheme -ne 'https')) {
                throw 'DNS interface DoH property has an invalid HTTPS template'
            }
        }
        $nativeProperties.Add([NoIDPrivacy.DnsDohPropertyState]@{
                Version = 1; ServerIndex = [uint32]$index; Type = [uint32]$propertyType
                Flags = $flags; Template = $template; Port = [uint16]$port
            })
    }

    $actualBefore = Get-DnsInterfaceDohState -InterfaceGuid $InterfaceGuid -AddressFamily $AddressFamily
    $actualSelection = [uint64]0
    foreach ($property in @($actualBefore.Properties)) {
        $actualSelection = $actualSelection -bor $(if ([int]$property.Type -eq 1) {
                [uint64]0x1000
            }
            else { throw 'Unsupported native secure-DNS property type in current state' })
    }
    $nativeArray = [NoIDPrivacy.DnsDohPropertyState[]]$nativeProperties.ToArray()
    $desiredSelection = [uint64]0
    foreach ($property in @($Properties)) {
        $desiredSelection = $desiredSelection -bor $(if ([int]$property.Type -eq 1) {
                [uint64]0x1000
            }
            else { throw 'Unsupported native secure-DNS property type in target state' })
    }
    $staleSelection = $actualSelection -band (-bnot $desiredSelection)
    if ($staleSelection -ne 0) {
        # Clear only a property type that was actually present. This avoids
        # asking older supported builds to process a newer unused selector.
        [NoIDPrivacy.DnsInterfaceNative]::Write(
            $guid,
            [string[]]$canonicalServers,
            ($AddressFamily -eq 23),
            [NoIDPrivacy.DnsDohPropertyState[]]@(),
            $staleSelection)
    }
    if ($desiredSelection -ne 0) {
        [NoIDPrivacy.DnsInterfaceNative]::Write(
            $guid,
            [string[]]$canonicalServers,
            ($AddressFamily -eq 23),
            $nativeArray,
            $desiredSelection)
    }
    elseif ($actualSelection -ne 0 -and $staleSelection -eq 0) {
        [NoIDPrivacy.DnsInterfaceNative]::Write(
            $guid,
            [string[]]$canonicalServers,
            ($AddressFamily -eq 23),
            [NoIDPrivacy.DnsDohPropertyState[]]@(),
            $actualSelection)
    }

    $actual = Get-DnsInterfaceDohState -InterfaceGuid $InterfaceGuid -AddressFamily $AddressFamily
    $expected = [PSCustomObject]@{
        AddressFamily = $AddressFamily
        NameServers   = @($canonicalServers)
        Properties    = @(foreach ($property in @($Properties | Sort-Object ServerIndex)) {
                [PSCustomObject]@{
                    Version = 1; ServerIndex = [int]$property.ServerIndex; Type = [int]$property.Type
                    Flags = [uint64]$property.Flags
                    Template = if (
                        [int]$property.Type -eq 1 -and ([uint64]$property.Flags -band 0x0001) -ne 0
                    ) { $null } else { [string]$property.Template }
                    Port = [int]$property.Port
                }
            })
    }
    if (-not (Test-DnsInterfaceDohStateExact -Actual $actual -Expected $expected)) {
        $actualJson = $actual | ConvertTo-Json -Compress -Depth 8
        $expectedJson = $expected | ConvertTo-Json -Compress -Depth 8
        throw "DNS interface DoH state verification failed for $InterfaceGuid/$AddressFamily; expected=$expectedJson; actual=$actualJson"
    }
    return $true
}

function Clear-DnsInterfaceDohPropertiesForResolverReset {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)][string]$InterfaceGuid,
        [Parameter(Mandatory = $true)][ValidateSet(2, 23)][int]$AddressFamily,
        [Parameter(Mandatory = $true)][string[]]$CurrentNameServers
    )

    Initialize-DnsInterfaceDohNativeApi
    $guid = [Guid]::Empty
    if (-not [Guid]::TryParse($InterfaceGuid.Trim([char[]]@('{', '}')), [ref]$guid)) {
        throw "Invalid DNS interface GUID: $InterfaceGuid"
    }
    $canonicalServers = @($CurrentNameServers | ForEach-Object {
            $parsed = [System.Net.IPAddress]::Parse([string]$_)
            $expectedFamily = if ($AddressFamily -eq 2) {
                [System.Net.Sockets.AddressFamily]::InterNetwork
            }
            else { [System.Net.Sockets.AddressFamily]::InterNetworkV6 }
            if ($parsed.AddressFamily -ne $expectedFamily) {
                throw "DNS interface server belongs to the wrong family: $_"
            }
            $parsed.ToString()
        })
    if ($canonicalServers.Count -eq 0 -or
        @($canonicalServers | Sort-Object -Unique).Count -ne $canonicalServers.Count) {
        throw 'DNS interface property clear requires a non-empty, duplicate-free current server list'
    }
    if (-not $PSCmdlet.ShouldProcess(
            "$InterfaceGuid/$AddressFamily",
            'Clear native secure-DNS properties before resetting the resolver source')) {
        return $false
    }

    $actualBefore = Get-DnsInterfaceDohState `
        -InterfaceGuid $InterfaceGuid -AddressFamily $AddressFamily
    if (@($actualBefore.Properties).Count -eq 0) {
        return $true
    }
    foreach ($property in @($actualBefore.Properties)) {
        if ([int]$property.Type -ne 1) {
            throw 'Unsupported native secure-DNS property type in current state'
        }
    }

    [NoIDPrivacy.DnsInterfaceNative]::Write(
        $guid,
        [string[]]$canonicalServers,
        ($AddressFamily -eq 23),
        [NoIDPrivacy.DnsDohPropertyState[]]@(),
        [uint64]0x1000)

    # Live Windows 11 behavior can clear the interface NameServer field when
    # its last DoH property is removed. That resolver list is deliberately not
    # accepted as a final state here: Restore-DNSSettings immediately invokes
    # the supported DNS-client reset/static cmdlet and later verifies the full
    # sealed native state exactly.
    $actualAfter = Get-DnsInterfaceDohState `
        -InterfaceGuid $InterfaceGuid -AddressFamily $AddressFamily
    if (@($actualAfter.Properties).Count -ne 0) {
        throw "DNS interface secure-DNS properties were not cleared for $InterfaceGuid/$AddressFamily"
    }
    return $true
}
