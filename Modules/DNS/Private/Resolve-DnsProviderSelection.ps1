function Resolve-DnsProviderSelection {
    <#
    .SYNOPSIS
        Map one interactive menu selection to its DNS provider identity.

    .DESCRIPTION
        Pure decision, extracted from the interactive selection loop so the
        number-to-provider mapping is testable as a value. The mapping used to
        exist only inline: swapping two switch arms sent a user who read
        "[3] AdGuard DNS - RECOMMENDED FOR AD-BLOCKING" and typed 3 to
        Cloudflare's unfiltered resolver - no ad/tracker/malware filtering -
        while the confirmation line printed the provider it actually chose, so
        nothing looked wrong and no test failed. The menu text and this mapping
        are now pinned against each other by the unit tests.

        Follows the same pattern as SecurityBaseline's
        Read-StandardUserElevationModeChoice: the prompt loop stays where the
        prose lives; the decision is a pure function.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        # Raw operator input. Blank means "accept the default", which is Quad9.
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Selection
    )

    $normalized = if ([string]::IsNullOrWhiteSpace($Selection)) { '1' } else { $Selection.Trim() }

    switch ($normalized) {
        '1' { return 'Quad9' }
        '2' { return 'Cloudflare' }
        '3' { return 'AdGuard' }
        '0' { return $null }
        default {
            throw "Unsupported DNS provider selection: '$Selection'"
        }
    }
}
