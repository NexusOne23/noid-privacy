function Resolve-DnsProviderSelection {
    <#
    .SYNOPSIS
        Map one interactive menu selection to its DNS provider identity.

    .DESCRIPTION
        Pure decision, kept separate from the interactive selection loop so the
        number-to-provider mapping is testable as a value. A swapped mapping
        would silently send a user who typed "3" (AdGuard, filtering) to an
        unfiltered resolver, so the unit tests pin the menu text and this
        mapping against each other.

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
