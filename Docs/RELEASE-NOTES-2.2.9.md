# Release Notes — v2.2.9 (2026-10-19)

NoID Privacy 2.2.9 keeps the complete 2.2.8 product: Windows 11 24H2, 25H2
and 26H2 are all supported releases with the same seven modules, baselines,
Backup, Apply, Verify and Restore (BAVR) contract and counts. It fixes the DNS
backup on networks whose router announces its IPv6 resolver twice.
Declared default-decision total is now 656 (Strict 675, Paranoid 709), as in
2.2.8; every complete verification reports 709 targets. The [CHANGELOG](../CHANGELOG.md)
carries the short summary, and the [2.2.8 release notes](RELEASE-NOTES-2.2.8.md)
remain the reference for that release's changes.

## DNS behind routers that announce their IPv6 resolver twice

Many home routers announce their own IPv6 DNS resolver in two ways: in Router
Advertisements (the RDNSS option) and through DHCPv6. Windows then lists the
same address twice for the network adapter, for example in
`Get-DnsClientServerAddress -AddressFamily IPv6`.

2.2.6, 2.2.7 and 2.2.8 required every resolver address in the DNS backup to be
unique. On these PCs the DNS module stopped before changing anything with
"Failed to create complete DNS pre-state backup - DNS pre-state contains a
duplicate server for {...}/23", kept the attempt as an incomplete,
non-restorable DNS session and reported its five checks as not proven. The
other modules still applied.

2.2.9 accepts the repeated address where the list is only an observation:

- For an adapter that receives DNS automatically, Restore returns the adapter
  to automatic DNS and never writes the observed list back. The backup now
  records that list as Windows reports it, including a repeated address.
- A static DNS list, which Restore writes back exactly, must still be free of
  duplicates; the backup refuses a repeated static address as before.
- Measured on Windows 11 26H2 behind a router that announces the same IPv6
  resolver both ways: 2.2.8 stops as described above; 2.2.9 applies DNS,
  Verify passes all 5 DNS checks, and Restore returns the exact previous
  state, with the router-assigned resolver back in place.

The incomplete DNS sessions from earlier attempts contain nothing to restore.
Keep them or remove them; they do not affect a new run.

## Upgrade

Replace the engine folder with the 2.2.9 release. Backups made with 2.2.5,
2.2.6, 2.2.7 and 2.2.8 restore exactly as before; 2.2.9 introduces no backup
conversion. The configuration file must carry `"version": "2.2.9"`, which the
released `config.json` already does. A PC hardened with 2.2.8 needs no new
Apply. Where DNS stopped as described above, run DNS or the hardening again.
