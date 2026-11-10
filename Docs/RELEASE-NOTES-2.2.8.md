# Release Notes — v2.2.8 (2026-10-18)

NoID Privacy 2.2.8 keeps the complete 2.2.7 product: Windows 11 24H2, 25H2
and 26H2 are all supported releases with the same seven modules, baselines,
Backup, Apply, Verify and Restore (BAVR) contract and counts. It fixes how
AdvancedSecurity handles network adapters that are not present or unplugged.
Declared default-decision total is now 656 (Strict 675, Paranoid 709), as in
2.2.7; every complete verification reports 709 targets. The [CHANGELOG](../CHANGELOG.md)
carries the short summary, and the [2.2.7 release notes](RELEASE-NOTES-2.2.7.md)
remain the reference for that release's changes.

## NetBIOS on adapters that are not present

Windows keeps listing some network adapters while their hardware is absent,
with the status `Not Present` in `Get-NetAdapter`. A reported case is a
laptop with an HP 5G modem: its mobile-broadband interfaces stay listed while
the modem is switched off, and Windows has no network configuration
(`Win32_NetworkAdapterConfiguration`) for them.

2.2.6 and 2.2.7 required such a configuration for every physical adapter. On
these PCs the AdvancedSecurity backup stopped with "NetBIOS adapter snapshot
failed: Physical network adapter '...' has no matching
Win32_NetworkAdapterConfiguration", so AdvancedSecurity applied nothing; the
other six modules still applied.

2.2.8 covers these adapters instead of stopping:

- Every physical adapter Windows lists is a NetBIOS target, including
  disconnected and disabled adapters and adapters that are not present.
- An adapter without a Windows network configuration is set through its NetBT
  value `NetbiosOptions=2` under
  `HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{GUID}`.
  This is the per-adapter setting Windows itself uses; it takes effect when the
  adapter connects. Adapters with an active network configuration are still
  set through the Windows network provider (`SetTcpipNetbios`) as before.
- Verify checks this value for every listed physical adapter, and Restore
  returns its exact prestate, including removing a key that did not exist
  before.
- A physical adapter without a stable adapter GUID still stops the backup.

## Restore with unplugged adapters

Each NetBIOS value belongs to one adapter GUID. Restore now returns every
backed-up value by that GUID:

- An adapter that was unplugged after Apply, such as a USB network adapter or
  a dock, gets its exact previous value back. Before, Restore stopped with
  "NetBIOS adapter inventory changed before Restore" until the adapter was
  plugged in again.
- An adapter connected after the backup was never changed and stays as it is.
- An adapter that Windows removed together with its NetBT key is reported in
  the log; nothing of it remains to restore.
- Apply now refuses to run when the adapter inventory changed after the
  backup, so the backup always holds every value Apply changes.

DNS servers, by contrast, can only be set through a connected adapter. When a
network adapter from the backup is unplugged, DNS Restore now says so and asks
you to reconnect it and run Restore again; it still changes nothing before
every adapter resolves.

## Wireless Display: Wi-Fi Direct adapters

With the optional complete Wireless Display disable, AdvancedSecurity also
disables the Wi-Fi Direct virtual adapters that most Wi-Fi adapters bring.
This path was tested on Windows 11 26H2 with a real USB Wi-Fi adapter for this
release. In 2.2.6 and 2.2.7 it could not be applied on any PC with a Wi-Fi
Direct adapter:

- The backup recorded each adapter's state as Windows PowerShell 5.1 writes the
  underlying enum, as a number. The backup's own validation accepts only "Up"
  or "Down", so Apply stopped before changing anything with "Wi-Fi Direct
  adapter artifact has invalid or duplicate stable identities". The backup now
  records "Up" or "Down".
- Wi-Fi Direct adapters are hidden adapters. Apply and Restore looked them up
  by name, which does not find hidden adapters and treats `*` in a name as a
  wildcard. They now change each adapter as the exact Windows object.
- Disabling a Wi-Fi Direct adapter makes Windows remove the role adapters it
  created beside it on demand, asynchronously; for a moment the role adapter is
  still listed. Apply now disables the oldest adapter first (Windows numbers
  later instances "#2", "#3", ...) and waits until the adapter set settles, so
  a role adapter is never disabled while Windows removes it.
- Restore re-enables in the same order and waits again. A role adapter that
  Windows has not created again matches the backup when its persisted device
  state does; Windows keeps a device's disabled state while the device is
  absent. If the Wi-Fi adapter itself is unplugged and its saved state differs,
  Restore says so and asks you to reconnect it and run Restore again; measured,
  that second Restore returns the exact prestate.
- Wi-Fi Direct adapters that Windows reports as not present carry no traffic
  and cannot change their state; they are outside the target in Backup, Apply,
  Verify and the Wireless Display Quick Action until their Wi-Fi adapter
  returns.
- The Wireless Display Quick Action stopped with "Quick Action Wi-Fi Direct
  adapter identity changed" on every PC with a Wi-Fi Direct adapter: Windows
  reports the adapter GUID with braces, and the action compared it as text with
  the normalized GUID it had saved. It now compares the parsed GUIDs and
  changes adapters in the same order as Apply.
- When Windows had created a role adapter, the Quick Action's Disable removed
  it as described above, and the action's own verification then saw a
  different adapter set. Verification, the automatic undo and the session
  Restore now compare against the adapters the action started with: an absent
  role adapter matches when Windows keeps its device in the recorded state or
  has removed the device, and a role adapter that Windows creates after Enable
  matches when it is Up. Every other difference still stops the action, and
  the state itself always comes from the live read. Measured with a role
  adapter present: Disable, session Restore, Disable and Enable completed, and
  the state returned to its exact starting fingerprint once Windows had
  created the role adapter again.

## Other fixes

- **Audit policies.** On a Windows 11 26H2 Home test PC, auditpol failed once
  for one of the 23 audit subcategories during a full test run; the run
  reported only "Audit policy application/verification failed" and the next
  runs passed. Apply and Restore now retry a failed auditpol call once. The
  exact readback of every subcategory still decides, and a remaining failure
  names the subcategory and auditpol's output in the log.
- **Headline.** The README and product texts now state 600+ checks instead of
  630+. The High Security profile applies 620 settings on Windows 11 Pro,
  which is below the former floor; the declared totals are unchanged.

## Upgrade

Replace the engine folder with the 2.2.8 release. Backups made with 2.2.5,
2.2.6 and 2.2.7 restore exactly as before; 2.2.8 introduces no backup
conversion. The configuration file must carry `"version": "2.2.8"`, which the
released `config.json` already does. A PC hardened with 2.2.7 needs no new
Apply; verification reports the same results, except that physical adapters
that are not present now appear in the NetBIOS check until the hardening is
applied again.
