# SecurityBaseline firmware and restart recovery — 2.2.6

The Microsoft 26H2 source, like its 25H2 predecessor, requests UEFI locks for LSA protection, Credential
Guard and memory integrity. A sealed registry backup does not capture those
firmware variables. Restoring its registry values cannot remove an activated
UEFI lock. That limitation also applies to existing 2.2.5 backups; changing a
backup reader cannot reconstruct firmware prestate that was never recorded.

## New Apply plan

The fixed 2.2.6 product decision is to keep BAVR recovery in Windows, with normal
restarts where necessary. No new option or EFI/BIOS opt-out workflow is added.
The four mappings below avoid creating firmware locks that a Windows-only
Restore could not remove. This is a deliberate security/recoverability trade-off,
not a requirement to change existing backup formats.

Version 2.2.6 maps these four source directives to the documented value `2`
when building the Apply and verification plans:

| HKLM key | Value | Microsoft source | Applied expectation |
|---|---|---:|---:|
| `SOFTWARE\Policies\Microsoft\Windows\System` | `RunAsPPL` | 1 | 2 |
| `SYSTEM\CurrentControlSet\Control\Lsa` | `RunAsPPL` | 1 | 2 |
| `SOFTWARE\Policies\Microsoft\Windows\DeviceGuard` | `LsaCfgFlags` | 1 | 2 |
| `SOFTWARE\Policies\Microsoft\Windows\DeviceGuard` | `HypervisorEnforcedCodeIntegrity` | 1 | 2 |

For these directives, `2` requests enabled protection without a new UEFI
lock. Protection still depends on Windows edition, hardware and successful
activation after restart. The security trade-off is that the new configuration
does not gain the additional firmware persistence that resists an administrator
disabling protection. These are four registry entries for three protection
features; the two RunAsPPL entries configure the same LSA protection. Apply
explains the trade-off before mutation. Existing firmware locks are
not removed, and the engine does not change Secure Boot or the bootloader.

The hash-bound source JSON retains Microsoft's `1` values. This is an explicit
application-model deviation, separate from the two embedded data deviations
documented in [baseline provenance](SECURITY-BASELINE-PROVENANCE.md). The mapping
checks complete key/value identities and changes exactly four data fields;
all real security directives remain in the 425-target plan. The separate
firewall format-metadata exclusion is documented in [baseline provenance](SECURITY-BASELINE-PROVENANCE.md).

Verify shows a compact **Windows protection at verification** summary in the
shell and HTML report, including both print modes. Policy checks establish
configuration; they do not establish that a boot-dependent protection is
running. The separate summary reads `Win32_DeviceGuard` for VBS, memory
integrity, Credential Guard, Secure Launch and kernel stack protection. LSA
uses WinInit event 12 from the current Windows boot and is labelled **Protected
at this boot**. An absent event means no evidence, not proof of disabled LSA.
Unreadable runtime evidence stays explicit. These observations add no policy
targets or backup fields, and do not change the existing setting-check counts
or their completion contract. The JSON export includes the same observation
under `SecurityBaselineRuntime`; HTML rendering never re-queries that state.
For newly applied protection, restart Windows and verify again. Persistent
inactivity requires checking hardware, drivers and edition requirements; it is
not automatically classified as an unsupported feature or a pending restart.
Restore instead recovers the recorded prestate: an originally inactive protection
can correctly be inactive again. The hardening verifier's policy counters do not
compare against a backup and are not a substitute for recovery verification.

Credential Guard is not supported on Windows Home. Microsoft's current edition
and licensing table lists Enterprise and Education; the separately documented
Pro exception concerns devices that previously ran Credential Guard, such as
after an Enterprise downgrade. Inactive Credential Guard on Home therefore does
not by itself indicate a failed Apply. VBS and memory integrity are separate
runtime observations. See
[Microsoft's edition requirements](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/#windows-edition-and-licensing-requirements).

On Windows Home, Apply additionally configures VBS and memory integrity through
[Microsoft's documented local registry controls](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity#enable-memory-integrity-using-registry).
The local path retains Secure Boot and the
baseline's `HVCIMATRequired=1` requirement; Microsoft also demonstrates that
[local MAT setting](https://github.com/microsoft/MSLab/blob/master/Scenarios/DeviceGuard/VBS/readme.md).
Local activation requires both recorded `Locked` values to be absent or DWORD
`0`. An existing nonzero or unfamiliar lock configuration blocks activation
before any local control is written; its original name, type and data remain
unchanged. A recorded `Locked=1` can request a new firmware binding at the next
boot even when protection is currently inactive. Apply therefore neither clears
that value nor treats `Enabled=1` as proof that the lock already exists in
firmware. This check also retains a pre-existing active protection unchanged.
An existing DWORD `0` is preserved; original absence permits writing `0`.
All six local targets are already captured by the twenty-value backup and the
first recovery supplement. Their schema and Restore implementation are unchanged.
Pro, Enterprise and Education retain native policy processing. This Home
activation path neither adds policy targets nor claims Credential Guard support;
running protection is observed separately after restart.

## Backup compatibility and recovery limits

New 2.2.6 sessions also seal `DeviceGuardGpo.json`: the original eight native
GPO values, their types/bytes and names, key/ancestor existence and this tool's
editor registrations. The existing schema-4 `RegistryPolicies.json` additionally
captures 20 local controls that Windows can materialize. These are backup
targets, not extra baseline settings: Apply/Verify retain their 425-target plan.
All prestate is reconciled before and after manifest sealing, before the first
native Save can notify Windows. Restore restores the GPO prestate first and
then the effective/local registry prestate. It never replaces a shared historical
policy file or GPO directory. Native GPO revision bookkeeping can advance. On a
system that never had a local GPO, the first native Save creates an empty one
(`gpt.ini`, `Machine\Registry.pol` and the `Machine`/`User` folders); Restore
leaves this empty, policy-free structure in place.

The added artifact is optional for historical sessions. New sessions require
complete corresponding local prestate, and an absent file declared in a sealed
manifest is an error. Existing 2.2.5+ artifacts are neither migrated nor rewritten.

The engine retains a machine-local supplement before the first native
Device Guard Apply, at
`%ProgramData%\NoID Privacy\EngineState\deviceguard-legacy-recovery.json`.
It contains the original eight GPO values/editor registrations, the twenty
recorded local controls and their source hashes. Only Administrators and SYSTEM
can write it. Publication is atomic and create-only; subsequent Apply and
Restore operations preserve the first record. It remains usable after moving
the original backup folder and is independent of timestamps and restore receipts.

When a historical session has no GPO artifact, Restore first uses this supplement
to undo the native backend introduced on that machine, then restores the
historical session's own recorded values. New complete sessions use their own
prestate. Neither path substitutes Apply defaults. Missing or damaged recovery
evidence cannot produce a successful native-backend recovery; restore a retained
complete newer baseline backup first if the supplement has been lost. Preserve
this EngineState file with the machine's recovery data. It records the state
before introduction of this backend, not an inferred state at the date of an
older backup. Changes predating that capture which the older writer never
recorded cannot be reconstructed.

Backup schemas, recorded target identities and historical restore values are
unchanged by this mapping. A valid 2.2.5-or-newer backup still restores its
recorded values, including `1`, `2`, other original data or original absence.
Restore does not replace those values with the new Apply defaults. The
published 2.2.4 release remains the recovery path for its older backup format.

Registry equality immediately after Restore is not evidence that firmware and
boot-time runtime state have returned to their original state. In particular,
Microsoft documents that deleting Credential Guard registry settings may not
disable the feature; its documented disable procedure writes `0` and requires
a restart. That operation is different from restoring an originally absent
value and must not be hidden behind an exact-prestate success claim.

Existing UEFI locks need the relevant Microsoft recovery procedure and, where
required, physical confirmation. The engine does not silently clear firmware
variables, modify boot entries or disable Secure Boot to obtain a passing
restore result.

## Shell and GUI disclosure

The shell module description, Apply explanation and 2.2.6 release documentation
identify this fixed BAVR decision. GUI consumers must carry the same explanation in
their SecurityBaseline module details, BAVR help and release notes.

The explanation must name the four `1` to `2` mappings, the omitted firmware
resistance to privileged reconfiguration, the Windows-based recovery reason and
the unchanged original-value behavior for 2.2.5-or-newer backups. It must not
claim that an enabled policy proves active protection on every edition or device.
Keep one relevant explanation rather than repeated warning rows, and add no
configuration toggle for this decision.

## Microsoft references

- [Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
- [LocalSecurityAuthority policy mapping](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-lsa)
- [Configure Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure)
- [Memory integrity policy values](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-virtualizationbasedtechnology)
- [Enable memory integrity and recovery considerations](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity)
