#Requires -Version 5.1

function Initialize-AdvancedSecurityFirewallGpoStore {
    [CmdletBinding()]
    param()
    if (-not ('NoIDPrivacy.FirewallGpoStore' -as [type])) {
        # Authored interop for the documented IGroupPolicyObject interface.
        # The vtable order and identifiers follow Microsoft's GPEdit.h.
        # https://learn.microsoft.com/windows/win32/api/gpedit/nn-gpedit-igrouppolicyobject
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace NoIDPrivacy {
    [ComImport, Guid("EA502723-A23D-11D1-A7D3-0000F87571E3"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IFirewallGroupPolicyObject {
        [PreserveSig] int New(IntPtr domain, IntPtr name, uint flags);
        [PreserveSig] int OpenDSGPO(IntPtr path, uint flags);
        [PreserveSig] int OpenLocalMachineGPO(uint flags);
        [PreserveSig] int OpenRemoteMachineGPO(IntPtr machine, uint flags);
        [PreserveSig] int Save([MarshalAs(UnmanagedType.Bool)] bool machine, [MarshalAs(UnmanagedType.Bool)] bool add, ref Guid extension, ref Guid editor);
        [PreserveSig] int Delete();
        [PreserveSig] int GetName(IntPtr name, uint length);
        [PreserveSig] int GetDisplayName(IntPtr name, uint length);
        [PreserveSig] int SetDisplayName(IntPtr name);
        [PreserveSig] int GetPath(IntPtr path, uint length);
        [PreserveSig] int GetDSPath(uint section, IntPtr path, uint length);
        [PreserveSig] int GetFileSysPath(uint section, IntPtr path, uint length);
        [PreserveSig] int GetRegistryKey(uint section, out IntPtr key);
    }

    public sealed class FirewallGpoInventory {
        public readonly Dictionary<string,string> Sources = new Dictionary<string,string>(StringComparer.Ordinal);
        public readonly Dictionary<string,string> Mirrors = new Dictionary<string,string>(StringComparer.Ordinal);
        public readonly Dictionary<string,bool> UnownedGpo = new Dictionary<string,bool>(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string,bool> UnownedLocal = new Dictionary<string,bool>(StringComparer.OrdinalIgnoreCase);
    }

    public static class FirewallGpoStore {
        private const string Firewall = @"SOFTWARE\Policies\Microsoft\WindowsFirewall";
        private const string LocalFirewall = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        private const string RegistryExtension = "35378eac-683f-11d2-a89a-00c04fbbcfa2";
        private const string Editor = "b05566ac-fe9c-4368-be01-7a4cbb6cba11";

        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, EntryPoint="GetPrivateProfileStringW")]
        private static extern uint ReadIni(string section, string key, string fallback,
            StringBuilder value, uint length, string path);

        private sealed class RuleStore {
            internal readonly Dictionary<string,string> Rules = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
            internal int? PolicyVersion;
            internal bool VersionTypeValid = true;
        }

        private static RuleStore ReadRules(RegistryKey firewall) {
            RuleStore result = new RuleStore();
            if (firewall == null) return result;
            object version = firewall.GetValue("PolicyVersion", null, RegistryValueOptions.DoNotExpandEnvironmentNames);
            if (version != null) {
                result.VersionTypeValid = firewall.GetValueKind("PolicyVersion") == RegistryValueKind.DWord;
                if (result.VersionTypeValid) result.PolicyVersion = (int)version;
            }
            using (RegistryKey rules = firewall.OpenSubKey("FirewallRules", false)) {
                if (rules != null) foreach (string name in rules.GetValueNames()) {
                    // Unknown foreign value types still reserve their names. Never
                    // reinterpret, overwrite or delete them as owned rule data.
                    string data = rules.GetValueKind(name) == RegistryValueKind.String
                        ? rules.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) as string : null;
                    result.Rules.Add(name, data);
                }
            }
            return result;
        }

        private static RuleStore ReadLocalRules() {
            using (RegistryKey machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (RegistryKey firewall = machine.OpenSubKey(LocalFirewall, false)) {
                if (firewall == null) throw new InvalidOperationException("Local firewall policy store is unavailable");
                return ReadRules(firewall);
            }
        }

        private static bool IsOwned(string data, string group) {
            if (data == null) return false;
            int fields = 0, matches = 0;
            foreach (string field in data.Split('|')) {
                if (!field.StartsWith("EmbedCtxt=", StringComparison.Ordinal)) continue;
                fields++;
                if (String.Equals(field, "EmbedCtxt=" + group, StringComparison.Ordinal)) matches++;
            }
            if (matches != 0 && (fields != 1 || matches != 1))
                throw new InvalidOperationException("Native firewall rule ownership is ambiguous");
            return matches == 1;
        }

        private static FirewallGpoInventory Inventory(RuleStore local, RuleStore gpo, string[] names, string group, string suffix) {
            HashSet<string> catalog = new HashSet<string>(names, StringComparer.Ordinal);
            if (catalog.Count != names.Length || catalog.Count == 0 || String.IsNullOrEmpty(group) || String.IsNullOrEmpty(suffix))
                throw new ArgumentException("Invalid firewall recovery catalog");
            FirewallGpoInventory result = new FirewallGpoInventory();
            foreach (KeyValuePair<string,string> rule in local.Rules) {
                if (!IsOwned(rule.Value, group)) { result.UnownedLocal.Add(rule.Key, true); continue; }
                if (!rule.Key.EndsWith(suffix, StringComparison.Ordinal))
                    throw new InvalidOperationException("An unknown local rule uses the reserved NoID firewall mirror group");
                string name = rule.Key.Substring(0, rule.Key.Length - suffix.Length);
                if (!catalog.Contains(name)) throw new InvalidOperationException("Unknown NoID firewall recovery-copy identity");
                result.Sources.Add(name, rule.Value);
            }
            foreach (KeyValuePair<string,string> rule in gpo.Rules) {
                if (!IsOwned(rule.Value, group)) { result.UnownedGpo.Add(rule.Key, true); continue; }
                if (!catalog.Contains(rule.Key)) throw new InvalidOperationException("An unknown GPO rule uses the reserved NoID firewall mirror group");
                result.Mirrors.Add(rule.Key, rule.Value);
            }
            return result;
        }

        private static bool EqualRules(IDictionary<string,string> first, IDictionary<string,string> second) {
            if (first.Count != second.Count) return false;
            foreach (KeyValuePair<string,string> rule in first) {
                string value;
                if (!second.TryGetValue(rule.Key, out value) || !String.Equals(rule.Value, value, StringComparison.Ordinal)) return false;
            }
            return true;
        }

        public static FirewallGpoInventory ReadOwnedState(string[] names, string group, string suffix, string policyDirectory) {
            string policyFile = Path.Combine(policyDirectory, @"Machine\Registry.pol");
            string versionFile = Path.Combine(policyDirectory, "gpt.ini");
            byte[] policy = ReadPolicyFile(policyFile), version = ReadPolicyFile(versionFile);
            if (policy == null) {
                // No persisted machine registry policy means no GPO firewall
                // rules. Avoid creating native GPO bookkeeping just to inspect
                // an empty store, including on Home and legacy WFW recovery.
                FirewallGpoInventory empty = Inventory(ReadLocalRules(), new RuleStore(), names, group, suffix);
                if (ReadPolicyFile(policyFile) != null || !EqualBytes(version, ReadPolicyFile(versionFile)))
                    throw new InvalidOperationException("Local GPO appeared during firewall inventory; retry");
                return empty;
            }
            IFirewallGroupPolicyObject gpo = null;
            try {
                gpo = (IFirewallGroupPolicyObject)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("EA502722-A23D-11D1-A7D3-0000F87571E3")));
                // A computer-name policy store can require ADMIN$ even for
                // localhost. This documented local API needs no SMB share.
                Check(gpo.OpenLocalMachineGPO(3)); // LOAD_REGISTRY | READ_ONLY
                IntPtr key;
                Check(gpo.GetRegistryKey(2, out key));
                using (SafeRegistryHandle handle = new SafeRegistryHandle(key, true))
                using (RegistryKey machine = RegistryKey.FromHandle(handle, RegistryView.Registry64))
                using (RegistryKey firewall = machine.OpenSubKey(Firewall, false)) {
                    FirewallGpoInventory result = Inventory(ReadLocalRules(), ReadRules(firewall), names, group, suffix);
                    if (!EqualBytes(policy, ReadPolicyFile(policyFile)) || !EqualBytes(version, ReadPolicyFile(versionFile)))
                        throw new InvalidOperationException("Local GPO changed during firewall inventory; retry");
                    return result;
                }
            }
            finally { if (gpo != null) Marshal.FinalReleaseComObject(gpo); }
        }

        public static bool SynchronizeOwnedRules(string[] names, string group, string suffix,
            IDictionary<string,string> expectedSources, string[] selectedNames, string policyDirectory) {
            HashSet<string> catalog = new HashSet<string>(names, StringComparer.Ordinal);
            string[] scope = selectedNames ?? names;
            HashSet<string> selection = new HashSet<string>(scope, StringComparer.Ordinal);
            if (selection.Count == 0 || selection.Count != scope.Length || !selection.IsSubsetOf(catalog))
                throw new ArgumentException("Invalid selected firewall synchronization scope");
            FirewallGpoInventory planned = ReadOwnedState(names, group, suffix, policyDirectory);
            if (!EqualRules(expectedSources, planned.Sources))
                throw new InvalidOperationException("NoID firewall recovery sources changed before synchronization");
            foreach (string name in planned.Sources.Keys) {
                if (planned.UnownedGpo.ContainsKey(name))
                    throw new InvalidOperationException("Firewall synchronization would overwrite an unowned local-GPO rule");
            }
            bool needsSave = false;
            foreach (string name in scope) {
                string source, mirror;
                bool hasSource = planned.Sources.TryGetValue(name, out source);
                bool hasMirror = planned.Mirrors.TryGetValue(name, out mirror);
                if (hasSource != hasMirror || (hasSource && !String.Equals(source, mirror, StringComparison.Ordinal))) needsSave = true;
            }
            if (!needsSave) return false;
            string policyFile = Path.Combine(policyDirectory, @"Machine\Registry.pol");
            string versionFile = Path.Combine(policyDirectory, "gpt.ini");
            byte[] policy = ReadPolicyFile(policyFile), version = ReadPolicyFile(versionFile);
            IFirewallGroupPolicyObject gpo = null;
            try {
                gpo = (IFirewallGroupPolicyObject)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("EA502722-A23D-11D1-A7D3-0000F87571E3")));
                Check(gpo.OpenLocalMachineGPO(1)); // LOAD_REGISTRY; private editable hive
                IntPtr key;
                Check(gpo.GetRegistryKey(2, out key));
                using (SafeRegistryHandle handle = new SafeRegistryHandle(key, true))
                using (RegistryKey machine = RegistryKey.FromHandle(handle, RegistryView.Registry64)) {
                    byte[] openedPolicy = ReadPolicyFile(policyFile), openedVersion = ReadPolicyFile(versionFile);
                    if (IsEmptyGptInitialization(policy, version, openedPolicy, openedVersion) &&
                        machine.ValueCount == 0 && machine.SubKeyCount == 0) {
                        // The first writable native open creates only gpt.ini's
                        // empty header. Advance this operation's guard, never
                        // the sealed backup or an existing policy revision.
                        version = openedVersion;
                    }
                    if (!EqualBytes(policy, openedPolicy) || !EqualBytes(version, openedVersion))
                        throw new InvalidOperationException("Local GPO changed before firewall synchronization; retry");
                    RuleStore local = ReadLocalRules(), existing;
                    using (RegistryKey firewall = machine.OpenSubKey(Firewall, false)) { existing = ReadRules(firewall); }
                    FirewallGpoInventory state = Inventory(local, existing, names, group, suffix);
                    if (!EqualRules(expectedSources, state.Sources))
                        throw new InvalidOperationException("NoID firewall recovery sources changed before synchronization");
                    foreach (string name in state.Sources.Keys) {
                        if (state.UnownedGpo.ContainsKey(name))
                            throw new InvalidOperationException("Firewall synchronization would overwrite an unowned local-GPO rule");
                    }
                    bool changed = false;
                    foreach (string name in scope) {
                        string desired, previous;
                        if (state.Sources.TryGetValue(name, out desired)) {
                            if (state.Mirrors.TryGetValue(name, out previous) && String.Equals(desired, previous, StringComparison.Ordinal)) continue;
                            if (!local.VersionTypeValid || !local.PolicyVersion.HasValue || !existing.VersionTypeValid)
                                throw new InvalidOperationException("Native firewall format metadata is missing or invalid");
                            using (RegistryKey firewall = machine.CreateSubKey(Firewall)) {
                                if (!existing.PolicyVersion.HasValue || (uint)existing.PolicyVersion.Value < (uint)local.PolicyVersion.Value)
                                    firewall.SetValue("PolicyVersion", local.PolicyVersion.Value, RegistryValueKind.DWord);
                                using (RegistryKey rules = firewall.CreateSubKey("FirewallRules")) {
                                    // Copy the complete Windows-generated native string,
                                    // including unknown future fields; do not rebuild it.
                                    rules.SetValue(name, desired, RegistryValueKind.String);
                                }
                            }
                            changed = true;
                        }
                        else if (state.Mirrors.ContainsKey(name)) {
                            using (RegistryKey rules = machine.OpenSubKey(Firewall + @"\FirewallRules", true)) { rules.DeleteValue(name, true); }
                            changed = true;
                        }
                    }
                    if (!changed) return false;
                    using (RegistryKey firewall = machine.OpenSubKey(Firewall, true)) {
                        if (firewall != null) {
                            bool emptyRules;
                            using (RegistryKey rules = firewall.OpenSubKey("FirewallRules", false)) {
                                emptyRules = rules != null && rules.ValueCount == 0 && rules.SubKeyCount == 0;
                            }
                            if (emptyRules) firewall.DeleteSubKey("FirewallRules", true);
                            if (firewall.SubKeyCount == 0 && firewall.ValueCount == 1 &&
                                firewall.GetValueNames()[0] == "PolicyVersion" && firewall.GetValueKind("PolicyVersion") == RegistryValueKind.DWord)
                                firewall.DeleteValue("PolicyVersion", true);
                        }
                    }
                    PruneEmptyAncestors(machine, Firewall);
                    RuleStore currentLocal = ReadLocalRules();
                    if (!EqualRules(state.Sources, Inventory(currentLocal, existing, names, group, suffix).Sources) ||
                        local.PolicyVersion != currentLocal.PolicyVersion || local.VersionTypeValid != currentLocal.VersionTypeValid)
                        throw new InvalidOperationException("NoID firewall recovery sources changed during synchronization");
                    if (!EqualBytes(policy, ReadPolicyFile(policyFile)) || !EqualBytes(version, ReadPolicyFile(versionFile)))
                        throw new InvalidOperationException("Local GPO changed during firewall synchronization; retry");
                    Guid extension = new Guid(RegistryExtension);
                    Guid editor = new Guid(Editor);
                    // Persist all selected changes and final empty metadata once.
                    // Retain every unrelated policy and its registry CSE registration.
                    Check(gpo.Save(true, machine.ValueCount != 0 || machine.SubKeyCount != 0, ref extension, ref editor));
                    return true;
                }
            }
            finally { if (gpo != null) Marshal.FinalReleaseComObject(gpo); }
        }

        private static void Check(int result) {
            if (result < 0) Marshal.ThrowExceptionForHR(result);
        }

        private static byte[] ReadPolicyFile(string path) {
            try { return File.ReadAllBytes(path); }
            catch (FileNotFoundException) { return null; }
            catch (DirectoryNotFoundException) { return null; }
        }

        private static bool EqualBytes(byte[] first, byte[] second) {
            if (first == null || second == null) return first == second;
            if (first.Length != second.Length) return false;
            for (int i = 0; i < first.Length; i++) if (first[i] != second[i]) return false;
            return true;
        }

        public static bool IsEmptyGptInitialization(byte[] beforePolicy, byte[] beforeVersion,
            byte[] afterPolicy, byte[] afterVersion) {
            // Same native first-open boundary as DeviceGuardGpoStore: only
            // complete absence becoming the exact eleven-byte ASCII header.
            return beforePolicy == null && beforeVersion == null && afterPolicy == null &&
                EqualBytes(Encoding.ASCII.GetBytes("[General]\r\n"), afterVersion);
        }

        private static void PruneEmptyAncestors(RegistryKey machine, string path) {
            while (path.Length != 0) {
                using (RegistryKey key = machine.OpenSubKey(path, false)) {
                    if (key == null || key.ValueCount != 0 || key.SubKeyCount != 0) return;
                }
                machine.DeleteSubKey(path, true);
                int separator = path.LastIndexOf('\\');
                path = separator < 0 ? "" : path.Substring(0, separator);
            }
        }

        // Pure parser, also exercised outside Windows. MS-GPOL encodes each
        // block as one CSE GUID followed by one or more editor GUIDs. Returns
        // the editors registered for the Registry CSE, lower-case and sorted.
        public static string[] ParseRegistryEditors(string text) {
            if (text == null) throw new ArgumentNullException("text");
            string guid = @"\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}";
            string pattern = @"\[(?<extension>" + guid + @")(?<editors>(?:" + guid + @")+)\]";
            HashSet<string> extensions = new HashSet<string>(StringComparer.Ordinal);
            List<string> result = new List<string>();
            int offset = 0;
            foreach (Match block in Regex.Matches(text, pattern, RegexOptions.CultureInvariant)) {
                if (block.Index != offset) throw new InvalidDataException("Malformed Group Policy extension list");
                string extension = new Guid(block.Groups["extension"].Value).ToString("D");
                if (!extensions.Add(extension)) throw new InvalidDataException("Duplicate Group Policy extension");
                HashSet<string> editors = new HashSet<string>(StringComparer.Ordinal);
                foreach (Match item in Regex.Matches(block.Groups["editors"].Value, guid)) {
                    if (!editors.Add(new Guid(item.Value).ToString("D"))) throw new InvalidDataException("Duplicate Group Policy editor");
                }
                if (extension == RegistryExtension) result.AddRange(editors);
                offset += block.Length;
            }
            if (offset != text.Length) throw new InvalidDataException("Malformed Group Policy extension list");
            result.Sort(StringComparer.Ordinal);
            return result.ToArray();
        }

        private static string[] ReadRegistryEditors(string policyDirectory, byte[] version) {
            if (version == null) return new string[0];
            StringBuilder value = new StringBuilder(65536);
            uint length = ReadIni("General", "gPCMachineExtensionNames", "", value,
                (uint)value.Capacity, Path.Combine(policyDirectory, "gpt.ini"));
            if (length >= value.Capacity - 1) throw new InvalidDataException("Group Policy extension list is truncated");
            return ParseRegistryEditors(value.ToString());
        }

        public static bool ReadEditorRegistration(string policyDirectory) {
            string versionFile = Path.Combine(policyDirectory, "gpt.ini");
            byte[] version = ReadPolicyFile(versionFile);
            bool registered = Array.IndexOf(ReadRegistryEditors(policyDirectory, version), Editor) >= 0;
            if (!EqualBytes(version, ReadPolicyFile(versionFile)))
                throw new InvalidOperationException("Local GPO changed during firewall registration inventory; retry");
            return registered;
        }

        // Restore the firewall editor's Registry CSE registration to its sealed
        // prestate. A Save with loaded nonempty registry policy retains the
        // saving editor's registration even with bAdd=false, so a restore that
        // runs while other policy remains (for example Device Guard policy that
        // SecurityBaseline restores afterward) must reconcile it separately.
        public static string ReconcileEditorRegistration(bool registered, string policyDirectory) {
            string policyFile = Path.Combine(policyDirectory, @"Machine\Registry.pol");
            string versionFile = Path.Combine(policyDirectory, "gpt.ini");
            byte[] policy = ReadPolicyFile(policyFile), version = ReadPolicyFile(versionFile);
            string[] editors = ReadRegistryEditors(policyDirectory, version);
            if ((Array.IndexOf(editors, Editor) >= 0) == registered) return "Unchanged";
            if (!registered && policy != null) {
                bool firewallPolicy, registryPolicy;
                IFirewallGroupPolicyObject reader = null;
                try {
                    reader = (IFirewallGroupPolicyObject)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("EA502722-A23D-11D1-A7D3-0000F87571E3")));
                    Check(reader.OpenLocalMachineGPO(3)); // LOAD_REGISTRY | READ_ONLY
                    IntPtr key;
                    Check(reader.GetRegistryKey(2, out key));
                    using (SafeRegistryHandle handle = new SafeRegistryHandle(key, true))
                    using (RegistryKey machine = RegistryKey.FromHandle(handle, RegistryView.Registry64))
                    using (RegistryKey firewall = machine.OpenSubKey(Firewall, false)) {
                        firewallPolicy = firewall != null;
                        registryPolicy = machine.ValueCount != 0 || machine.SubKeyCount != 0;
                    }
                }
                finally { if (reader != null) Marshal.FinalReleaseComObject(reader); }
                // Never orphan remaining policy: keep the registration while any
                // firewall policy remains, or while it is the only Registry CSE
                // registration of other remaining registry policy.
                if (firewallPolicy || (registryPolicy && editors.Length == 1)) return "Retained";
            }
            IFirewallGroupPolicyObject gpo = null;
            try {
                gpo = (IFirewallGroupPolicyObject)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("EA502722-A23D-11D1-A7D3-0000F87571E3")));
                // Writable without GPO_OPEN_LOAD_REGISTRY: edit only the
                // CSE/editor pair and never resave a loaded registry hive.
                Check(gpo.OpenLocalMachineGPO(0));
                if (!EqualBytes(policy, ReadPolicyFile(policyFile)) || !EqualBytes(version, ReadPolicyFile(versionFile)))
                    throw new InvalidOperationException("Local GPO changed before firewall registration restore; retry");
                Guid extension = new Guid(RegistryExtension);
                Guid editor = new Guid(Editor);
                Check(gpo.Save(true, registered, ref extension, ref editor));
            }
            finally { if (gpo != null) Marshal.FinalReleaseComObject(gpo); }
            if (!EqualBytes(policy, ReadPolicyFile(policyFile)))
                throw new InvalidOperationException("Registration-only Save unexpectedly changed registry policy bytes");
            List<string> expected = new List<string>(editors);
            if (registered) expected.Add(Editor); else expected.Remove(Editor);
            expected.Sort(StringComparer.Ordinal);
            if (String.Join("|", ReadRegistryEditors(policyDirectory, ReadPolicyFile(versionFile))) != String.Join("|", expected.ToArray()))
                throw new InvalidOperationException("Firewall editor registration did not reach its sealed prestate");
            return "Changed";
        }
    }
}
'@
    }
}

function Get-AdvancedSecurityLocalFirewallGpoState {
    [CmdletBinding()]
    param()
    $contract = Get-AdvancedSecurityFirewallMirrorContract
    Initialize-AdvancedSecurityFirewallGpoStore
    return [NoIDPrivacy.FirewallGpoStore]::ReadOwnedState(
        $contract.Names, $contract.Group, $contract.Suffix, (Join-Path $env:SystemRoot 'System32\GroupPolicy'))
}

function Sync-AdvancedSecurityLocalFirewallGpo {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.Dictionary[string,string]]$ExpectedSources,
        [string[]]$NamesToSynchronize
    )
    if (-not $PSCmdlet.ShouldProcess('Local firewall GPO', 'Synchronize owned native rule data through the local Group Policy API')) { return $false }
    $contract = Get-AdvancedSecurityFirewallMirrorContract
    Initialize-AdvancedSecurityFirewallGpoStore
    return [NoIDPrivacy.FirewallGpoStore]::SynchronizeOwnedRules(
        $contract.Names, $contract.Group, $contract.Suffix, $ExpectedSources, $NamesToSynchronize,
        (Join-Path $env:SystemRoot 'System32\GroupPolicy'))
}

function Get-AdvancedSecurityFirewallGpoEditorRegistration {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    Initialize-AdvancedSecurityFirewallGpoStore
    return [NoIDPrivacy.FirewallGpoStore]::ReadEditorRegistration((Join-Path $env:SystemRoot 'System32\GroupPolicy'))
}

function Set-AdvancedSecurityFirewallGpoEditorRegistration {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([string])]
    param([Parameter(Mandatory = $true)][bool]$Registered)
    if (-not $PSCmdlet.ShouldProcess('Local firewall GPO', 'Restore the sealed firewall editor registration')) { return 'Unchanged' }
    Initialize-AdvancedSecurityFirewallGpoStore
    return [NoIDPrivacy.FirewallGpoStore]::ReconcileEditorRegistration(
        $Registered, (Join-Path $env:SystemRoot 'System32\GroupPolicy'))
}
