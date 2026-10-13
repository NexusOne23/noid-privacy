#Requires -Version 5.1

function Initialize-SecurityBaselineDeviceGuardGpoStore {
    [CmdletBinding()]
    param()

    if ('NoIDPrivacy.DeviceGuardGpoStore' -as [type]) { return }
    # Authored interop for IGroupPolicyObject (GPEdit.h). Registry values are
    # captured as native kind/bytes, retaining even noncanonical string data.
    # Save persists a CSE/editor pair, not an entire historical policy file.
    # https://learn.microsoft.com/windows/win32/api/gpedit/nf-gpedit-igrouppolicyobject-save
    Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace NoIDPrivacy {
    [ComImport, Guid("EA502723-A23D-11D1-A7D3-0000F87571E3"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IDeviceGuardGroupPolicyObject {
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

    public sealed class DeviceGuardGpoValue {
        public string Name;
        public bool Exists;
        public string OriginalName;
        public int Kind;
        public string Data;
    }

    public sealed class DeviceGuardGpoSnapshot {
        public int SchemaVersion = 1;
        public string Target = "SecurityBaselineDeviceGuardGpo";
        public bool KeyExisted;
        public string[] AbsentAncestorKeys;
        public DeviceGuardGpoValue[] Values;
        public bool RegistryEditorPresent;
        public bool DeviceGuardEditorPresent;
        // Hashes reconcile Apply with its sealed prestate. Restore does not
        // replace these shared files or demand that later foreign edits vanish.
        public string PolicyFileSha256;
        public string GptFileSha256;
    }

    public static class DeviceGuardGpoStore {
        private const string Target = @"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
        private const string RegistryExtension = "35378EAC-683F-11D2-A89A-00C04FBBCFA2";
        private const string DeviceGuardExtension = "F312195E-3D9D-447A-A3F5-08DFFA24735E";
        // Stable NoID SecurityBaseline editor identity. It does not register a
        // new processor or service. The installed Microsoft CSEs process policy.
        private const string Editor = "8ED67D93-8B70-4C15-BD23-43D585B9FD81";
        private static readonly string[] Names = {
            "EnableVirtualizationBasedSecurity", "RequirePlatformSecurityFeatures",
            "HypervisorEnforcedCodeIntegrity", "HVCIMATRequired", "LsaCfgFlags",
            "MachineIdentityIsolation", "ConfigureSystemGuardLaunch", "ConfigureKernelShadowStacksLaunch"
        };
        private static readonly int[] ApplyValues = { 1, 1, 2, 1, 2, 3, 1, 1 };
        private const int MaximumValueBytes = 4194304;

        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, EntryPoint="RegQueryValueExW")]
        private static extern int QueryValue(SafeRegistryHandle key, string name, IntPtr reserved,
            out int kind, byte[] data, ref int length);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, EntryPoint="RegSetValueExW")]
        private static extern int SetValue(SafeRegistryHandle key, string name, int reserved,
            int kind, byte[] data, int length);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, EntryPoint="GetPrivateProfileStringW")]
        private static extern uint ReadIni(string section, string key, string fallback,
            StringBuilder value, uint length, string path);

        private sealed class Session : IDisposable {
            internal IDeviceGuardGroupPolicyObject Gpo;
            internal RegistryKey Machine;
            internal Session(bool readOnly) : this(readOnly, true) { }
            internal Session(bool readOnly, bool loadRegistry) {
                try {
                    Gpo = (IDeviceGuardGroupPolicyObject)Activator.CreateInstance(Type.GetTypeFromCLSID(
                        new Guid("EA502722-A23D-11D1-A7D3-0000F87571E3")));
                    Check(Gpo.OpenLocalMachineGPO((readOnly ? 2U : 0U) | (loadRegistry ? 1U : 0U)));
                    if (loadRegistry) {
                        IntPtr handle;
                        Check(Gpo.GetRegistryKey(2, out handle));
                        SafeRegistryHandle owned = new SafeRegistryHandle(handle, true);
                        try { Machine = RegistryKey.FromHandle(owned, RegistryView.Registry64); }
                        catch { owned.Dispose(); throw; }
                    }
                } catch { Dispose(); throw; }
            }
            public void Dispose() {
                if (Machine != null) { Machine.Dispose(); Machine = null; }
                if (Gpo != null) { Marshal.FinalReleaseComObject(Gpo); Gpo = null; }
            }
        }

        private static void Check(int result) {
            if (result < 0) Marshal.ThrowExceptionForHR(result);
            if (result != 0) throw new InvalidOperationException("Native Group Policy operation did not return S_OK");
        }
        private static void CheckRegistry(int result) { if (result != 0) throw new Win32Exception(result); }
        private static byte[] ReadFile(string path) {
            try { return File.ReadAllBytes(path); }
            catch (FileNotFoundException) { return null; }
            catch (DirectoryNotFoundException) { return null; }
        }
        private static string Hash(byte[] bytes) {
            if (bytes == null) return null;
            using (SHA256 sha = SHA256.Create()) {
                return BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", "").ToLowerInvariant();
            }
        }
        private static bool SupportedKind(int kind) {
            return kind == 0 || kind == 1 || kind == 2 || kind == 3 || kind == 4 || kind == 7 || kind == 11;
        }
        private static string[] Ancestors() {
            List<string> result = new List<string>();
            string path = Target;
            while (path.LastIndexOf('\\') > 0) {
                path = path.Substring(0, path.LastIndexOf('\\'));
                result.Add(path);
            }
            result.Reverse();
            return result.ToArray();
        }

        // Pure parser, also exercised outside Windows. MS-GPOL encodes each
        // block as one CSE GUID followed by one or more editor GUIDs.
        public static string[] ParseExtensionPairs(string text) {
            if (text == null) throw new ArgumentNullException("text");
            List<string> result = new List<string>();
            HashSet<string> extensions = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            string guid = @"\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}";
            string pattern = @"\[(?<extension>" + guid + @")(?<editors>(?:" + guid + @")+)\]";
            int offset = 0;
            foreach (Match block in Regex.Matches(text, pattern, RegexOptions.CultureInvariant)) {
                if (block.Index != offset) throw new InvalidDataException("Malformed Group Policy extension list");
                string extension = new Guid(block.Groups["extension"].Value).ToString("D");
                if (!extensions.Add(extension)) throw new InvalidDataException("Duplicate Group Policy extension");
                HashSet<string> editors = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (Match item in Regex.Matches(block.Groups["editors"].Value, guid)) {
                    string editor = new Guid(item.Value).ToString("D");
                    if (!editors.Add(editor)) throw new InvalidDataException("Duplicate Group Policy editor");
                    result.Add(extension + "|" + editor);
                }
                offset += block.Length;
            }
            if (offset != text.Length) throw new InvalidDataException("Malformed Group Policy extension list");
            result.Sort(StringComparer.Ordinal);
            return result.ToArray();
        }
        private static string[] ReadPairs(string directory, byte[] gpt) {
            if (gpt == null) return new string[0];
            StringBuilder value = new StringBuilder(65536);
            uint length = ReadIni("General", "gPCMachineExtensionNames", "", value,
                (uint)value.Capacity, Path.Combine(directory, "gpt.ini"));
            if (length >= value.Capacity - 1) throw new InvalidDataException("Group Policy extension list is truncated");
            return ParseExtensionPairs(value.ToString());
        }
        private static bool HasEditor(string[] pairs, string extension) {
            string pair = extension.ToLowerInvariant() + "|" + Editor.ToLowerInvariant();
            return Array.IndexOf(pairs, pair) >= 0;
        }

        private static DeviceGuardGpoValue ReadValue(RegistryKey key, string name) {
            return ReadValue(key, name, true);
        }
        private static DeviceGuardGpoValue ReadValue(RegistryKey key, string name, bool requireSupportedKind) {
            DeviceGuardGpoValue result = new DeviceGuardGpoValue();
            result.Name = name;
            if (key == null) return result;
            foreach (string actual in key.GetValueNames()) {
                if (String.Equals(actual, name, StringComparison.OrdinalIgnoreCase)) {
                    if (result.Exists) throw new InvalidDataException("Ambiguous Device Guard policy identity");
                    result.Exists = true; result.OriginalName = actual;
                }
            }
            if (!result.Exists) return result;
            int kind, length = 0;
            CheckRegistry(QueryValue(key.Handle, result.OriginalName, IntPtr.Zero, out kind, null, ref length));
            if ((requireSupportedKind && !SupportedKind(kind)) || length < 0 || length > MaximumValueBytes)
                throw new InvalidDataException("Unsupported Device Guard policy data");
            byte[] bytes = new byte[length];
            int actualKind, actualLength = length;
            CheckRegistry(QueryValue(key.Handle, result.OriginalName, IntPtr.Zero, out actualKind, bytes, ref actualLength));
            if (actualKind != kind || actualLength != length)
                throw new InvalidOperationException("Device Guard policy changed during backup");
            result.Kind = kind; result.Data = Convert.ToBase64String(bytes);
            return result;
        }
        private static DeviceGuardGpoSnapshot Capture(RegistryKey machine, string[] pairs, byte[] policy, byte[] gpt) {
            DeviceGuardGpoSnapshot result = new DeviceGuardGpoSnapshot();
            List<string> absent = new List<string>();
            foreach (string path in Ancestors()) {
                using (RegistryKey key = machine == null ? null : machine.OpenSubKey(path, false)) {
                    if (key == null) absent.Add(path);
                }
            }
            result.AbsentAncestorKeys = absent.ToArray();
            using (RegistryKey key = machine == null ? null : machine.OpenSubKey(Target, false)) {
                result.KeyExisted = key != null;
                List<DeviceGuardGpoValue> values = new List<DeviceGuardGpoValue>();
                foreach (string name in Names) values.Add(ReadValue(key, name));
                result.Values = values.ToArray();
            }
            result.RegistryEditorPresent = HasEditor(pairs, RegistryExtension);
            result.DeviceGuardEditorPresent = HasEditor(pairs, DeviceGuardExtension);
            result.PolicyFileSha256 = Hash(policy); result.GptFileSha256 = Hash(gpt);
            return result;
        }
        private static void RequireFilesUnchanged(string directory, byte[] policy, byte[] gpt) {
            if (Hash(policy) != Hash(ReadFile(Path.Combine(directory, @"Machine\Registry.pol"))) ||
                Hash(gpt) != Hash(ReadFile(Path.Combine(directory, "gpt.ini"))))
                throw new InvalidOperationException("Local Group Policy changed during Device Guard operation; retry with current state");
        }
        public static bool IsEmptyGptInitialization(byte[] beforePolicy, byte[] beforeGpt,
            byte[] afterPolicy, byte[] afterGpt) {
            // A first writable OpenLocalMachineGPO creates this header before
            // Save, even with no registry policy. Accept only that exact native
            // transition; revisions, registrations and policy bytes are edits.
            byte[] header = Encoding.ASCII.GetBytes("[General]\r\n");
            if (beforePolicy != null || beforeGpt != null || afterPolicy != null ||
                afterGpt == null || afterGpt.Length != header.Length) return false;
            for (int index = 0; index < header.Length; index++)
                if (afterGpt[index] != header[index]) return false;
            return true;
        }
        public static DeviceGuardGpoSnapshot Read(string directory) {
            byte[] policy = ReadFile(Path.Combine(directory, @"Machine\Registry.pol"));
            byte[] gpt = ReadFile(Path.Combine(directory, "gpt.ini"));
            string[] pairs = ReadPairs(directory, gpt);
            DeviceGuardGpoSnapshot result;
            if (policy == null) {
                // Native opening can create bookkeeping in an empty store.
                // Absence needs no editable hive, Save or policy refresh.
                result = Capture(null, pairs, policy, gpt);
            } else {
                if (gpt == null) throw new InvalidDataException("Existing local registry policy has no version metadata");
                using (Session session = new Session(true)) { result = Capture(session.Machine, pairs, policy, gpt); }
            }
            RequireFilesUnchanged(directory, policy, gpt);
            Validate(result);
            return result;
        }

        public static void Validate(DeviceGuardGpoSnapshot state) {
            if (state == null || state.SchemaVersion != 1 || state.Target != "SecurityBaselineDeviceGuardGpo" ||
                state.Values == null || state.Values.Length != Names.Length || state.AbsentAncestorKeys == null)
                throw new InvalidDataException("Invalid Device Guard GPO snapshot contract");
            string[] ancestors = Ancestors();
            HashSet<string> missing = new HashSet<string>(StringComparer.Ordinal);
            int previous = -1;
            foreach (string path in state.AbsentAncestorKeys) {
                int index = Array.IndexOf(ancestors, path);
                if (index < 0 || index <= previous || !missing.Add(path) || state.KeyExisted)
                    throw new InvalidDataException("Invalid Device Guard GPO ancestor inventory");
                previous = index;
            }
            if (missing.Count > 0 && state.AbsentAncestorKeys.Length != ancestors.Length - Array.IndexOf(ancestors, state.AbsentAncestorKeys[0]))
                throw new InvalidDataException("Device Guard GPO absent ancestors are not contiguous");
            for (int index = 0; index < Names.Length; index++) {
                DeviceGuardGpoValue value = state.Values[index];
                if (value == null || value.Name != Names[index]) throw new InvalidDataException("Device Guard GPO target identity differs");
                if (!value.Exists) {
                    if (value.OriginalName != null || value.Kind != 0 || value.Data != null)
                        throw new InvalidDataException("Absent Device Guard GPO value contains invented prestate");
                    continue;
                }
                if (!state.KeyExisted || !String.Equals(value.Name, value.OriginalName, StringComparison.OrdinalIgnoreCase) ||
                    !SupportedKind(value.Kind) || value.Data == null || value.Data.Length > ((MaximumValueBytes + 2) / 3) * 4)
                    throw new InvalidDataException("Invalid original Device Guard GPO value");
                byte[] bytes = Convert.FromBase64String(value.Data);
                if (bytes.Length > MaximumValueBytes || Convert.ToBase64String(bytes) != value.Data)
                    throw new InvalidDataException("Noncanonical Device Guard GPO byte encoding");
            }
            foreach (string hash in new string[] { state.PolicyFileSha256, state.GptFileSha256 }) {
                if (hash != null && !Regex.IsMatch(hash, @"\A[0-9a-f]{64}\z"))
                    throw new InvalidDataException("Invalid Device Guard GPO prestate hash");
            }
            if (state.PolicyFileSha256 == null && (state.KeyExisted || state.AbsentAncestorKeys.Length != ancestors.Length))
                throw new InvalidDataException("Absent policy file has contradictory Device Guard prestate");
            if (state.GptFileSha256 == null && (state.RegistryEditorPresent || state.DeviceGuardEditorPresent || state.PolicyFileSha256 != null))
                throw new InvalidDataException("Absent GPO metadata has contradictory registrations");
        }

        private static bool OwnedName(string name) {
            foreach (string candidate in Names) if (String.Equals(name, candidate, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
        private static bool OwnedPath(string path) {
            return String.Equals(path, Target, StringComparison.OrdinalIgnoreCase) ||
                Target.StartsWith(path + "\\", StringComparison.OrdinalIgnoreCase);
        }
        private static void WriteForeignState(RegistryKey key, string path, BinaryWriter writer) {
            if (!OwnedPath(path)) { writer.Write("K"); writer.Write(path); }
            string[] values = key.GetValueNames(); Array.Sort(values, StringComparer.Ordinal);
            foreach (string name in values) {
                if (String.Equals(path, Target, StringComparison.OrdinalIgnoreCase) && OwnedName(name)) continue;
                DeviceGuardGpoValue value = ReadValue(key, name, false);
                if (!value.Exists) throw new InvalidOperationException("Foreign GPO value disappeared during reconciliation");
                writer.Write("V"); writer.Write(path); writer.Write(value.OriginalName); writer.Write(value.Kind); writer.Write(value.Data);
            }
            string[] children = key.GetSubKeyNames(); Array.Sort(children, StringComparer.Ordinal);
            foreach (string name in children) {
                using (RegistryKey child = key.OpenSubKey(name, false)) {
                    if (child == null) throw new InvalidOperationException("Foreign GPO key disappeared during reconciliation");
                    WriteForeignState(child, path.Length == 0 ? name : path + "\\" + name, writer);
                }
            }
        }
        private static string ForeignState(RegistryKey machine) {
            using (MemoryStream stream = new MemoryStream()) {
                using (BinaryWriter writer = new BinaryWriter(stream, Encoding.UTF8, true)) { WriteForeignState(machine, "", writer); }
                return Hash(stream.ToArray());
            }
        }
        private static string[] ForeignPairs(string[] pairs) {
            List<string> result = new List<string>();
            foreach (string pair in pairs) {
                if (pair == RegistryExtension.ToLowerInvariant() + "|" + Editor.ToLowerInvariant() ||
                    pair == DeviceGuardExtension.ToLowerInvariant() + "|" + Editor.ToLowerInvariant()) continue;
                result.Add(pair);
            }
            return result.ToArray();
        }
        private static void RequireReviewedDeviceGuardScope(RegistryKey machine) {
            using (RegistryKey key = machine.OpenSubKey(Target, false)) {
                if (key == null) return;
                if (key.SubKeyCount != 0) throw new InvalidOperationException("Existing Device Guard GPO has unreviewed child settings");
                foreach (string name in key.GetValueNames()) {
                    if (!OwnedName(name)) throw new InvalidOperationException("Existing Device Guard GPO has settings outside the eight-policy BAVR scope");
                }
            }
        }
        private static void RequireOwnedAbsentTree(RegistryKey machine, string path) {
            using (RegistryKey key = machine.OpenSubKey(path, false)) {
                if (key == null) return;
                if (!OwnedPath(path)) throw new InvalidOperationException("Originally absent GPO ancestor now contains foreign keys; restore later policy changes first");
                foreach (string name in key.GetValueNames()) {
                    if (!String.Equals(path, Target, StringComparison.OrdinalIgnoreCase) || !OwnedName(name))
                        throw new InvalidOperationException("Originally absent GPO ancestor now contains foreign values; restore later policy changes first");
                }
                foreach (string child in key.GetSubKeyNames()) RequireOwnedAbsentTree(machine, path + "\\" + child);
            }
        }
        private static bool EqualValues(DeviceGuardGpoValue[] first, DeviceGuardGpoValue[] second) {
            if (first.Length != second.Length) return false;
            for (int index = 0; index < first.Length; index++) {
                DeviceGuardGpoValue a = first[index], b = second[index];
                if (a.Name != b.Name || a.Exists != b.Exists || a.OriginalName != b.OriginalName || a.Kind != b.Kind || a.Data != b.Data) return false;
            }
            return true;
        }
        private static void Save(Session session, string extension, bool add) {
            Guid processor = new Guid(extension), editor = new Guid(Editor);
            Check(session.Gpo.Save(true, add, ref processor, ref editor));
        }
        private static void SaveRegistration(string directory, string extension, bool add) {
            byte[] policy = ReadFile(Path.Combine(directory, @"Machine\Registry.pol"));
            byte[] gpt = ReadFile(Path.Combine(directory, "gpt.ini"));
            // A loaded, nonempty registry policy retains the saving editor's
            // registry registration even when Save receives bAdd=false. Open
            // without GPO_OPEN_LOAD_REGISTRY to edit only the CSE/editor pair.
            // Native tests cover both flags and retention of other editors.
            using (Session registration = new Session(false, false)) {
                RequireFilesUnchanged(directory, policy, gpt);
                Save(registration, extension, add);
            }
            if (Hash(policy) != Hash(ReadFile(Path.Combine(directory, @"Machine\Registry.pol"))))
                throw new InvalidOperationException("Registration-only Save unexpectedly changed registry policy bytes");
        }
        private static void WriteOwnedValues(RegistryKey machine, DeviceGuardGpoValue[] values, bool keyExisted) {
            using (RegistryKey existing = machine.OpenSubKey(Target, false)) {
                if (existing == null && !keyExisted) return;
            }
            using (RegistryKey key = machine.CreateSubKey(Target, true)) {
                foreach (DeviceGuardGpoValue value in values) {
                    // Delete/recreate retains the exact original value-name case.
                    key.DeleteValue(value.Name, false);
                    if (value.Exists) {
                        byte[] bytes = Convert.FromBase64String(value.Data);
                        CheckRegistry(SetValue(key.Handle, value.OriginalName, 0, value.Kind, bytes, bytes.Length));
                    }
                }
            }
        }
        private static void RemoveEmptyKey(RegistryKey machine, string path) {
            using (RegistryKey key = machine.OpenSubKey(path, false)) {
                if (key == null) return;
                if (key.ValueCount != 0 || key.SubKeyCount != 0)
                    throw new InvalidOperationException("Originally absent Device Guard GPO key contains foreign state");
            }
            machine.DeleteSubKey(path, true);
        }
        public static bool Apply(DeviceGuardGpoSnapshot original, string directory) { return Change(original, directory, false); }
        public static bool Restore(DeviceGuardGpoSnapshot original, string directory) { return Change(original, directory, true); }
        private static bool Change(DeviceGuardGpoSnapshot original, string directory, bool restore) {
            Validate(original); // Bind every identity/byte before opening an editable native hive.
            byte[] policy = ReadFile(Path.Combine(directory, @"Machine\Registry.pol"));
            byte[] gpt = ReadFile(Path.Combine(directory, "gpt.ini"));
            if (!restore && (Hash(policy) != original.PolicyFileSha256 || Hash(gpt) != original.GptFileSha256))
                throw new InvalidOperationException("Device Guard GPO changed after its backup; Apply requires a fresh backup");
            string[] pairs = ReadPairs(directory, gpt);
            DeviceGuardGpoValue[] desired = original.Values;
            bool desiredKey = original.KeyExisted;
            bool registryEditor = original.RegistryEditorPresent, deviceGuardEditor = original.DeviceGuardEditorPresent;
            if (!restore) {
                desiredKey = true; registryEditor = true; deviceGuardEditor = true;
                desired = new DeviceGuardGpoValue[Names.Length];
                for (int index = 0; index < Names.Length; index++) {
                    desired[index] = new DeviceGuardGpoValue {
                        Name=Names[index], Exists=true, OriginalName=Names[index], Kind=4,
                        Data=Convert.ToBase64String(BitConverter.GetBytes(ApplyValues[index]))
                    };
                }
            }
            DeviceGuardGpoSnapshot before = Read(directory);
            RequireFilesUnchanged(directory, policy, gpt);
            bool noChange = before.KeyExisted == desiredKey && EqualValues(before.Values, desired) &&
                before.RegistryEditorPresent == registryEditor && before.DeviceGuardEditorPresent == deviceGuardEditor &&
                (!restore || String.Join("|", before.AbsentAncestorKeys) == String.Join("|", original.AbsentAncestorKeys));
            if (noChange && policy == null) return false;

            string foreignBefore;
            using (Session session = new Session(noChange)) {
                byte[] openedPolicy = ReadFile(Path.Combine(directory, @"Machine\Registry.pol"));
                byte[] openedGpt = ReadFile(Path.Combine(directory, "gpt.ini"));
                if (!noChange && IsEmptyGptInitialization(policy, gpt, openedPolicy, openedGpt) &&
                    session.Machine.ValueCount == 0 && session.Machine.SubKeyCount == 0) {
                    // Advance only this operation's expected bytes. The sealed
                    // backup retains actual original absence for Restore.
                    gpt = openedGpt;
                }
                RequireFilesUnchanged(directory, policy, gpt);
                DeviceGuardGpoSnapshot loaded = Capture(session.Machine, pairs, policy, gpt);
                if (!EqualValues(loaded.Values, before.Values) || loaded.KeyExisted != before.KeyExisted)
                    throw new InvalidOperationException("Native Device Guard GPO changed before editing");
                if (!restore) {
                    RequireReviewedDeviceGuardScope(session.Machine);
                    if (!EqualValues(loaded.Values, original.Values) || loaded.KeyExisted != original.KeyExisted ||
                        String.Join("|", loaded.AbsentAncestorKeys) != String.Join("|", original.AbsentAncestorKeys) ||
                        loaded.RegistryEditorPresent != original.RegistryEditorPresent || loaded.DeviceGuardEditorPresent != original.DeviceGuardEditorPresent)
                        throw new InvalidOperationException("Native Device Guard GPO no longer matches its sealed prestate");
                } else {
                    if (!original.KeyExisted) RequireOwnedAbsentTree(session.Machine, Target);
                    foreach (string path in original.AbsentAncestorKeys) RequireOwnedAbsentTree(session.Machine, path);
                    // An added foreign Device Guard setting may rely on this
                    // processor registration. Never silently orphan it.
                    if (!original.DeviceGuardEditorPresent) RequireReviewedDeviceGuardScope(session.Machine);
                }
                if (noChange) return false;
                foreignBefore = ForeignState(session.Machine);
                WriteOwnedValues(session.Machine, desired, desiredKey);
                if (restore && !desiredKey) {
                    RemoveEmptyKey(session.Machine, Target);
                    for (int index = original.AbsentAncestorKeys.Length - 1; index >= 0; index--)
                        RemoveEmptyKey(session.Machine, original.AbsentAncestorKeys[index]);
                }
                if (ForeignState(session.Machine) != foreignBefore)
                    throw new InvalidOperationException("Device Guard edit changed foreign policy in the private hive");
                RequireFilesUnchanged(directory, policy, gpt);
                // All module prestate must already be sealed before this call:
                // native Save can itself cause policy processing. Never defer
                // local-control capture until a later explicit gpupdate.
                Save(session, RegistryExtension, registryEditor);
            }
            // Registration-only operations never resave the previous private
            // registry hive over a later policy edit by another tool.
            byte[] intermediatePolicy = ReadFile(Path.Combine(directory, @"Machine\Registry.pol"));
            byte[] intermediateGpt = ReadFile(Path.Combine(directory, "gpt.ini"));
            string[] intermediatePairs = ReadPairs(directory, intermediateGpt);
            DeviceGuardGpoSnapshot intermediate = Read(directory);
            RequireFilesUnchanged(directory, intermediatePolicy, intermediateGpt);
            if (intermediate.KeyExisted != desiredKey || !EqualValues(intermediate.Values, desired))
                throw new InvalidOperationException("Device Guard policy changed before registration reconciliation");
            SaveRegistration(directory, DeviceGuardExtension, deviceGuardEditor);
            if (HasEditor(intermediatePairs, RegistryExtension) != registryEditor)
                SaveRegistration(directory, RegistryExtension, registryEditor);
            DeviceGuardGpoSnapshot after = Read(directory);
            if (after.KeyExisted != desiredKey || !EqualValues(after.Values, desired) ||
                after.RegistryEditorPresent != registryEditor || after.DeviceGuardEditorPresent != deviceGuardEditor ||
                (restore && String.Join("|", after.AbsentAncestorKeys) != String.Join("|", original.AbsentAncestorKeys)))
                throw new InvalidOperationException("Saved Device Guard GPO does not match the requested prestate or Apply plan");
            byte[] afterPolicy = ReadFile(Path.Combine(directory, @"Machine\Registry.pol"));
            byte[] afterGpt = ReadFile(Path.Combine(directory, "gpt.ini"));
            string[] afterPairs = ReadPairs(directory, afterGpt);
            using (Session check = new Session(true)) {
                if (ForeignState(check.Machine) != foreignBefore ||
                    String.Join("|", ForeignPairs(pairs)) != String.Join("|", ForeignPairs(afterPairs)))
                    throw new InvalidOperationException("Foreign policy or another editor registration changed during native Save");
            }
            RequireFilesUnchanged(directory, afterPolicy, afterGpt);
            return true;
        }
    }
}
'@
}

function Get-SecurityBaselineDeviceGuardGpoSnapshot {
    [CmdletBinding()]
    param()

    Initialize-SecurityBaselineDeviceGuardGpoStore
    return [NoIDPrivacy.DeviceGuardGpoStore]::Read((Join-Path $env:SystemRoot 'System32\GroupPolicy'))
}

function ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot {
    <# Validate JSON primitives before CLR conversion could invent/coerce them. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot)

    $fields = @('SchemaVersion', 'Target', 'KeyExisted', 'AbsentAncestorKeys', 'Values',
        'RegistryEditorPresent', 'DeviceGuardEditorPresent', 'PolicyFileSha256', 'GptFileSha256')
    $actualFields = @($Snapshot.PSObject.Properties.Name)
    if ($actualFields.Count -ne $fields.Count -or @($fields | Where-Object { $_ -cnotin $actualFields }).Count) {
        throw 'Device Guard GPO snapshot has missing or unsupported fields'
    }
    if (($Snapshot.SchemaVersion -isnot [int] -and $Snapshot.SchemaVersion -isnot [long]) -or
        $Snapshot.SchemaVersion -ne 1 -or $Snapshot.Target -isnot [string] -or
        $Snapshot.Target -cne 'SecurityBaselineDeviceGuardGpo' -or
        $Snapshot.KeyExisted -isnot [bool] -or $Snapshot.RegistryEditorPresent -isnot [bool] -or
        $Snapshot.DeviceGuardEditorPresent -isnot [bool] -or
        $Snapshot.AbsentAncestorKeys -isnot [array] -or $Snapshot.Values -isnot [array]) {
        throw 'Device Guard GPO snapshot has invalid primitive types or target identity'
    }
    foreach ($field in @('PolicyFileSha256', 'GptFileSha256')) {
        if ($null -ne $Snapshot.$field -and $Snapshot.$field -isnot [string]) {
            throw 'Device Guard GPO snapshot hash is not a string or null'
        }
    }
    foreach ($ancestor in $Snapshot.AbsentAncestorKeys) {
        if ($ancestor -isnot [string]) { throw 'Device Guard GPO ancestor is not a string' }
    }
    foreach ($value in $Snapshot.Values) {
        $valueFields = @('Name', 'Exists', 'OriginalName', 'Kind', 'Data')
        $actualValueFields = @($value.PSObject.Properties.Name)
        if ($null -eq $value -or $actualValueFields.Count -ne $valueFields.Count -or
            @($valueFields | Where-Object { $_ -cnotin $actualValueFields }).Count -or
            $value.Name -isnot [string] -or $value.Exists -isnot [bool] -or
            ($value.Kind -isnot [int] -and $value.Kind -isnot [long]) -or
            $value.Kind -lt 0 -or $value.Kind -gt [int]::MaxValue -or
            ($null -ne $value.OriginalName -and $value.OriginalName -isnot [string]) -or
            ($null -ne $value.Data -and $value.Data -isnot [string])) {
            throw 'Device Guard GPO value has invalid fields or primitive types'
        }
    }
    Initialize-SecurityBaselineDeviceGuardGpoStore
    $native = [NoIDPrivacy.DeviceGuardGpoSnapshot]::new()
    # PowerShell coerces $null assigned to a CLR string field into ''. Leave
    # the fresh object's actual null intact: absence is different from empty
    # native data, which is a valid captured value.
    foreach ($field in $fields | Where-Object { $_ -cne 'Values' }) {
        if ($null -ne $Snapshot.$field) { $native.$field = $Snapshot.$field }
    }
    $native.Values = @(foreach ($value in $Snapshot.Values) {
            $entry = [NoIDPrivacy.DeviceGuardGpoValue]::new()
            foreach ($field in @('Name', 'Exists', 'OriginalName', 'Kind', 'Data')) {
                if ($null -ne $value.$field) { $entry.$field = $value.$field }
            }
            $entry
        })
    [NoIDPrivacy.DeviceGuardGpoStore]::Validate($native)
    return $native
}

function Backup-SecurityBaselineDeviceGuardGpo {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$BackupPath)

    $snapshot = Get-SecurityBaselineDeviceGuardGpoSnapshot
    $json = ConvertTo-Json -InputObject $snapshot -Depth 10
    $null = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot ($json | ConvertFrom-Json -ErrorAction Stop)
    # An existing backup is never replaced, including on a retry after failure.
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = [IO.File]::Open($BackupPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true) }
    finally { $stream.Dispose() }
    return $snapshot
}

function Assert-SecurityBaselineDeviceGuardGpoPrestate {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Snapshot)

    $expected = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot $Snapshot
    $current = Get-SecurityBaselineDeviceGuardGpoSnapshot
    if ((ConvertTo-Json -InputObject $current -Depth 10 -Compress) -cne
        (ConvertTo-Json -InputObject $expected -Depth 10 -Compress)) {
        throw 'Device Guard local policy changed after backup; Apply requires a fresh backup'
    }
    return $true
}

function Set-SecurityBaselineDeviceGuardGpo {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Snapshot)

    $native = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot $Snapshot
    if ($PSCmdlet.ShouldProcess('Local Device Guard policy', 'Apply the eight sealed baseline decisions')) {
        return [NoIDPrivacy.DeviceGuardGpoStore]::Apply($native, (Join-Path $env:SystemRoot 'System32\GroupPolicy'))
    }
}

function Restore-SecurityBaselineDeviceGuardGpo {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$BackupPath)

    $snapshot = Get-Content -LiteralPath $BackupPath -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    $native = ConvertTo-SecurityBaselineDeviceGuardGpoSnapshot -Snapshot $snapshot
    if ($PSCmdlet.ShouldProcess('Local Device Guard policy', 'Restore the recorded values and editor registrations')) {
        $changed = [NoIDPrivacy.DeviceGuardGpoStore]::Restore($native, (Join-Path $env:SystemRoot 'System32\GroupPolicy'))
        if ($changed) { $null = Wait-SecurityBaselineComputerPolicyProcessing }
        return $changed
    }
}

function Wait-SecurityBaselineComputerPolicyProcessing {
    <#
    .SYNOPSIS
        Waits until Windows has processed the changed local computer policy.

    .DESCRIPTION
        IGroupPolicyObject::Save only requests computer policy processing; it
        runs asynchronously. When a restore removes values from the local GPO,
        that processing deletes them from the effective registry. Callers
        replay the recorded registry prestate directly afterwards, so a late
        run could delete recorded values again. gpupdate without /force
        processes only changed policy, which is the same work the Save already
        requested, and /wait returns after it has finished.
        A failed or timed-out wait is reported but does not block the replay.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([ValidateRange(30, 600)][int]$TimeoutSeconds = 120)

    $gpupdate = Join-Path $env:SystemRoot 'System32\gpupdate.exe'
    $output = & $gpupdate /target:computer "/wait:$TimeoutSeconds" 2>&1
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 0) { return $true }

    $message = "Computer policy processing after the Device Guard policy restore did not report success (gpupdate exit $exitCode): $((@($output) -join ' ').Trim())"
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level WARNING -Message $message -Module 'SecurityBaseline'
    }
    else {
        Write-Warning $message
    }
    return $false
}
