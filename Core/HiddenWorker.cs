// SPDX-License-Identifier: GPL-3.0-only
// Loaded in memory by a short-lived SYSTEM scheduled task. Only the installed
// Windows PowerShell is launched; no unsigned executable is written to disk.
// The original user's token, environment and session are checked before launch.
// A kill-on-close job covers the child and descendants, including task termination.
using System;
using System.ComponentModel;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

public static class NoIDHiddenWorker
{
    [StructLayout(LayoutKind.Sequential)]
    private struct StartupInfo
    {
        public int Size;
        public IntPtr Reserved, Desktop, Title;
        public uint X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
        public ushort ShowWindow, ReservedSize;
        public IntPtr ReservedBytes, Input, Output, Error;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    private struct BasicLimits
    {
        public long ProcessTime, JobTime;
        public uint Flags;
        public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
        public uint ActiveProcesses;
        public UIntPtr Affinity;
        public uint Priority, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct IoCounters { public ulong Read, Write, Other, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct ExtendedLimits
    {
        public BasicLimits Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr security, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr job, int informationClass, ref ExtendedLimits limits, uint size);
    [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUserW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessAsUser(IntPtr token, string application, StringBuilder command, IntPtr processSecurity,
        IntPtr threadSecurity, bool inheritHandles, uint flags, IntPtr environment, string directory,
        ref StartupInfo startup, out ProcessInfo process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll")] private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
    [DllImport("kernel32.dll")] private static extern bool TerminateProcess(IntPtr process, uint code);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(uint session, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(IntPtr token, int kind, IntPtr buffer, int size, out int needed);
    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
    [DllImport("userenv.dll")] private static extern bool DestroyEnvironmentBlock(IntPtr environment);

    private static int ReadTokenInt(IntPtr token, int kind)
    {
        IntPtr buffer = Marshal.AllocHGlobal(4);
        try { int needed; if (!GetTokenInformation(token, kind, buffer, 4, out needed)) throw new Win32Exception(); return Marshal.ReadInt32(buffer); }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    private static IntPtr ReadLinkedToken(IntPtr token)
    {
        IntPtr buffer = Marshal.AllocHGlobal(IntPtr.Size);
        try { int needed; if (!GetTokenInformation(token, 19, buffer, IntPtr.Size, out needed)) throw new Win32Exception(); return Marshal.ReadIntPtr(buffer); }
        finally { Marshal.FreeHGlobal(buffer); }
    }
    public static int Run(string encoded, string expectedSid, int session)
    {
        using (var self = WindowsIdentity.GetCurrent())
            if (!self.IsSystem) throw new InvalidOperationException("Dispatcher must be SYSTEM");
        if (session < 1 || String.IsNullOrEmpty(expectedSid) ||
            !Regex.IsMatch(expectedSid, @"\AS-1-(?:5-21|12-1)-[0-9-]+\z") ||
            String.IsNullOrEmpty(encoded) || encoded.Length > 28000 || encoded.Length % 4 != 0 ||
            !Regex.IsMatch(encoded, @"\A[A-Za-z0-9+/]+={0,2}\z")) throw new ArgumentException("Invalid request");
        IntPtr token = IntPtr.Zero, linked = IntPtr.Zero, job = IntPtr.Zero, environment = IntPtr.Zero, desktop = IntPtr.Zero;
        ProcessInfo process = new ProcessInfo(); bool assigned = false;
        try
        {
            if (!WTSQueryUserToken((uint)session, out token)) throw new Win32Exception(Marshal.GetLastWin32Error(), "WTSQueryUserToken");
            IntPtr selected = token;
            // WTS may return the full split token of a logged-on administrator.
            // Always use its limited half. A default (non-split) token retains
            // the logged-on user's own rights, including when UAC is disabled.
            if (ReadTokenInt(selected, 18) == 2)
            {
                linked = ReadLinkedToken(selected);
                selected = linked;
                if (ReadTokenInt(selected, 18) != 3 || ReadTokenInt(selected, 20) != 0)
                    throw new InvalidOperationException("Limited user token is unavailable");
            }
            using (var user = new WindowsIdentity(selected))
                if (user.User.Value != expectedSid || user.IsSystem) throw new InvalidOperationException("User identity mismatch");
            if (ReadTokenInt(selected, 12) != session || ReadTokenInt(selected, 8) != 1)
                throw new InvalidOperationException("User session or primary token mismatch");
            if (!CreateEnvironmentBlock(out environment, selected, false)) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateEnvironmentBlock");
            job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) throw new Win32Exception();
            var limits = new ExtendedLimits(); limits.Basic.Flags = 0x2000;
            if (!SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits))) throw new Win32Exception();
            string powershell = System.IO.Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
            var command = new StringBuilder("\"" + powershell + "\" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded);
            desktop = Marshal.StringToHGlobalUni(@"winsta0\default");
            var startup = new StartupInfo(); startup.Size = Marshal.SizeOf(startup); startup.Desktop = desktop;
            if (!CreateProcessAsUser(selected, powershell, command, IntPtr.Zero, IntPtr.Zero, false, 0x08000404,
                environment, Environment.SystemDirectory, ref startup, out process))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateProcessAsUser");
            if (!AssignProcessToJobObject(job, process.Process)) throw new Win32Exception(Marshal.GetLastWin32Error(), "AssignProcessToJobObject");
            assigned = true;
            if (ResumeThread(process.Thread) == uint.MaxValue) throw new Win32Exception();
            // The caller and Task Scheduler own independent bounded deadlines.
            // Stopping this dispatcher closes the job and all its descendants.
            if (WaitForSingleObject(process.Process, uint.MaxValue) != 0) throw new Win32Exception();
            uint exitCode; if (!GetExitCodeProcess(process.Process, out exitCode)) throw new Win32Exception();
            return unchecked((int)exitCode);
        }
        finally
        {
            if (process.Process != IntPtr.Zero && !assigned) TerminateProcess(process.Process, 87);
            if (job != IntPtr.Zero) CloseHandle(job);
            if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread);
            if (process.Process != IntPtr.Zero) CloseHandle(process.Process);
            if (environment != IntPtr.Zero) DestroyEnvironmentBlock(environment);
            if (desktop != IntPtr.Zero) Marshal.FreeHGlobal(desktop);
            if (linked != IntPtr.Zero) CloseHandle(linked);
            if (token != IntPtr.Zero) CloseHandle(token);
        }
    }
}
