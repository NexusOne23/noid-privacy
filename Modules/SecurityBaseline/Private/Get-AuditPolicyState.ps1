function Get-AuditPolicyState {
    [CmdletBinding()]
    [OutputType([uint32])]
    param(
        [Parameter(Mandatory = $true)]
        [Guid]$SubcategoryGuid
    )

    if (-not ('NoIDAuditNative' -as [type])) {
        $nativeSource = @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
internal struct AUDIT_POLICY_INFORMATION
{
    public Guid AuditSubCategoryGuid;
    public UInt32 AuditingInformation;
    public Guid AuditCategoryGuid;
}

public static class NoIDAuditNative
{
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.U1)]
    private static extern bool AuditQuerySystemPolicy(
        [In] Guid[] pSubCategoryGuids,
        UInt32 dwPolicyCount,
        out IntPtr ppAuditPolicy);

    [DllImport("advapi32.dll")]
    private static extern void AuditFree(IntPtr buffer);

    public static UInt32 Query(Guid subcategoryGuid)
    {
        IntPtr buffer;
        if (!AuditQuerySystemPolicy(new Guid[] { subcategoryGuid }, 1, out buffer))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "AuditQuerySystemPolicy failed");
        }
        try
        {
            AUDIT_POLICY_INFORMATION policy =
                (AUDIT_POLICY_INFORMATION)Marshal.PtrToStructure(
                    buffer,
                    typeof(AUDIT_POLICY_INFORMATION));
            if (policy.AuditSubCategoryGuid != subcategoryGuid)
            {
                throw new InvalidOperationException("AuditQuerySystemPolicy returned a different subcategory");
            }
            // AuditQuerySystemPolicy returns 0 for an effective "No Auditing"
            // state (confirmed against auditpol). Normalize that query state
            // to the sealed POLICY_AUDIT_EVENT_NONE flag (4); restore maps it
            // to explicit /success:disable and /failure:disable switches.
            return policy.AuditingInformation == 0 ? 4U : policy.AuditingInformation;
        }
        finally
        {
            AuditFree(buffer);
        }
    }

}
'@
        Add-Type -TypeDefinition $nativeSource -Language CSharp -ErrorAction Stop
    }

    return [uint32][NoIDAuditNative]::Query($SubcategoryGuid)
}
