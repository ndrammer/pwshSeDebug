function Disable-SeDebugPrivilege {
    $definition = @'
        using System;
        using System.Runtime.InteropServices;
        using System.Security.Principal;

        public class PrivilegeAdjuster {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out IntPtr TokenHandle);

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLengthInBytes, IntPtr PreviousState, IntPtr ReturnLengthInBytes);

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern IntPtr GetCurrentProcess();

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct LUID {
                public uint LowPart;
                public int HighPart;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct LUID_AND_ATTRIBUTES {
                public LUID Luid;
                public uint Attributes;
            }

            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            internal struct TOKEN_PRIVILEGES {
                public uint PrivilegeCount;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
                public LUID_AND_ATTRIBUTES[] Privileges;
            }

            public const int SE_PRIVILEGE_DISABLED = 0x000000000;
            public const int TOKEN_ADJUST_PRIVILEGES = 0x0020;
            public const int TOKEN_QUERY = 0x0008;

            public static bool DisableDebugPrivilege() {
                IntPtr hToken;
                LUID luid;
                TOKEN_PRIVILEGES tkp;
                
                if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken)) {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out luid)) {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                tkp.PrivilegeCount = 1;
                tkp.Privileges = new LUID_AND_ATTRIBUTES[1];
                tkp.Privileges[0].Luid = luid;
                tkp.Privileges[0].Attributes = SE_PRIVILEGE_DISABLED;

                if (!AdjustTokenPrivileges(hToken, false, ref tkp, 0, IntPtr.Zero, IntPtr.Zero)) {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                return Marshal.GetLastWin32Error() == 0; 
            }
        }
'@

    Add-Type -TypeDefinition $definition -Language CSharp
    return [PrivilegeAdjuster]::DisableDebugPrivilege()
}


$success = Disable-SeDebugPrivilege
if ($success) {
    Write-Output "SeDebugPrivilege has been succesfully disabled."
} else {
    Write-Output "It was not possible to disable SeDebugPrivilege."
}
