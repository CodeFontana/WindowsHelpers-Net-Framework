using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace WindowsNative
{
    class NativeMethods
    {
        // ******************************
        // External Windows Functions.
        // ******************************

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool AdjustTokenPrivileges(
            IntPtr TokenHandle,
            [MarshalAs(UnmanagedType.Bool)] bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState,
            UInt32 BufferLengthInBytes,
            out TOKEN_PRIVILEGES PreviousState, // ref TOKEN_PRIVILEGES PreviousState
            out UInt32 ReturnLengthInBytes);

        [DllImportAttribute("advapi32.dll", EntryPoint = "AllocateAndInitializeSid")]
        [return: MarshalAsAttribute(UnmanagedType.Bool)]
        public static extern bool AllocateAndInitializeSid(
            [InAttribute] ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            byte nSubAuthorityCount,
            uint nSubAuthority0,
            uint nSubAuthority1,
            uint nSubAuthority2,
            uint nSubAuthority3,
            uint nSubAuthority4,
            uint nSubAuthority5,
            uint nSubAuthority6,
            uint nSubAuthority7,
            ref IntPtr pSid);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool AttachConsole(int dwProcessId);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern void BuildExplicitAccessWithName(
            ref EXPLICIT_ACCESS pExplicitAccess,
            string pTrusteeName,
            ACCESS_MASK AccessPermissions,
            ACCESS_MODE AccessMode,
            uint Inheritance);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean ChangeServiceConfig(
            IntPtr hService,
            UInt32 nServiceType,
            UInt32 nStartType,
            UInt32 nErrorControl,
            String lpBinaryPathName,
            String lpLoadOrderGroup,
            IntPtr lpdwTagId,
            [In] char[] lpDependencies,
            String lpServiceStartName,
            String lpPassword,
            String lpDisplayName);

        [DllImport("User32.Dll")]
        public static extern bool ClientToScreen(IntPtr hWnd, ref POINT point);

        [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CloseDesktop(IntPtr hDesktop);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("advapi32.dll", EntryPoint = "CloseServiceHandle")]
        public static extern int CloseServiceHandle(IntPtr hSCObject);

        [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CloseWindowStation(IntPtr hWinSta);

        [DllImport("userenv.dll", SetLastError = true)]
        public static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFile(
            string lpFileName,
            EFileAccess dwDesiredAccess,
            EFileShare dwShareMode,
            IntPtr lpSecurityAttributes,
            ECreationDisposition dwCreationDisposition,
            EFileAttributes dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CreateProcessAsUser(
            IntPtr hToken,
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(
            IntPtr hToken,
            LogonFlags dwLogonFlags,
            string lpApplicationName,
            string lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr CreateService(
            IntPtr hSCManager,
            string lpServiceName,
            string lpDisplayName,
            uint dwDesiredAccess,
            uint dwServiceType,
            uint dwStartType,
            uint dwErrorControl,
            string lpBinaryPathName,
            string lpLoadOrderGroup,
            string lpdwTagId,
            string lpDependencies,
            string lpServiceStartName,
            string lpPassword);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool DeviceIoControl(
            IntPtr hDevice,
            uint dwIoControlCode,
            IntPtr InBuffer,
            int nInBufferSize,
            IntPtr OutBuffer,
            int nOutBufferSize,
            out int pBytesReturned, IntPtr lpOverlapped);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateToken(
            IntPtr ExistingTokenHandle,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            out IntPtr DuplicateTokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            ref IntPtr phNewToken);

        [DllImport("user32.dll")]
        public static extern bool EnableMenuItem(IntPtr hMenu, uint uIDEnableItem, uint uEnable);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool FreeConsole();

        [DllImportAttribute("advapi32.dll", EntryPoint = "FreeSid")]
        public static extern IntPtr FreeSid([InAttribute] IntPtr pSid);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetConsoleWindow();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetCursorPos(out POINT lpPoint);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern UInt32 GetDynamicTimeZoneInformation(out DYNAMIC_TIME_ZONE_INFORMATION lpTimeZoneInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetProcessWindowStation();

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr GetSidSubAuthority(IntPtr pSid, UInt32 nSubAuthority);

        [DllImport("user32.dll")]
        public static extern IntPtr GetSystemMenu(IntPtr hWnd, bool bRevert);

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int GetSystemMetrics(int nIndex);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetThreadDesktop(int dwThreadId);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(
            IntPtr hToken,
            TOKEN_INFORMATION_CLASS tokenInfoClass,
            IntPtr pTokenInfo,
            Int32 tokenInfoLength,
            out Int32 returnLength);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern int GetWindowLong(IntPtr hWnd, int nIndex);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool InitiateSystemShutdownEx(
            string lpMachineName,
            string lpMessage,
            uint dwTimeout,
            bool bForceAppsClosed,
            bool bRebootAfterShutdown,
            ShutdownReason dwReason);

        [DllImport("userenv.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO lpProfileInfo);

        [DllImportAttribute("kernel32.dll", EntryPoint = "LocalFree")]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LogonUser(
            string pszUserName,
            string pszDomain,
            string pszPassword,
            int dwLogonType,
            int dwLogonProvider,
            ref IntPtr phToken);

        [DllImport("advapi32.dll")]
        public static extern bool LookupPrivilegeValue(
            string lpSystemName,
            string lpName,
            ref LUID lpLuid);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool MoveFileEx(
        string lpExistingFileName,
        string lpNewFileName,
        MoveFileFlags dwFlags);

        [DllImport("netapi32.dll", EntryPoint = "NetApiBufferFree")]
        public static extern void NetApiBufferFree(IntPtr bufptr);

        [DllImport("netapi32.dll", EntryPoint = "NetLocalGroupGetMembers")]
        public static extern uint NetLocalGroupGetMembers(
            IntPtr ServerName,
            IntPtr GrouprName,
            uint level,
            ref IntPtr siPtr,
            uint prefmaxlen,
            ref uint entriesread,
            ref uint totalentries,
            IntPtr resumeHandle);

        [DllImport("netapi32.dll", EntryPoint = "NetLocalGroupEnum")]
        public static extern uint NetLocalGroupEnum(
            IntPtr ServerName,
            uint level,
            ref IntPtr siPtr,
            uint prefmaxlen,
            ref uint entriesread,
            ref uint totalentries,
            IntPtr resumeHandle);

        [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenDesktop(string name, Int32 flags, bool fInherit, long param);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(
            IntPtr hProcess,
            UInt32 desiredAccess,
            out IntPtr hToken);

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenWindowStation(string name, bool fInherit, uint needAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool RevertToSelf();

        [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr SendMessage(IntPtr hWnd, int Msg, int wParam, IntPtr lParam);

        [DllImport("user32", EntryPoint = "SendMessageTimeoutA", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
        public static extern int SendMessageTimeout(int hwnd, uint msg, int wParam, string lParam, uint fuFlags, uint uTimeout, ref ushort lpdwResult);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetComputerName(string lpComputerName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetComputerNameEx(COMPUTER_NAME_FORMAT NameType, string lpBuffer);

        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetCursorPos(int x, int y);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern bool SetDynamicTimeZoneInformation([In] ref DYNAMIC_TIME_ZONE_INFORMATION lpTimeZoneInformation);

        [DllImport("Advapi32.dll", EntryPoint = "SetEntriesInAclA", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Ansi)]
        public static extern int SetEntriesInAcl(
            int CountofExplicitEntries,
            ref EXPLICIT_ACCESS ea,
            IntPtr OldAcl,
            ref IntPtr NewAcl);

        [DllImport("user32.dll")]
        public static extern bool SetForegroundWindow(IntPtr hWnd);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern int SetNamedSecurityInfo(
            string pObjectName,
            SE_OBJECT_TYPE ObjectType,
            SECURITY_INFORMATION SecurityInfo,
            IntPtr psidOwner,
            IntPtr psidGroup,
            IntPtr pDacl,
            IntPtr pSacl);

        [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetProcessWindowStation(IntPtr hWinSta);

        [DllImport("User32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetThreadDesktop(IntPtr hDesktop);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern EXECUTION_STATE SetThreadExecutionState(EXECUTION_STATE esFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean SetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            ref UInt32 TokenInformation,
            UInt32 TokenInformationLength);

        [DllImport("user32.dll")]
        public static extern int SetWindowLong(IntPtr hWnd, int nIndex, int dwNewLong);

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SystemParametersInfo(uint uAction, uint uParam, string lpvParam, int fuWinIni);

        [DllImport("Userenv.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool UnloadUserProfile(IntPtr hToken, IntPtr lpProfileInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSCloseServer(IntPtr hServer);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSEnumerateSessions(
            IntPtr hServer,
            [MarshalAs(UnmanagedType.U4)] Int32 Reserved,
            [MarshalAs(UnmanagedType.U4)] Int32 Version,
            ref IntPtr ppSessionInfo,
            [MarshalAs(UnmanagedType.U4)] out UInt32 pCount);

        [DllImport("wtsapi32.dll")]
        public static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern uint WTSGetActiveConsoleSessionId();

        [DllImport("wtsapi32.dll")]
        public static extern IntPtr WTSOpenServer([MarshalAs(UnmanagedType.LPStr)] String pServerName);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        public static extern bool WTSQueryUserToken(
            UInt32 sessionId,
            out IntPtr Token);

        [DllImport("Wtsapi32.dll")]
        public static extern bool WTSQuerySessionInformation(
            IntPtr hServer,
            int sessionId,
            WTS_INFO_CLASS wtsInfoClass,
            out IntPtr ppBuffer,
            out uint pBytesReturned);

        // ******************************
        // Classes.
        // ******************************
        public class GenericAccessRule : AccessRule
        {
            public GenericAccessRule(
                IdentityReference identity,
                int accessMask,
                AccessControlType type) :
                base(identity, accessMask, false, InheritanceFlags.None, PropagationFlags.None, type)
            {

            }
        }

        public class GenericSecurity : NativeObjectSecurity
        {
            public GenericSecurity(
                bool isContainer,
                ResourceType resType,
                SafeHandle objectHandle,
                AccessControlSections sectionsRequested)
                : base(isContainer, resType, objectHandle, sectionsRequested)
            {

            }

            new public void Persist(SafeHandle handle, AccessControlSections includeSections)
            {
                base.Persist(handle, includeSections);
            }

            new public void AddAccessRule(AccessRule rule)
            {
                base.AddAccessRule(rule);
            }

            public override Type AccessRightType
            {
                get { throw new NotImplementedException(); }
            }

            public override AccessRule AccessRuleFactory(
                IdentityReference identityReference,
                int accessMask,
                bool isInherited,
                InheritanceFlags inheritanceFlags,
                PropagationFlags propagationFlags,
                AccessControlType type)
            {
                throw new NotImplementedException();
            }

            public override Type AccessRuleType
            {
                get { return typeof(AccessRule); }
            }

            public override AuditRule AuditRuleFactory(
                IdentityReference identityReference,
                int accessMask,
                bool isInherited,
                InheritanceFlags inheritanceFlags,
                PropagationFlags propagationFlags,
                AuditFlags flags)
            {
                throw new NotImplementedException();
            }

            public override Type AuditRuleType
            {
                get { return typeof(AuditRule); }
            }
        }

        public class NoopSafeHandle : SafeHandle
        {
            public NoopSafeHandle(IntPtr handle) : base(handle, false)
            {

            }

            public override bool IsInvalid
            {
                get { return false; }
            }

            protected override bool ReleaseHandle()
            {
                return true;
            }
        }

        // ******************************
        // Structures.
        // ******************************

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray)] public LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_ELEVATION
        {
            public Int32 TokenIsElevated;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_MANDATORY_LABEL
        {
            public SID_AND_ATTRIBUTES Label;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct WTS_SESSION_INFO
        {
            public UInt32 SessionID;
            [MarshalAs(UnmanagedType.LPStr)] public String pWinStationName;
            public WTS_CONNECTSTATE_CLASS State;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct REPARSE_DATA_BUFFER
        {
            // Reparse point tag. Must be a Microsoft reparse point tag.
            public uint reparseTag;

            // Size, in bytes, of the data after the Reserved member. This can be calculated by:
            // (4 * sizeof(ushort)) + SubstituteNameLength + PrintNameLength + (namesAreNullTerminated ? 2 * sizeof(char) : 0)
            public ushort reparseDataLength;

            // Reserved -- do not use
            public ushort Reserved;

            // Offset, in bytes, of the substitute name string in the PathBuffer array.
            public ushort SubstituteNameOffset;

            // Length, in bytes, of the substitute name string. If this string is null-terminated, SubstituteNameLength does not include space for the null character.
            public ushort SubstituteNameLength;

            // Offset, in bytes, of the print name string in the PathBuffer array.
            public ushort PrintNameOffset;

            // Length, in bytes, of the print name string. If this string is null-terminated, PrintNameLength does not include space for the null character. 
            public ushort PrintNameLength;

            // A buffer containing the unicode-encoded path string. The path string contains the substitute name string and print name string.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 0x3FF0)] public byte[] pathBuffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROFILEINFO
        {
            /// Specifies the size of the structure, in bytes.
            public int dwSize;

            /// This member can be one of the following flags: PI_NOUI or PI_APPLYPOLICY
            public int dwFlags;

            /// Pointer to the name of the user.
            /// This member is used as the base name of the directory in which to store a new profile.
            public string lpUserName;

            /// Pointer to the roaming user profile path.
            /// If the user does not have a roaming profile, this member can be NULL.
            public string lpProfilePath;

            /// Pointer to the default user profile path. This member can be NULL.
            public string lpDefaultPath;

            /// Pointer to the name of the validating domain controller, in NetBIOS format.
            /// If this member is NULL, the Windows NT 4.0-style policy will not be applied.
            public string lpServerName;

            /// Pointer to the path of the Windows NT 4.0-style policy file. This member can be NULL.
            public string lpPolicyPath;

            /// Handle to the HKEY_CURRENT_USER registry key.
            public IntPtr hProfile;
        }

        [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct LOCALGROUP_MEMBERS_INFO_1
        {
            public IntPtr lgrmi1_sid;
            public IntPtr lgrmi1_sidusage;
            public IntPtr lgrmi1_name;
        }

        [StructLayoutAttribute(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct LOCALGROUP_INFO_1
        {
            public IntPtr lpszGroupName;
            public IntPtr lpszComment;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct POINT
        {
            public int x;
            public int y;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct SYSTEMTIME
        {
            public ushort wYear;
            public ushort wMonth;
            public ushort wDayOfWeek;
            public ushort wDay;
            public ushort wHour;
            public ushort wMinute;
            public ushort wSecond;
            public ushort wMilliseconds;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct REGTZI
        {
            public int Bias;
            public int StandardBias;
            public int DaylightBias;
            public SYSTEMTIME StandardDate;
            public SYSTEMTIME DaylightDate;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct DYNAMIC_TIME_ZONE_INFORMATION
        {
            [MarshalAs(UnmanagedType.I4)]
            public int bias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string standardName;
            public SYSTEMTIME standardDate;
            [MarshalAs(UnmanagedType.I4)]
            public int standardBias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
            public string daylightName;
            public SYSTEMTIME daylightDate;
            [MarshalAs(UnmanagedType.I4)]
            public int daylightBias;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string timeZoneKeyName;
            public bool dynamicDaylightTimeDisabled;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_IDENTIFIER_AUTHORITY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
            public byte[] Value;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct TRUSTEE
        {
            public System.IntPtr pMultipleTrustee;
            public MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
            public TRUSTEE_FORM TrusteeForm;
            public TRUSTEE_TYPE TrusteeType;
            public IntPtr ptstrName;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct EXPLICIT_ACCESS
        {
            public ACCESS_MASK grfAccessPermissions;
            public ACCESS_MODE grfAccessMode;
            public uint grfInheritance;
            public TRUSTEE Trustee;
        }

        // ******************************
        // Enums.
        // ******************************

        public enum COMPUTER_NAME_FORMAT
        {
            ComputerNameNetBIOS,
            ComputerNameDnsHostname,
            ComputerNameDnsDomain,
            ComputerNameDnsFullyQualified,
            ComputerNamePhysicalNetBIOS,
            ComputerNamePhysicalDnsHostname,
            ComputerNamePhysicalDnsDomain,
            ComputerNamePhysicalDnsFullyQualified,
        }

        public enum CreateProcessFlags : uint
        {
            DEBUG_PROCESS = 0x00000001,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            CREATE_SUSPENDED = 0x00000004,
            DETACHED_PROCESS = 0x00000008,
            CREATE_NEW_CONSOLE = 0x00000010,
            NORMAL_PRIORITY_CLASS = 0x00000020,
            IDLE_PRIORITY_CLASS = 0x00000040,
            HIGH_PRIORITY_CLASS = 0x00000080,
            REALTIME_PRIORITY_CLASS = 0x00000100,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_FORCEDOS = 0x00002000,
            BELOW_NORMAL_PRIORITY_CLASS = 0x00004000,
            ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000,
            INHERIT_PARENT_AFFINITY = 0x00010000,
            INHERIT_CALLER_PRIORITY = 0x00020000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            PROCESS_MODE_BACKGROUND_BEGIN = 0x00100000,
            PROCESS_MODE_BACKGROUND_END = 0x00200000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NO_WINDOW = 0x08000000,
            PROFILE_USER = 0x10000000,
            PROFILE_KERNEL = 0x20000000,
            PROFILE_SERVER = 0x40000000,
            CREATE_IGNORE_SYSTEM_DEFAULT = 0x80000000
        }

        [Flags]
        public enum EFileAccess : uint
        {
            GenericRead = 0x80000000,
            GenericWrite = 0x40000000,
            GenericExecute = 0x20000000,
            GenericAll = 0x10000000
        }

        [Flags]
        public enum EFileShare : uint
        {
            None = 0x00000000,
            Read = 0x00000001,
            Write = 0x00000002,
            Delete = 0x00000004
        }

        public enum ECreationDisposition
        {
            New = 1,
            CreateAlways = 2,
            OpenExisting = 3,
            OpenAlways = 4,
            TruncateExisting = 5
        }

        [Flags]
        public enum EFileAttributes : uint
        {
            Readonly = 0x00000001,
            Hidden = 0x00000002,
            System = 0x00000004,
            Directory = 0x00000010,
            Archive = 0x00000020,
            Device = 0x00000040,
            Normal = 0x00000080,
            Temporary = 0x00000100,
            SparseFile = 0x00000200,
            ReparsePoint = 0x00000400,
            Compressed = 0x00000800,
            Offline = 0x00001000,
            NotContentIndexed = 0x00002000,
            Encrypted = 0x00004000,
            Write_Through = 0x80000000,
            Overlapped = 0x40000000,
            NoBuffering = 0x20000000,
            RandomAccess = 0x10000000,
            SequentialScan = 0x08000000,
            DeleteOnClose = 0x04000000,
            BackupSemantics = 0x02000000,
            PosixSemantics = 0x01000000,
            OpenReparsePoint = 0x00200000,
            OpenNoRecall = 0x00100000,
            FirstPipeInstance = 0x00080000
        }

        [Flags]
        public enum SCM_ACCESS : uint
        {
            STANDARD_RIGHTS_REQUIRED = 0xF0000,
            SC_MANAGER_CONNECT = 0x00001,
            SC_MANAGER_CREATE_SERVICE = 0x00002,
            SC_MANAGER_ENUMERATE_SERVICE = 0x00004,
            SC_MANAGER_LOCK = 0x00008,
            SC_MANAGER_QUERY_LOCK_STATUS = 0x00010,
            SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00020,
            SC_MANAGER_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
                             SC_MANAGER_CONNECT |
                             SC_MANAGER_CREATE_SERVICE |
                             SC_MANAGER_ENUMERATE_SERVICE |
                             SC_MANAGER_LOCK |
                             SC_MANAGER_QUERY_LOCK_STATUS |
                             SC_MANAGER_MODIFY_BOOT_CONFIG
        }

        [Flags]
        public enum SERVICE_ACCESS : uint
        {
            STANDARD_RIGHTS_REQUIRED = 0xF0000,
            SERVICE_QUERY_CONFIG = 0x00001,
            SERVICE_CHANGE_CONFIG = 0x00002,
            SERVICE_QUERY_STATUS = 0x00004,
            SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
            SERVICE_START = 0x00010,
            SERVICE_STOP = 0x00020,
            SERVICE_PAUSE_CONTINUE = 0x00040,
            SERVICE_INTERROGATE = 0x00080,
            SERVICE_USER_DEFINED_CONTROL = 0x00100,
            SERVICE_ALL_ACCESS =
                (STANDARD_RIGHTS_REQUIRED | SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE
                    | SERVICE_INTERROGATE | SERVICE_USER_DEFINED_CONTROL)
        }

        [Flags]
        public enum SERVICE_TYPES : int
        {
            SERVICE_KERNEL_DRIVER = 0x00000001,
            SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
            SERVICE_WIN32_OWN_PROCESS = 0x00000010,
            SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
            SERVICE_INTERACTIVE_PROCESS = 0x00000100
        }

        public enum SERVICE_START_TYPES : int
        {
            SERVICE_AUTO_START = 0x00000002,
            SERVICE_BOOT_START = 0x00000000,
            SERVICE_DEMAND_START = 0x00000003,
            SERVICE_DISABLED = 0x00000004,
            SERVICE_SYSTEM_START = 0x00000001
        }

        public enum SERVICE_ERROR_CONTROL : int
        {
            SERVICE_ERROR_CRITICAL = 0x00000003,
            SERVICE_ERROR_IGNORE = 0x00000000,
            SERVICE_ERROR_NORMAL = 0x00000001,
            SERVICE_ERROR_SEVERE = 0x00000002,
        }

        public enum Style
        {
            Fill,
            Fit,
            Span,
            Stretch,
            Tile,
            Center
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            MaxTokenInfoClass
        }

        public enum SECURITY_IMPERSONATION_LEVEL
        {
            SecurityAnonymous,
            SecurityIdentification,
            SecurityImpersonation,
            SecurityDelegation
        }

        public enum TOKEN_ELEVATION_TYPE
        {
            TokenElevationTypeDefault = 1,
            TokenElevationTypeFull,
            TokenElevationTypeLimited
        }

        public enum WELL_KNOWN_SID_TYPE
        {
            WinNullSid = 0,
            WinWorldSid = 1,
            WinLocalSid = 2,
            WinCreatorOwnerSid = 3,
            WinCreatorGroupSid = 4,
            WinCreatorOwnerServerSid = 5,
            WinCreatorGroupServerSid = 6,
            WinNtAuthoritySid = 7,
            WinDialupSid = 8,
            WinNetworkSid = 9,
            WinBatchSid = 10,
            WinInteractiveSid = 11,
            WinServiceSid = 12,
            WinAnonymousSid = 13,
            WinProxySid = 14,
            WinEnterpriseControllersSid = 15,
            WinSelfSid = 16,
            WinAuthenticatedUserSid = 17,
            WinRestrictedCodeSid = 18,
            WinTerminalServerSid = 19,
            WinRemoteLogonIdSid = 20,
            WinLogonIdsSid = 21,
            WinLocalSystemSid = 22,
            WinLocalServiceSid = 23,
            WinNetworkServiceSid = 24,
            WinBuiltinDomainSid = 25,
            WinBuiltinAdministratorsSid = 26,
            WinBuiltinUsersSid = 27,
            WinBuiltinGuestsSid = 28,
            WinBuiltinPowerUsersSid = 29,
            WinBuiltinAccountOperatorsSid = 30,
            WinBuiltinSystemOperatorsSid = 31,
            WinBuiltinPrintOperatorsSid = 32,
            WinBuiltinBackupOperatorsSid = 33,
            WinBuiltinReplicatorSid = 34,
            WinBuiltinPreWindows2000CompatibleAccessSid = 35,
            WinBuiltinRemoteDesktopUsersSid = 36,
            WinBuiltinNetworkConfigurationOperatorsSid = 37,
            WinAccountAdministratorSid = 38,
            WinAccountGuestSid = 39,
            WinAccountKrbtgtSid = 40,
            WinAccountDomainAdminsSid = 41,
            WinAccountDomainUsersSid = 42,
            WinAccountDomainGuestsSid = 43,
            WinAccountComputersSid = 44,
            WinAccountControllersSid = 45,
            WinAccountCertAdminsSid = 46,
            WinAccountSchemaAdminsSid = 47,
            WinAccountEnterpriseAdminsSid = 48,
            WinAccountPolicyAdminsSid = 49,
            WinAccountRasAndIasServersSid = 50,
            WinNTLMAuthenticationSid = 51,
            WinDigestAuthenticationSid = 52,
            WinSChannelAuthenticationSid = 53,
            WinThisOrganizationSid = 54,
            WinOtherOrganizationSid = 55,
            WinBuiltinIncomingForestTrustBuildersSid = 56,
            WinBuiltinPerfMonitoringUsersSid = 57,
            WinBuiltinPerfLoggingUsersSid = 58,
            WinBuiltinAuthorizationAccessSid = 59,
            WinBuiltinTerminalServerLicenseServersSid = 60,
            WinBuiltinDCOMUsersSid = 61,
            WinBuiltinIUsersSid = 62,
            WinIUserSid = 63,
            WinBuiltinCryptoOperatorsSid = 64,
            WinUntrustedLabelSid = 65,
            WinLowLabelSid = 66,
            WinMediumLabelSid = 67,
            WinHighLabelSid = 68,
            WinSystemLabelSid = 69,
            WinWriteRestrictedCodeSid = 70,
            WinCreatorOwnerRightsSid = 71,
            WinCacheablePrincipalsGroupSid = 72,
            WinNonCacheablePrincipalsGroupSid = 73,
            WinEnterpriseReadonlyControllersSid = 74,
            WinAccountReadonlyControllersSid = 75,
            WinBuiltinEventLogReadersGroup = 76,
            WinNewEnterpriseReadonlyControllersSid = 77,
            WinBuiltinCertSvcDComAccessGroup = 78
        }

        public enum WTS_INFO_CLASS
        {
            WTSInitialProgram,
            WTSApplicationName,
            WTSWorkingDirectory,
            WTSOEMId,
            WTSSessionId,
            WTSUserName,
            WTSWinStationName,
            WTSDomainName,
            WTSConnectState,
            WTSClientBuildNumber,
            WTSClientName,
            WTSClientDirectory,
            WTSClientProductId,
            WTSClientHardwareId,
            WTSClientAddress,
            WTSClientDisplay,
            WTSClientProtocolType
        }

        public enum WTS_CONNECTSTATE_CLASS
        {
            WTSActive,
            WTSConnected,
            WTSConnectQuery,
            WTSShadow,
            WTSDisconnected,
            WTSIdle,
            WTSListen,
            WTSReset,
            WTSDown,
            WTSInit
        }

        [FlagsAttribute]
        public enum EXECUTION_STATE : uint
        {
            ES_AWAYMODE_REQUIRED = 0x00000040,
            ES_CONTINUOUS = 0x80000000,
            ES_DISPLAY_REQUIRED = 0x00000002,
            ES_SYSTEM_REQUIRED = 0x00000001
            // Legacy flag, should not be used.
            // ES_USER_PRESENT = 0x00000004
        }

        public enum LogonFlags
        {
            /// <summary>
            /// Log on, then load the user's profile in the HKEY_USERS registry key. The function
            /// returns after the profile has been loaded. Loading the profile can be time-consuming,
            /// so it is best to use this value only if you must access the information in the
            /// HKEY_CURRENT_USER registry key.
            /// NOTE: Windows Server 2003: The profile is unloaded after the new process has been
            /// terminated, regardless of whether it has created child processes.
            /// </summary>
            /// <remarks>See LOGON_WITH_PROFILE</remarks>
            WithProfile = 1,
            /// <summary>
            /// Log on, but use the specified credentials on the network only. The new process uses the
            /// same token as the caller, but the system creates a new logon session within LSA, and
            /// the process uses the specified credentials as the default credentials.
            /// This value can be used to create a process that uses a different set of credentials
            /// locally than it does remotely. This is useful in inter-domain scenarios where there is
            /// no trust relationship.
            /// The system does not validate the specified credentials. Therefore, the process can start,
            /// but it may not have access to network resources.
            /// </summary>
            /// <remarks>See LOGON_NETCREDENTIALS_ONLY</remarks>
            NetCredentialsOnly
        }

        public enum LogonType
        {
            /// <summary>
            /// This logon type is intended for users who will be interactively using the computer, such as a user being logged on  
            /// by a terminal server, remote shell, or similar process.
            /// This logon type has the additional expense of caching logon information for disconnected operations;
            /// therefore, it is inappropriate for some client/server applications,
            /// such as a mail server.
            /// </summary>
            LOGON32_LOGON_INTERACTIVE = 2,

            /// <summary>
            /// This logon type is intended for high performance servers to authenticate plaintext passwords.

            /// The LogonUser function does not cache credentials for this logon type.
            /// </summary>
            LOGON32_LOGON_NETWORK = 3,

            /// <summary>
            /// This logon type is intended for batch servers, where processes may be executing on behalf of a user without
            /// their direct intervention. This type is also for higher performance servers that process many plaintext
            /// authentication attempts at a time, such as mail or Web servers.
            /// The LogonUser function does not cache credentials for this logon type.
            /// </summary>
            LOGON32_LOGON_BATCH = 4,

            /// <summary>
            /// Indicates a service-type logon. The account provided must have the service privilege enabled.
            /// </summary>
            LOGON32_LOGON_SERVICE = 5,

            /// <summary>
            /// This logon type is for GINA DLLs that log on users who will be interactively using the computer.
            /// This logon type can generate a unique audit record that shows when the workstation was unlocked.
            /// </summary>
            LOGON32_LOGON_UNLOCK = 7,

            /// <summary>
            /// This logon type preserves the name and password in the authentication package, which allows the server to make
            /// connections to other network servers while impersonating the client. A server can accept plaintext credentials
            /// from a client, call LogonUser, verify that the user can access the system across the network, and still
            /// communicate with other servers.
            /// NOTE: Windows NT:  This value is not supported.
            /// </summary>
            LOGON32_LOGON_NETWORK_CLEARTEXT = 8,

            /// <summary>
            /// This logon type allows the caller to clone its current token and specify new credentials for outbound connections.
            /// The new logon session has the same local identifier but uses different credentials for other network connections.
            /// NOTE: This logon type is supported only by the LOGON32_PROVIDER_WINNT50 logon provider.
            /// NOTE: Windows NT:  This value is not supported.
            /// </summary>
            LOGON32_LOGON_NEW_CREDENTIALS = 9,
        }

        public enum LogonProvider
        {
            /// <summary>
            /// Use the standard logon provider for the system.
            /// The default security provider is negotiate, unless you pass NULL for the domain name and the user name
            /// is not in UPN format. In this case, the default provider is NTLM.
            /// NOTE: Windows 2000/NT:   The default security provider is NTLM.
            /// </summary>
            LOGON32_PROVIDER_DEFAULT = 0,
            LOGON32_PROVIDER_WINNT35 = 1,
            LOGON32_PROVIDER_WINNT40 = 2,
            LOGON32_PROVIDER_WINNT50 = 3
        }

        [Flags]
        public enum ExitWindows : uint
        {
            // ONE of the following five:
            LogOff = 0x00,
            ShutDown = 0x01,
            Reboot = 0x02,
            PowerOff = 0x08,
            RestartApps = 0x40,
            // plus AT MOST ONE of the following two:
            Force = 0x04,
            ForceIfHung = 0x10,
        }

        [Flags]
        public enum ShutdownReason : uint
        {
            MajorApplication = 0x00040000,
            MajorHardware = 0x00010000,
            MajorLegacyApi = 0x00070000,
            MajorOperatingSystem = 0x00020000,
            MajorOther = 0x00000000,
            MajorPower = 0x00060000,
            MajorSoftware = 0x00030000,
            MajorSystem = 0x00050000,

            MinorBlueScreen = 0x0000000F,
            MinorCordUnplugged = 0x0000000b,
            MinorDisk = 0x00000007,
            MinorEnvironment = 0x0000000c,
            MinorHardwareDriver = 0x0000000d,
            MinorHotfix = 0x00000011,
            MinorHung = 0x00000005,
            MinorInstallation = 0x00000002,
            MinorMaintenance = 0x00000001,
            MinorMMC = 0x00000019,
            MinorNetworkConnectivity = 0x00000014,
            MinorNetworkCard = 0x00000009,
            MinorOther = 0x00000000,
            MinorOtherDriver = 0x0000000e,
            MinorPowerSupply = 0x0000000a,
            MinorProcessor = 0x00000008,
            MinorReconfig = 0x00000004,
            MinorSecurity = 0x00000013,
            MinorSecurityFix = 0x00000012,
            MinorSecurityFixUninstall = 0x00000018,
            MinorServicePack = 0x00000010,
            MinorServicePackUninstall = 0x00000016,
            MinorTermSrv = 0x00000020,
            MinorUnstable = 0x00000006,
            MinorUpgrade = 0x00000003,
            MinorWMI = 0x00000015,

            FlagUserDefined = 0x40000000,
            FlagPlanned = 0x80000000
        }

        public enum ShowWindowCommands : uint
        {
            /// <summary>
            ///        Hides the window and activates another window.
            /// </summary>
            SW_HIDE = 0,

            /// <summary>
            ///        Activates and displays a window. If the window is minimized or maximized, the system restores it to its original size and position. An application should specify this flag when displaying the window for the first time.
            /// </summary>
            SW_SHOWNORMAL = 1,

            /// <summary>
            ///        Activates and displays a window. If the window is minimized or maximized, the system restores it to its original size and position. An application should specify this flag when displaying the window for the first time.
            /// </summary>
            SW_NORMAL = 1,

            /// <summary>
            ///        Activates the window and displays it as a minimized window.
            /// </summary>
            SW_SHOWMINIMIZED = 2,

            /// <summary>
            ///        Activates the window and displays it as a maximized window.
            /// </summary>
            SW_SHOWMAXIMIZED = 3,

            /// <summary>
            ///        Maximizes the specified window.
            /// </summary>
            SW_MAXIMIZE = 3,

            /// <summary>
            ///        Displays a window in its most recent size and position. This value is similar to <see cref="ShowWindowCommands.SW_SHOWNORMAL"/>, except the window is not activated.
            /// </summary>
            SW_SHOWNOACTIVATE = 4,

            /// <summary>
            ///        Activates the window and displays it in its current size and position.
            /// </summary>
            SW_SHOW = 5,

            /// <summary>
            ///        Minimizes the specified window and activates the next top-level window in the z-order.
            /// </summary>
            SW_MINIMIZE = 6,

            /// <summary>
            ///        Displays the window as a minimized window. This value is similar to <see cref="ShowWindowCommands.SW_SHOWMINIMIZED"/>, except the window is not activated.
            /// </summary>
            SW_SHOWMINNOACTIVE = 7,

            /// <summary>
            ///        Displays the window in its current size and position. This value is similar to <see cref="ShowWindowCommands.SW_SHOW"/>, except the window is not activated.
            /// </summary>
            SW_SHOWNA = 8,

            /// <summary>
            ///        Activates and displays the window. If the window is minimized or maximized, the system restores it to its original size and position. An application should specify this flag when restoring a minimized window.
            /// </summary>
            SW_RESTORE = 9,

            /// <summary>
            ///        Items 10, 11 and 11 existed in the VB definition but not the c# definition - so I am assuming this was a mistake and have added them here.
            ///         Please forgive me if this is wrong!  I don't think it should have any negative impact.
            ///         According to what I have read elsewhere: The SW_SHOWDEFAULT makes sure the window is restored prior to showing, then activating.
            ///         And the 11's try to coerce a window to minimized or maximized.
            /// </summary>
            SW_SHOWDEFAULT = 10,
            SW_FORCEMINIMIZE = 11,
            SW_MAX = 11
        }

        public enum MoveFileFlags
        {
            None = 0,
            ReplaceExisting = 1,
            CopyAllowed = 2,
            DelayUntilReboot = 4,
            WriteThrough = 8,
            CreateHardlink = 16,
            FailIfNotTrackable = 32,
        }

        public enum TRUSTEE_TYPE
        {
            TRUSTEE_IS_UNKNOWN,
            TRUSTEE_IS_USER,
            TRUSTEE_IS_GROUP,
            TRUSTEE_IS_DOMAIN,
            TRUSTEE_IS_ALIAS,
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            TRUSTEE_IS_DELETED,
            TRUSTEE_IS_INVALID,
            TRUSTEE_IS_COMPUTER
        }

        public enum TRUSTEE_FORM
        {
            TRUSTEE_IS_SID,
        }

        public enum MULTIPLE_TRUSTEE_OPERATION { }

        public enum SE_OBJECT_TYPE
        {
            SE_UNKNOWN_OBJECT_TYPE = 0,
            SE_FILE_OBJECT,
            SE_SERVICE,
            SE_PRINTER,
            SE_REGISTRY_KEY,
            SE_LMSHARE,
            SE_KERNEL_OBJECT,
            SE_WINDOW_OBJECT,
            SE_DS_OBJECT,
            SE_DS_OBJECT_ALL,
            SE_PROVIDER_DEFINED_OBJECT,
            SE_WMIGUID_OBJECT,
            SE_REGISTRY_WOW64_32KEY
        }

        [Flags]
        public enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,

            STANDARD_RIGHTS_REQUIRED = 0x000F0000,

            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,

            STANDARD_RIGHTS_ALL = 0x001F0000,

            SPECIFIC_RIGHTS_ALL = 0x0000FFFF,

            ACCESS_SYSTEM_SECURITY = 0x01000000,

            MAXIMUM_ALLOWED = 0x02000000,

            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,

            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,

            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,

            WINSTA_ALL_ACCESS = 0x0000037F
        }

        [Flags]
        public enum SECURITY_INFORMATION : uint
        {
            OWNER_SECURITY_INFORMATION = 0x00000001,
            DACL_SECURITY_INFORMATION = 0x00000004,
        }

        public enum ACCESS_MODE
        {
            NOT_USED_ACCESS,
            GRANT_ACCESS,
            SET_ACCESS,
            DENY_ACCESS,
            REVOKE_ACCESS,
            SET_AUDIT_SUCCESS,
            SET_AUDIT_FAILURE
        }

        // ******************************
        // Constants.
        // ******************************

        // Access masks
        public const UInt32 DELETE = 0x00010000;
        public const UInt32 READ_CONTROL = 0x00020000;
        public const UInt32 WRITE_DAC = 0x00040000;
        public const UInt32 WRITE_OWNER = 0x00080000;
        public const UInt32 SYNCHRONIZE = 0x00100000;

        public const UInt32 STANDARD_RIGHTS_REQUIRED = 0x000F0000;

        public const UInt32 STANDARD_RIGHTS_READ = 0x00020000;
        public const UInt32 STANDARD_RIGHTS_WRITE = 0x00020000;
        public const UInt32 STANDARD_RIGHTS_EXECUTE = 0x00020000;

        public const UInt32 STANDARD_RIGHTS_ALL = 0x001F0000;

        public const UInt32 SPECIFIC_RIGHTS_ALL = 0x0000FFFF;

        public const UInt32 ACCESS_SYSTEM_SECURITY = 0x01000000;

        public const UInt32 MAXIMUM_ALLOWED = 0x02000000;

        public const UInt32 GENERIC_READ = 0x80000000;
        public const UInt32 GENERIC_WRITE = 0x40000000;
        public const UInt32 GENERIC_EXECUTE = 0x20000000;
        public const UInt32 GENERIC_ALL = 0x10000000;

        public const UInt32 DESKTOP_READOBJECTS = 0x00000001;
        public const UInt32 DESKTOP_CREATEWINDOW = 0x00000002;
        public const UInt32 DESKTOP_CREATEMENU = 0x00000004;
        public const UInt32 DESKTOP_HOOKCONTROL = 0x00000008;
        public const UInt32 DESKTOP_JOURNALRECORD = 0x00000010;
        public const UInt32 DESKTOP_JOURNALPLAYBACK = 0x00000020;
        public const UInt32 DESKTOP_ENUMERATE = 0x00000040;
        public const UInt32 DESKTOP_WRITEOBJECTS = 0x00000080;
        public const UInt32 DESKTOP_SWITCHDESKTOP = 0x00000100;

        public const UInt32 WINSTA_ENUMDESKTOPS = 0x00000001;
        public const UInt32 WINSTA_READATTRIBUTES = 0x00000002;
        public const UInt32 WINSTA_ACCESSCLIPBOARD = 0x00000004;
        public const UInt32 WINSTA_CREATEDESKTOP = 0x00000008;
        public const UInt32 WINSTA_WRITEATTRIBUTES = 0x00000010;
        public const UInt32 WINSTA_ACCESSGLOBALATOMS = 0x00000020;
        public const UInt32 WINSTA_EXITWINDOWS = 0x00000040;
        public const UInt32 WINSTA_ENUMERATE = 0x00000100;
        public const UInt32 WINSTA_READSCREEN = 0x00000200;

        public const UInt32 WINSTA_ALL_ACCESS = 0x0000037F;

        // Token rights
        public const UInt32 TOKEN_ASSIGN_PRIMARY = 0x00000001;
        public const UInt32 TOKEN_DUPLICATE = 0x00000002;
        public const UInt32 TOKEN_IMPERSONATE = 0x00000004;
        public const UInt32 TOKEN_QUERY = 0x00000008;
        public const UInt32 TOKEN_QUERY_SOURCE = 0x00000010;
        public const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        public const UInt32 TOKEN_ADJUST_GROUPS = 0x00000040;
        public const UInt32 TOKEN_ADJUST_DEFAULT = 0x00000080;
        public const UInt32 TOKEN_ADJUST_SESSIONID = 0x00000100;
        public const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const UInt32 TOKEN_WRITE = (STANDARD_RIGHTS_READ | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT);
        public const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE |
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES |
            TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);
        public const int GENERIC_ALL_ACCESS = 0x10000000;
        public const int TOKEN_MAXIMUM_ALLOWED = 0x2000000;

        // Privileges
        public const int SE_PRIVILEGE_ENABLED = 0x00000002;
        public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        public const string SE_TCB_NAME = "SeTcbPrivilege";
        public const string SE_DEBUG_NAME = "SeDebugPrivilege";
        public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";
        public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";
        public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";
        public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";
        public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";

        public const int NO_INHERITANCE = 0x0;
        public const int SECURITY_BUILTIN_DOMAIN_RID = 0x00000020;
        public const int DOMAIN_ALIAS_RID_ADMINS = 0x00000220;

        // The file or directory is not a reparse point.
        public const int ERROR_NOT_A_REPARSE_POINT = 4390;

        // The reparse point attribute cannot be set because it conflicts with an existing attribute.
        public const int ERROR_REPARSE_ATTRIBUTE_CONFLICT = 4391;

        // The data present in the reparse point buffer is invalid.
        public const int ERROR_INVALID_REPARSE_DATA = 4392;

        // The tag present in the reparse point buffer is invalid.
        public const int ERROR_REPARSE_TAG_INVALID = 4393;

        // There is a mismatch between the tag specified in the request and the tag present in the reparse point.
        public const int ERROR_REPARSE_TAG_MISMATCH = 4394;

        // Command to set the reparse point data block.
        public const int FSCTL_SET_REPARSE_POINT = 0x000900A4;

        // Command to get the reparse point data block.
        public const int FSCTL_GET_REPARSE_POINT = 0x000900A8;

        // Command to delete the reparse point data base.
        public const int FSCTL_DELETE_REPARSE_POINT = 0x000900AC;

        // Reparse point tag used to identify mount points and junction points.
        public const uint IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003;

        // This prefix indicates to NTFS that the path is to be treated as a non-interpreted path in the virtual file system.
        public const string NonInterpretedPathPrefix = @"\??\";

        public const int LOGON32_PROVIDER_DEFAULT = 0;
        public const int LOGON32_LOGON_INTERACTIVE = 2; // LogonUser will create primary token

        // UI stuff
        public const int GWL_STYLE = -16;
        public const int WS_SYSMENU = 0x80000;
        public const int SC_MOVE = 0xF010;
        public const uint MF_BYCOMMAND = 0x00000000;
        public const uint MF_GRAYED = 0x00000001;
        public const uint MF_ENABLED = 0x00000000;
        public const uint SC_CLOSE = 0xF060;

        // UI stuff
        public const UInt32 WM_ACTIVATE = 0x0006;
        public const UInt32 WM_ACTIVATEAPP = 0x001C;
        public const UInt32 WM_AFXFIRST = 0x0360;
        public const UInt32 WM_AFXLAST = 0x037F;
        public const UInt32 WM_APP = 0x8000;
        public const UInt32 WM_ASKCBFORMATNAME = 0x030C;
        public const UInt32 WM_CANCELJOURNAL = 0x004B;
        public const UInt32 WM_CANCELMODE = 0x001F;
        public const UInt32 WM_CAPTURECHANGED = 0x0215;
        public const UInt32 WM_CHANGECBCHAIN = 0x030D;
        public const UInt32 WM_CHANGEUISTATE = 0x0127;
        public const UInt32 WM_CHAR = 0x0102;
        public const UInt32 WM_CHARTOITEM = 0x002F;
        public const UInt32 WM_CHILDACTIVATE = 0x0022;
        public const UInt32 WM_CLEAR = 0x0303;
        public const UInt32 WM_CLOSE = 0x0010;
        public const UInt32 WM_COMMAND = 0x0111;
        public const UInt32 WM_COMPACTING = 0x0041;
        public const UInt32 WM_COMPAREITEM = 0x0039;
        public const UInt32 WM_CONTEXTMENU = 0x007B;
        public const UInt32 WM_COPY = 0x0301;
        public const UInt32 WM_COPYDATA = 0x004A;
        public const UInt32 WM_CREATE = 0x0001;
        public const UInt32 WM_CTLCOLORBTN = 0x0135;
        public const UInt32 WM_CTLCOLORDLG = 0x0136;
        public const UInt32 WM_CTLCOLOREDIT = 0x0133;
        public const UInt32 WM_CTLCOLORLISTBOX = 0x0134;
        public const UInt32 WM_CTLCOLORMSGBOX = 0x0132;
        public const UInt32 WM_CTLCOLORSCROLLBAR = 0x0137;
        public const UInt32 WM_CTLCOLORSTATIC = 0x0138;
        public const UInt32 WM_CUT = 0x0300;
        public const UInt32 WM_DEADCHAR = 0x0103;
        public const UInt32 WM_DELETEITEM = 0x002D;
        public const UInt32 WM_DESTROY = 0x0002;
        public const UInt32 WM_DESTROYCLIPBOARD = 0x0307;
        public const UInt32 WM_DEVICECHANGE = 0x0219;
        public const UInt32 WM_DEVMODECHANGE = 0x001B;
        public const UInt32 WM_DISPLAYCHANGE = 0x007E;
        public const UInt32 WM_DRAWCLIPBOARD = 0x0308;
        public const UInt32 WM_DRAWITEM = 0x002B;
        public const UInt32 WM_DROPFILES = 0x0233;
        public const UInt32 WM_ENABLE = 0x000A;
        public const UInt32 WM_ENDSESSION = 0x0016;
        public const UInt32 WM_ENTERIDLE = 0x0121;
        public const UInt32 WM_ENTERMENULOOP = 0x0211;
        public const UInt32 WM_ENTERSIZEMOVE = 0x0231;
        public const UInt32 WM_ERASEBKGND = 0x0014;
        public const UInt32 WM_EXITMENULOOP = 0x0212;
        public const UInt32 WM_EXITSIZEMOVE = 0x0232;
        public const UInt32 WM_FONTCHANGE = 0x001D;
        public const UInt32 WM_GETDLGCODE = 0x0087;
        public const UInt32 WM_GETFONT = 0x0031;
        public const UInt32 WM_GETHOTKEY = 0x0033;
        public const UInt32 WM_GETICON = 0x007F;
        public const UInt32 WM_GETMINMAXINFO = 0x0024;
        public const UInt32 WM_GETOBJECT = 0x003D;
        public const UInt32 WM_GETTEXT = 0x000D;
        public const UInt32 WM_GETTEXTLENGTH = 0x000E;
        public const UInt32 WM_HANDHELDFIRST = 0x0358;
        public const UInt32 WM_HANDHELDLAST = 0x035F;
        public const UInt32 WM_HELP = 0x0053;
        public const UInt32 WM_HOTKEY = 0x0312;
        public const UInt32 WM_HSCROLL = 0x0114;
        public const UInt32 WM_HSCROLLCLIPBOARD = 0x030E;
        public const UInt32 WM_ICONERASEBKGND = 0x0027;
        public const UInt32 WM_IME_CHAR = 0x0286;
        public const UInt32 WM_IME_COMPOSITION = 0x010F;
        public const UInt32 WM_IME_COMPOSITIONFULL = 0x0284;
        public const UInt32 WM_IME_CONTROL = 0x0283;
        public const UInt32 WM_IME_ENDCOMPOSITION = 0x010E;
        public const UInt32 WM_IME_KEYDOWN = 0x0290;
        public const UInt32 WM_IME_KEYLAST = 0x010F;
        public const UInt32 WM_IME_KEYUP = 0x0291;
        public const UInt32 WM_IME_NOTIFY = 0x0282;
        public const UInt32 WM_IME_REQUEST = 0x0288;
        public const UInt32 WM_IME_SELECT = 0x0285;
        public const UInt32 WM_IME_SETCONTEXT = 0x0281;
        public const UInt32 WM_IME_STARTCOMPOSITION = 0x010D;
        public const UInt32 WM_INITDIALOG = 0x0110;
        public const UInt32 WM_INITMENU = 0x0116;
        public const UInt32 WM_INITMENUPOPUP = 0x0117;
        public const UInt32 WM_INPUTLANGCHANGE = 0x0051;
        public const UInt32 WM_INPUTLANGCHANGEREQUEST = 0x0050;
        public const UInt32 WM_KEYDOWN = 0x0100;
        public const UInt32 WM_KEYFIRST = 0x0100;
        public const UInt32 WM_KEYLAST = 0x0108;
        public const UInt32 WM_KEYUP = 0x0101;
        public const UInt32 WM_KILLFOCUS = 0x0008;
        public const UInt32 WM_LBUTTONDBLCLK = 0x0203;
        public const UInt32 WM_LBUTTONDOWN = 0x0201;
        public const UInt32 WM_LBUTTONUP = 0x0202;
        public const UInt32 WM_MBUTTONDBLCLK = 0x0209;
        public const UInt32 WM_MBUTTONDOWN = 0x0207;
        public const UInt32 WM_MBUTTONUP = 0x0208;
        public const UInt32 WM_MDIACTIVATE = 0x0222;
        public const UInt32 WM_MDICASCADE = 0x0227;
        public const UInt32 WM_MDICREATE = 0x0220;
        public const UInt32 WM_MDIDESTROY = 0x0221;
        public const UInt32 WM_MDIGETACTIVE = 0x0229;
        public const UInt32 WM_MDIICONARRANGE = 0x0228;
        public const UInt32 WM_MDIMAXIMIZE = 0x0225;
        public const UInt32 WM_MDINEXT = 0x0224;
        public const UInt32 WM_MDIREFRESHMENU = 0x0234;
        public const UInt32 WM_MDIRESTORE = 0x0223;
        public const UInt32 WM_MDISETMENU = 0x0230;
        public const UInt32 WM_MDITILE = 0x0226;
        public const UInt32 WM_MEASUREITEM = 0x002C;
        public const UInt32 WM_MENUCHAR = 0x0120;
        public const UInt32 WM_MENUCOMMAND = 0x0126;
        public const UInt32 WM_MENUDRAG = 0x0123;
        public const UInt32 WM_MENUGETOBJECT = 0x0124;
        public const UInt32 WM_MENURBUTTONUP = 0x0122;
        public const UInt32 WM_MENUSELECT = 0x011F;
        public const UInt32 WM_MOUSEACTIVATE = 0x0021;
        public const UInt32 WM_MOUSEFIRST = 0x0200;
        public const UInt32 WM_MOUSEHOVER = 0x02A1;
        public const UInt32 WM_MOUSELAST = 0x020D;
        public const UInt32 WM_MOUSELEAVE = 0x02A3;
        public const UInt32 WM_MOUSEMOVE = 0x0200;
        public const UInt32 WM_MOUSEWHEEL = 0x020A;
        public const UInt32 WM_MOUSEHWHEEL = 0x020E;
        public const UInt32 WM_MOVE = 0x0003;
        public const UInt32 WM_MOVING = 0x0216;
        public const UInt32 WM_NCACTIVATE = 0x0086;
        public const UInt32 WM_NCCALCSIZE = 0x0083;
        public const UInt32 WM_NCCREATE = 0x0081;
        public const UInt32 WM_NCDESTROY = 0x0082;
        public const UInt32 WM_NCHITTEST = 0x0084;
        public const UInt32 WM_NCLBUTTONDBLCLK = 0x00A3;
        public const UInt32 WM_NCLBUTTONDOWN = 0x00A1;
        public const UInt32 WM_NCLBUTTONUP = 0x00A2;
        public const UInt32 WM_NCMBUTTONDBLCLK = 0x00A9;
        public const UInt32 WM_NCMBUTTONDOWN = 0x00A7;
        public const UInt32 WM_NCMBUTTONUP = 0x00A8;
        public const UInt32 WM_NCMOUSEHOVER = 0x02A0;
        public const UInt32 WM_NCMOUSELEAVE = 0x02A2;
        public const UInt32 WM_NCMOUSEMOVE = 0x00A0;
        public const UInt32 WM_NCPAINT = 0x0085;
        public const UInt32 WM_NCRBUTTONDBLCLK = 0x00A6;
        public const UInt32 WM_NCRBUTTONDOWN = 0x00A4;
        public const UInt32 WM_NCRBUTTONUP = 0x00A5;
        public const UInt32 WM_NCXBUTTONDBLCLK = 0x00AD;
        public const UInt32 WM_NCXBUTTONDOWN = 0x00AB;
        public const UInt32 WM_NCXBUTTONUP = 0x00AC;
        public const UInt32 WM_NCUAHDRAWCAPTION = 0x00AE;
        public const UInt32 WM_NCUAHDRAWFRAME = 0x00AF;
        public const UInt32 WM_NEXTDLGCTL = 0x0028;
        public const UInt32 WM_NEXTMENU = 0x0213;
        public const UInt32 WM_NOTIFY = 0x004E;
        public const UInt32 WM_NOTIFYFORMAT = 0x0055;
        public const UInt32 WM_NULL = 0x0000;
        public const UInt32 WM_PAINT = 0x000F;
        public const UInt32 WM_PAINTCLIPBOARD = 0x0309;
        public const UInt32 WM_PAINTICON = 0x0026;
        public const UInt32 WM_PALETTECHANGED = 0x0311;
        public const UInt32 WM_PALETTEISCHANGING = 0x0310;
        public const UInt32 WM_PARENTNOTIFY = 0x0210;
        public const UInt32 WM_PASTE = 0x0302;
        public const UInt32 WM_PENWINFIRST = 0x0380;
        public const UInt32 WM_PENWINLAST = 0x038F;
        public const UInt32 WM_POWER = 0x0048;
        public const UInt32 WM_POWERBROADCAST = 0x0218;
        public const UInt32 WM_PRINT = 0x0317;
        public const UInt32 WM_PRINTCLIENT = 0x0318;
        public const UInt32 WM_QUERYDRAGICON = 0x0037;
        public const UInt32 WM_QUERYENDSESSION = 0x0011;
        public const UInt32 WM_QUERYNEWPALETTE = 0x030F;
        public const UInt32 WM_QUERYOPEN = 0x0013;
        public const UInt32 WM_QUEUESYNC = 0x0023;
        public const UInt32 WM_QUIT = 0x0012;
        public const UInt32 WM_RBUTTONDBLCLK = 0x0206;
        public const UInt32 WM_RBUTTONDOWN = 0x0204;
        public const UInt32 WM_RBUTTONUP = 0x0205;
        public const UInt32 WM_RENDERALLFORMATS = 0x0306;
        public const UInt32 WM_RENDERFORMAT = 0x0305;
        public const UInt32 WM_SETCURSOR = 0x0020;
        public const UInt32 WM_SETFOCUS = 0x0007;
        public const UInt32 WM_SETFONT = 0x0030;
        public const UInt32 WM_SETHOTKEY = 0x0032;
        public const UInt32 WM_SETICON = 0x0080;
        public const UInt32 WM_SETREDRAW = 0x000B;
        public const UInt32 WM_SETTEXT = 0x000C;
        public const UInt32 WM_SETTINGCHANGE = 0x001A;
        public const UInt32 WM_SHOWWINDOW = 0x0018;
        public const UInt32 WM_SIZE = 0x0005;
        public const UInt32 WM_SIZECLIPBOARD = 0x030B;
        public const UInt32 WM_SIZING = 0x0214;
        public const UInt32 WM_SPOOLERSTATUS = 0x002A;
        public const UInt32 WM_STYLECHANGED = 0x007D;
        public const UInt32 WM_STYLECHANGING = 0x007C;
        public const UInt32 WM_SYNCPAINT = 0x0088;
        public const UInt32 WM_SYSCHAR = 0x0106;
        public const UInt32 WM_SYSCOLORCHANGE = 0x0015;
        public const UInt32 WM_SYSCOMMAND = 0x0112;
        public const UInt32 WM_SYSDEADCHAR = 0x0107;
        public const UInt32 WM_SYSKEYDOWN = 0x0104;
        public const UInt32 WM_SYSKEYUP = 0x0105;
        public const UInt32 WM_TCARD = 0x0052;
        public const UInt32 WM_TIMECHANGE = 0x001E;
        public const UInt32 WM_TIMER = 0x0113;
        public const UInt32 WM_UNDO = 0x0304;
        public const UInt32 WM_UNINITMENUPOPUP = 0x0125;
        public const UInt32 WM_USER = 0x0400;
        public const UInt32 WM_USERCHANGED = 0x0054;
        public const UInt32 WM_VKEYTOITEM = 0x002E;
        public const UInt32 WM_VSCROLL = 0x0115;
        public const UInt32 WM_VSCROLLCLIPBOARD = 0x030A;
        public const UInt32 WM_WINDOWPOSCHANGED = 0x0047;
        public const UInt32 WM_WINDOWPOSCHANGING = 0x0046;
        public const UInt32 WM_WININICHANGE = 0x001A;
        public const UInt32 WM_XBUTTONDBLCLK = 0x020D;
        public const UInt32 WM_XBUTTONDOWN = 0x020B;
        public const UInt32 WM_XBUTTONUP = 0x020C;

        public const int HWND_BROADCAST = (-1);
        public const int SMTO_ABORTIFHUNG = 0x2;

        public const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;
        public const uint SERVICE_QUERY_CONFIG = 0x00000001;
        public const uint SERVICE_CHANGE_CONFIG = 0x00000002;
        public const uint SC_MANAGER_ALL_ACCESS = 0x000F003F;

        public const int TIME_ZONE_ID_UNKNOWN = 0;
        public const int TIME_ZONE_ID_STANDARD = 1;
        public const int TIME_ZONE_ID_DAYLIGHT = 2;

        // ******************************
        // Definitations.
        // ******************************

        // Instantiate SIDs. (Reference: https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers#:~:text=The%20SECURITY_NT_AUTHORITY%20%28S-1-5%29%20predefined%20identifier%20authority%20produces%20SIDs,topic.%20The%20following%20table%20lists%20the%20well-known%20SIDs.000)

        public static SID_IDENTIFIER_AUTHORITY SECURITY_NULL_SID_AUTHORITY = new NativeMethods.SID_IDENTIFIER_AUTHORITY()
        {
            Value = new byte[] { 0, 0, 0, 0, 0, 0 }
        };

        public static SID_IDENTIFIER_AUTHORITY SECURITY_WORLD_SID_AUTHORITY = new NativeMethods.SID_IDENTIFIER_AUTHORITY()
        {
            Value = new byte[] { 0, 0, 0, 0, 0, 1 }
        };

        public static SID_IDENTIFIER_AUTHORITY SECURITY_LOCAL_SID_AUTHORITY = new NativeMethods.SID_IDENTIFIER_AUTHORITY()
        {
            Value = new byte[] { 0, 0, 0, 0, 0, 2 }
        };

        public static SID_IDENTIFIER_AUTHORITY SECURITY_CREATOR_SID_AUTHORITY = new NativeMethods.SID_IDENTIFIER_AUTHORITY()
        {
            Value = new byte[] { 0, 0, 0, 0, 0, 3 }
        };

        public static SID_IDENTIFIER_AUTHORITY SECURITY_NT_AUTHORITY = new NativeMethods.SID_IDENTIFIER_AUTHORITY()
        {
            Value = new byte[] { 0, 0, 0, 0, 0, 5 }
        };
    }
}