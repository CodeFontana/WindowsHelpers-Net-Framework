using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.Drawing.Imaging;
using System.Security.AccessControl;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.DirectoryServices.AccountManagement;
using SimpleLogger;

namespace WindowsNative
{
    public static class WindowsHelper
    {
        public static bool AddHostFileEntry(string logComponent, string entry)
        {
            try
            {
                var hostsWriter = new StreamWriter(Environment.GetEnvironmentVariable("windir") + "\\system32\\drivers\\etc\\hosts", true);
                hostsWriter.AutoFlush = true;
                hostsWriter.WriteLine(entry);
                hostsWriter.Dispose();
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to add hosts file entry.");
                return false;
            }

            return true;
        }

        public static List<Tuple<string, Bitmap>> CaptureScreen(string logComponent)
        {
            try
            {
                var bitmapList = new List<Tuple<string, Bitmap>>();

                foreach (Screen s in Screen.AllScreens)
                {
                    string captureFileShortName = s.DeviceName.Substring(s.DeviceName.LastIndexOf("\\") + 1) + "--" + GetTimeStamp();
                    SimpleLog.Log(logComponent, "Capture screen: " + s.DeviceName +
                        " [" + s.Bounds.Width + "x" + s.Bounds.Height + "] [" + captureFileShortName + "].");

                    var bmpScreenshot = new Bitmap(s.Bounds.Width, s.Bounds.Height, PixelFormat.Format32bppArgb);
                    Graphics gfxScreenshot = Graphics.FromImage(bmpScreenshot);
                    gfxScreenshot.CopyFromScreen(s.Bounds.X, s.Bounds.Y, 0, 0, s.Bounds.Size, CopyPixelOperation.SourceCopy);
                    bitmapList.Add(new Tuple<string, Bitmap>(captureFileShortName, bmpScreenshot));
                }

                return bitmapList;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to capture screen.");
            }

            return null;
        }

        public static bool CaptureScreen(string logComponent, string outputFolder)
        {
            try
            {
                foreach (Screen s in Screen.AllScreens)
                {
                    string captureFileShortName = s.DeviceName.Substring(s.DeviceName.LastIndexOf("\\") + 1) + "--" + GetTimeStamp();
                    SimpleLog.Log(logComponent, "Capture screen: " + s.DeviceName +
                        " [" + s.Bounds.Width + "x" + s.Bounds.Height + "] [" + captureFileShortName + "].");

                    Bitmap bmpScreenshot = new Bitmap(s.Bounds.Width, s.Bounds.Height, PixelFormat.Format32bppArgb);
                    Graphics gfxScreenshot = Graphics.FromImage(bmpScreenshot);
                    gfxScreenshot.CopyFromScreen(s.Bounds.X, s.Bounds.Y, 0, 0, s.Bounds.Size, CopyPixelOperation.SourceCopy);
                    SimpleLog.Log(logComponent, "Save: " + outputFolder + "\\" + captureFileShortName + ".png");
                    bmpScreenshot.Save(outputFolder + "\\" + captureFileShortName + ".png", ImageFormat.Png);
                }

                return true;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to capture screen.");
            }

            return false;
        }

        public static void CreateShortcut(
            string shortcutFileName,
            string targetFileName,
            string targetArguments = "",
            string shortcutDescription = "",
            int iconNumber = 2)
        {
            // Icon index numbers can be referenced at this link:
            //   https://help4windows.com/windows_7_shell32_dll.shtml

            // Define 'Windows Script Host Shell Object' as a type
            Type windowsScriptHostShell = Type.GetTypeFromCLSID(new Guid("72C24DD5-D70A-438B-8A42-98424B88AFB8"));

            // Create a shell instance
            dynamic wshShellInstance = Activator.CreateInstance(windowsScriptHostShell);

            try
            {
                if (!shortcutFileName.EndsWith(".lnk"))
                {
                    shortcutFileName += ".lnk";
                }

                var lnk = wshShellInstance.CreateShortcut(shortcutFileName);

                try
                {
                    lnk.TargetPath = targetFileName;
                    lnk.Arguments = targetArguments;
                    lnk.WorkingDirectory = FileSystemHelper.ParsePath(targetFileName);
                    lnk.IconLocation = "shell32.dll, " + iconNumber.ToString();
                    lnk.Description = shortcutDescription;
                    lnk.Save();
                }
                finally
                {
                    Marshal.FinalReleaseComObject(lnk);
                }
            }
            finally
            {
                Marshal.FinalReleaseComObject(wshShellInstance);
            }
        }

        public static bool ConfigureAutomaticLogon(string logComponent, string logonUser, string logonPwd)
        {
            try
            {
                SimpleLog.Log(logComponent, "Configure automatic logon user: " + logonUser);

                RegistryKey winLogonKey = RegistryHelper.OpenKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", true, RegistryHive.LocalMachine);
                winLogonKey.SetValue("AutoAdminLogon", "1", RegistryValueKind.String);
                winLogonKey.SetValue("DefaultUserName", logonUser, RegistryValueKind.String);
                winLogonKey.SetValue("DefaultPassword", logonPwd, RegistryValueKind.String);
                winLogonKey.SetValue("DisableCAD", "1", RegistryValueKind.DWord);
                winLogonKey.DeleteValue("AutoLogonCount", false);
                winLogonKey.DeleteValue("DefaultDomainName", false);
                winLogonKey.Dispose();

                RegistryKey policiesKey = RegistryHelper.OpenKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", true, RegistryHive.LocalMachine);
                policiesKey.SetValue("EnableFirstLogonAnimation", "0", RegistryValueKind.DWord);
                policiesKey.Dispose();

                return true;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to configure automatic logon.");
                return false;
            }
        }

        public static DateTime ConvertBinaryDateTime(Byte[] bytes)
        {
            long filedate = (((((((
            (long)bytes[7] * 256 +
            (long)bytes[6]) * 256 +
            (long)bytes[5]) * 256 +
            (long)bytes[4]) * 256 +
            (long)bytes[3]) * 256 +
            (long)bytes[2]) * 256 +
            (long)bytes[1]) * 256 +
            (long)bytes[0]);
            DateTime returnDate = DateTime.FromFileTime(filedate);
            return returnDate;
        }

        public static bool DeleteEnvironmentVariable(string variableName)
        {
            if (Environment.GetEnvironmentVariable(variableName, EnvironmentVariableTarget.Machine) != null)
            {
                Environment.SetEnvironmentVariable(variableName, null, EnvironmentVariableTarget.Machine);
                return true;
            }

            return false;
        }

        public static void DetachConsole()
        {
            IntPtr cw = NativeMethods.GetConsoleWindow();
            NativeMethods.FreeConsole();
            NativeMethods.SendMessage(cw, 0x0102, 13, IntPtr.Zero);
        }

        public static IntPtr DuplicateToken(string logComponent, IntPtr hUserToken, uint sessionId = 65536)
        {
            IntPtr hTokenToDup = hUserToken; // this may be replaced by a linked/elevated token if UAC is turned ON/enabled.
            IntPtr hDuplicateToken = IntPtr.Zero;
            int cbSize = 0;

            try
            {
                NativeMethods.SECURITY_ATTRIBUTES sa = new NativeMethods.SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(sa);

                if (hUserToken == null || hUserToken == IntPtr.Zero)
                {
                    SimpleLog.Log(logComponent, "No token was provided.", SimpleLog.MsgType.ERROR);
                    return IntPtr.Zero;
                }

                if (Environment.OSVersion.Version.Major >= 6)
                {
                    // Is the provided token NOT elevated?
                    if (!IsTokenElevated(logComponent, hUserToken))
                    {
                        cbSize = IntPtr.Size;
                        IntPtr pLinkedToken = Marshal.AllocHGlobal(cbSize);

                        if (pLinkedToken == IntPtr.Zero)
                        {
                            SimpleLog.Log(logComponent, "Failed to allocate memory for linked token check.", SimpleLog.MsgType.ERROR);
                            return IntPtr.Zero;
                        }

                        // Are we NOT able to query the linked token? [Note: If the user is an admin, the linked token will be the elevation token!!!!!]
                        if (!NativeMethods.GetTokenInformation(hUserToken,
                            NativeMethods.TOKEN_INFORMATION_CLASS.TokenLinkedToken,
                            pLinkedToken,
                            cbSize,
                            out cbSize))
                        {
                            SimpleLog.Log(logComponent, "Failed to query LINKED token [GetTokenInformation=" + 
                                Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                            Marshal.FreeHGlobal(pLinkedToken);
                            return IntPtr.Zero;
                        }

                        if (pLinkedToken != null && pLinkedToken != IntPtr.Zero)
                        {
                            SimpleLog.Log(logComponent, "Token has a LINKED token.");

                            // Is the linked token an elevated token?
                            if (IsTokenElevated(logComponent, Marshal.ReadIntPtr(pLinkedToken)))
                            {
                                SimpleLog.Log(logComponent, "LINKED token is ELEVATED, assign for duplication...");
                                hTokenToDup = Marshal.ReadIntPtr(pLinkedToken);
                            }
                            else
                            {
                                SimpleLog.Log(logComponent, "LINKED token is not elevated.");
                            }

                            Marshal.FreeHGlobal(pLinkedToken);
                        }
                        else
                        {
                            SimpleLog.Log(logComponent, "Token does NOT have a LINKED token.");
                        }
                    }
                }

                if (!NativeMethods.DuplicateTokenEx(hTokenToDup,
                                                 NativeMethods.TOKEN_MAXIMUM_ALLOWED,
                                                 ref sa,
                                                 NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                                                 NativeMethods.TOKEN_TYPE.TokenPrimary,
                                                 ref hDuplicateToken))
                {
                    SimpleLog.Log(logComponent, "Failed to duplicate token [DuplicateTokenEx=" + 
                        Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                    Marshal.FreeHGlobal(hTokenToDup);
                    return IntPtr.Zero;
                }

                Marshal.FreeHGlobal(hTokenToDup);

                cbSize = IntPtr.Size;
                IntPtr pSessionId = Marshal.AllocHGlobal(cbSize);

                if (!NativeMethods.GetTokenInformation(hDuplicateToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenSessionId, pSessionId, cbSize, out cbSize))
                {
                    SimpleLog.Log(logComponent, "Failed to token's session id [GetTokenInformation=" + 
                        Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                    Marshal.FreeHGlobal(pSessionId);
                    return IntPtr.Zero;
                }
                else
                {
                    SimpleLog.Log(logComponent, "Duplicated token is configured for session id [" + 
                        Marshal.ReadInt32(pSessionId).ToString() + "].");
                }

                if (sessionId >= 0 && sessionId <= 65535 && sessionId != Marshal.ReadInt32(pSessionId))
                {
                    SimpleLog.Log(logComponent, "Adjust token session: " + sessionId.ToString());

                    if (!NativeMethods.SetTokenInformation(hDuplicateToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenSessionId, ref sessionId, (uint)Marshal.SizeOf(sessionId)))
                    {
                        SimpleLog.Log(logComponent, "Failed to assign token session [SetTokenInformation=" + 
                            Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                        return hDuplicateToken;
                    }
                }

                Marshal.FreeHGlobal(pSessionId);
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed duplicating or elevating user token.");
            }

            return hDuplicateToken;
        }

        public static List<Tuple<uint, string>> GetUserSessions(string logComponent)
        {
            var userSessions = new List<Tuple<uint, string>>();

            try
            {
                IntPtr hServer = NativeMethods.WTSOpenServer(Environment.MachineName);
                IntPtr hSessionInfo = IntPtr.Zero;

                if (!NativeMethods.WTSEnumerateSessions(hServer, 0, 1, ref hSessionInfo, out UInt32 sessionCount))
                {
                    SimpleLog.Log(logComponent, "Failed to enumerate user sessions [WTSEnumerateSessions=" + 
                        Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                }
                else
                {
                    Int32 sessionSize = Marshal.SizeOf(typeof(NativeMethods.WTS_SESSION_INFO));
                    IntPtr hCurSession = hSessionInfo;

                    for (int i = 1; i < sessionCount; i++)
                    {
                        NativeMethods.WTS_SESSION_INFO si = (NativeMethods.WTS_SESSION_INFO)Marshal.PtrToStructure(hCurSession, typeof(NativeMethods.WTS_SESSION_INFO));

                        if (!NativeMethods.WTSQueryUserToken(si.SessionID, out IntPtr hUserToken))
                        {
                            SimpleLog.Log(logComponent, "Failed to query terminal user token [WTSQueryUserToken=" + 
                                Marshal.GetLastWin32Error().ToString() + "] in session [" + si.SessionID.ToString() + "].", SimpleLog.MsgType.ERROR);
                        }
                        else
                        {
                            WindowsIdentity userId = new WindowsIdentity(hUserToken);
                            SimpleLog.Log(logComponent, "Found session: " + si.SessionID.ToString() + "/" + userId.Name);
                            userSessions.Add(new Tuple<uint, string>(si.SessionID, userId.Name));
                            userId.Dispose();
                        }

                        hCurSession += sessionSize;
                    }

                    NativeMethods.WTSFreeMemory(hSessionInfo);
                }

                NativeMethods.WTSCloseServer(hServer);
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to query terminal user sessions.");
            }

            return userSessions;
        }

        public static bool EnablePrivilege(string logComponent,IntPtr hToken, string privilege)
        {
            SimpleLog.Log(logComponent, "Enable: " + privilege);

            NativeMethods.LUID luid = new NativeMethods.LUID();
            NativeMethods.TOKEN_PRIVILEGES newState;
            newState.PrivilegeCount = 1;
            newState.Privileges = new NativeMethods.LUID_AND_ATTRIBUTES[1];

            if (!NativeMethods.LookupPrivilegeValue(null, privilege, ref luid))
            {
                SimpleLog.Log(logComponent, "Unable to lookup privilege (LookupPrivilegeValue=" + 
                    Marshal.GetLastWin32Error().ToString() + ").", SimpleLog.MsgType.ERROR);
                return false;
            }

            newState.Privileges[0].Luid = luid;
            newState.Privileges[0].Attributes = NativeMethods.SE_PRIVILEGE_ENABLED;

            if (!NativeMethods.AdjustTokenPrivileges(hToken, false, ref newState, (UInt32)Marshal.SizeOf(newState), out NativeMethods.TOKEN_PRIVILEGES oldState, out UInt32 outBytes))
            {
                SimpleLog.Log(logComponent, "Unable to adjust token privileges (AdjustTokenPrivileges=" + 
                    Marshal.GetLastWin32Error().ToString() + ").", SimpleLog.MsgType.ERROR);
                return false;
            }

            return true;
        }

        public static IntPtr GetAdminUserToken(string logComponent)
        {
            try
            {
                uint consoleSessionId = NativeMethods.WTSGetActiveConsoleSessionId();

                if (consoleSessionId != 0xFFFFFFFF)
                {
                    SimpleLog.Log(logComponent, "Found console session: " + consoleSessionId.ToString());

                    if (!NativeMethods.WTSQueryUserToken(consoleSessionId, out IntPtr hUserToken))
                    {
                        SimpleLog.Log(logComponent, "Failed to query console user token [WTSQueryUserToken=" + Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                    }
                    else
                    {
                        WindowsIdentity userId = new WindowsIdentity(hUserToken);
                        SimpleLog.Log(logComponent, "Console user: " + userId.Name);
                        userId.Dispose();

                        if (!IsUserInAdminGroup(logComponent, hUserToken))
                        {
                            SimpleLog.Log(logComponent, "Console user is not an administrator.", SimpleLog.MsgType.WARN);
                        }
                        else
                        {
                            SimpleLog.Log(logComponent, "Console user is an administrator.");
                            return hUserToken;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to query console user session.");
            }

            try
            {
                IntPtr hServer = NativeMethods.WTSOpenServer(Environment.MachineName);
                IntPtr hSessionInfo = IntPtr.Zero;

                if (!NativeMethods.WTSEnumerateSessions(hServer, 0, 1, ref hSessionInfo, out UInt32 sessionCount))
                {
                    SimpleLog.Log(logComponent, "Failed to enumerate user sessions [WTSEnumerateSessions=" + 
                        Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                }
                else
                {
                    Int32 sessionSize = Marshal.SizeOf(typeof(NativeMethods.WTS_SESSION_INFO));
                    IntPtr hCurSession = hSessionInfo;

                    for (int i = 0; i < sessionCount; i++)
                    {
                        NativeMethods.WTS_SESSION_INFO si = (NativeMethods.WTS_SESSION_INFO)Marshal.PtrToStructure(hCurSession, typeof(NativeMethods.WTS_SESSION_INFO));
                        SimpleLog.Log(logComponent, "Found session: " + si.SessionID.ToString());

                        if (!NativeMethods.WTSQueryUserToken(si.SessionID, out IntPtr hUserToken))
                        {
                            SimpleLog.Log(logComponent, "Failed to query terminal user token [WTSQueryUserToken=" + 
                                Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                        }
                        else
                        {
                            WindowsIdentity userId = new WindowsIdentity(hUserToken);
                            SimpleLog.Log(logComponent, "Terminal user: " + userId.Name);
                            userId.Dispose();

                            if (!IsUserInAdminGroup(logComponent, hUserToken))
                            {
                                SimpleLog.Log(logComponent, "Terminal user is not an administrator.", SimpleLog.MsgType.WARN);
                            }
                            else
                            {
                                SimpleLog.Log(logComponent, "Terminal user is an administrator");
                                return hUserToken;
                            }
                        }

                        hCurSession += sessionSize;
                    }

                    NativeMethods.WTSFreeMemory(hSessionInfo);
                }

                NativeMethods.WTSCloseServer(hServer);
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to query terminal user sessions.");
            }

            return IntPtr.Zero;
        }

        public static IntPtr GetConsoleUserToken(string logComponent)
        {
            try
            {
                uint consoleSessionId = NativeMethods.WTSGetActiveConsoleSessionId();

                if (consoleSessionId != 0xFFFFFFFF)
                {
                    SimpleLog.Log(logComponent, "Found console session: " + consoleSessionId.ToString());

                    if (!NativeMethods.WTSQueryUserToken(consoleSessionId, out IntPtr hUserToken))
                    {
                        SimpleLog.Log(logComponent, "Failed to query console user token [WTSQueryUserToken=" + 
                            Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                    }
                    else
                    {
                        WindowsIdentity userId = new WindowsIdentity(hUserToken);
                        SimpleLog.Log(logComponent, "Console user: " + userId.Name);
                        userId.Dispose();
                        return hUserToken;
                    }
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to query console user session.");
            }

            return IntPtr.Zero;
        }

        public static string GetTimeStamp()
        {
            return DateTime.Now.ToString("yyyy-MM-dd--HH.mm.ss");
        }

        public static string GetUninstallReg(string logComponent, string displayName)
        {
            if (Environment.Is64BitOperatingSystem)
            {
                RegistryKey localMachine64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                RegistryKey uninstallKey64 = localMachine64.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", false);

                foreach (string subKeyName in uninstallKey64.GetSubKeyNames())
                {
                    try
                    {
                        RegistryKey productKey = uninstallKey64.OpenSubKey(subKeyName, false);
                        var displayNameValue = productKey.GetValue("DisplayName");

                        if (displayNameValue != null)
                        {
                            if (displayNameValue.ToString().ToLower().Equals(displayName.ToLower()))
                            {
                                uninstallKey64.Dispose();
                                localMachine64.Dispose();
                                return "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + subKeyName;
                            }
                        }

                        productKey.Dispose();
                    }
                    catch (Exception e)
                    {
                        SimpleLog.Log(logComponent, e, "Failed to open product key [" + subKeyName + "].");
                        continue;
                    }
                }

                uninstallKey64.Dispose();
                localMachine64.Dispose();
            }

            RegistryKey localMachine32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            RegistryKey uninstallKey32 = localMachine32.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", false);

            foreach (string subKeyName in uninstallKey32.GetSubKeyNames())
            {
                try
                {
                    RegistryKey productKey = uninstallKey32.OpenSubKey(subKeyName, false);
                    var displayNameValue = productKey.GetValue("DisplayName");

                    if (displayNameValue != null)
                    {
                        if (displayNameValue.ToString().ToLower().Equals(displayName.ToLower()))
                        {
                            uninstallKey32.Dispose();
                            localMachine32.Dispose();
                            return "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" + subKeyName;
                        }
                    }

                    productKey.Dispose();
                }
                catch (Exception e)
                {
                    SimpleLog.Log(logComponent, e, "Failed to open product key [" + subKeyName + "].");
                    continue;
                }
            }

            uninstallKey32.Dispose();
            localMachine32.Dispose();
            return null;
        }

        public static string GetUninstallString(string logComponent, string displayName)
        {
            bool foundApp = false;
            string returnString = null;

            if (Environment.Is64BitOperatingSystem)
            {
                RegistryKey localMachine64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                RegistryKey uninstallKey64 = localMachine64.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", false);

                foreach (string subKeyName in uninstallKey64.GetSubKeyNames())
                {
                    try
                    {
                        RegistryKey productKey = uninstallKey64.OpenSubKey(subKeyName, false);
                        var displayNameValue = productKey.GetValue("DisplayName");

                        if (displayNameValue != null)
                        {
                            if (displayNameValue.ToString().ToLower().Equals(displayName.ToLower()))
                            {
                                foundApp = true;
                                var uninstStringValue = productKey.GetValue("UninstallString");

                                if (uninstStringValue != null)
                                {
                                    returnString = uninstStringValue.ToString();
                                }

                                break;
                            }
                        }

                        productKey.Dispose();
                    }
                    catch (Exception e)
                    {
                        SimpleLog.Log(logComponent, e, "Failed to open product key [" + subKeyName + "].");
                        continue;
                    }
                }

                uninstallKey64.Dispose();
                localMachine64.Dispose();

                if (foundApp)
                {
                    return returnString;
                }
            }

            RegistryKey localMachine32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            RegistryKey uninstallKey32 = localMachine32.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", false);

            foreach (string subKeyName in uninstallKey32.GetSubKeyNames())
            {
                try
                {
                    RegistryKey productKey = uninstallKey32.OpenSubKey(subKeyName, false);
                    var displayNameValue = productKey.GetValue("DisplayName");

                    if (displayNameValue != null)
                    {
                        if (displayNameValue.ToString().ToLower().Equals(displayName.ToLower()))
                        {
                            foundApp = true;
                            var uninstStringValue = productKey.GetValue("UninstallString");

                            if (uninstStringValue != null)
                            {
                                returnString = uninstStringValue.ToString();
                            }

                            break;
                        }
                    }

                    productKey.Dispose();
                }
                catch (Exception e)
                {
                    SimpleLog.Log(logComponent, e, "Failed to open product key [" + subKeyName + "].");
                    continue;
                }
            }

            uninstallKey32.Dispose();
            localMachine32.Dispose();

            if (foundApp)
            {
                return returnString;
            }
            else
            {
                return returnString;
            }
        }

        private static void GrantAccess(string username, IntPtr handle, int accessMask)
        {
            SafeHandle safeHandle = new NativeMethods.NoopSafeHandle(handle);
            NativeMethods.GenericSecurity security = new NativeMethods.GenericSecurity(false, ResourceType.WindowObject, safeHandle, AccessControlSections.Access);
            security.AddAccessRule(new NativeMethods.GenericAccessRule(new NTAccount(username), accessMask, AccessControlType.Allow));
            security.Persist(safeHandle, AccessControlSections.Access);
        }

        public static void GrantAccessToWindowStationAndDesktop(string username)
        {
            IntPtr handle;
            const int WindowStationAllAccess = 0x000f037f;
            handle = NativeMethods.GetProcessWindowStation();
            GrantAccess(username, handle, WindowStationAllAccess);
            const int DesktopRightsAllAccess = 0x000f01ff;
            handle = NativeMethods.GetThreadDesktop(NativeMethods.GetCurrentThreadId());
            GrantAccess(username, handle, DesktopRightsAllAccess);
        }

        public static bool ImportCertificate(string logComponent,
            string certFilename,
            string certPassword = "",
            StoreName certStore = StoreName.My,
            StoreLocation certLocation = StoreLocation.CurrentUser)
        {
            try
            {
                if (!File.Exists(certFilename))
                {
                    SimpleLog.Log(logComponent, "Specified certifcate file does not exist [" + certFilename + "].", SimpleLog.MsgType.ERROR);
                    return false;
                }

                X509Certificate2 importCert = null;

                if (certPassword != "")
                {
                    importCert = new X509Certificate2(certFilename, certPassword);
                }
                else
                {
                    importCert = new X509Certificate2(certFilename);
                }

                var store = new X509Store(certStore, certLocation);
                store.Open(OpenFlags.ReadWrite);

                if (!store.Certificates.Contains(importCert))
                {
                    SimpleLog.Log(logComponent, "Import certificate...");
                    store.Add(importCert);
                    SimpleLog.Log(logComponent, "Certifcate imported successfully.");
                }
                else
                {
                    SimpleLog.Log(logComponent, "Certificate already imported.");
                }

                store.Dispose();
                return true;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to import certificate.");
                return false;
            }
        }

        public static bool IncreaseProcessPrivileges(string logComponent, Process targetProcess)
        {
            IntPtr hProcess = targetProcess.Handle;

            if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_ALL_ACCESS, out IntPtr hToken))
            {
                SimpleLog.Log(logComponent, "Unable to open specified process token [OpenProcessToken=" + 
                    Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                return false;
            }

            return IncreaseTokenPrivileges(logComponent, hToken);
        }

        public static bool IncreaseTokenPrivileges(string logComponent, IntPtr hToken)
        {
            if (!EnablePrivilege(logComponent, hToken, NativeMethods.SE_INCREASE_QUOTA_NAME))
            {
                SimpleLog.Log(logComponent, "Failed to enable privilege [SeIncreaseQuotaPrivilege].", SimpleLog.MsgType.ERROR);
                Marshal.FreeHGlobal(hToken);
                return false;
            }

            if (!EnablePrivilege(logComponent, hToken, NativeMethods.SE_ASSIGNPRIMARYTOKEN_NAME))
            {
                SimpleLog.Log(logComponent, "Failed to enable privilege [SeAssignPrimaryTokenPrivilege].", SimpleLog.MsgType.ERROR);
                Marshal.FreeHGlobal(hToken);
                return false;
            }

            if (!EnablePrivilege(logComponent, hToken, NativeMethods.SE_TCB_NAME))
            {
                SimpleLog.Log(logComponent, "Failed to enable privilege [SeTcbPrivilege].", SimpleLog.MsgType.ERROR);
                Marshal.FreeHGlobal(hToken);
                return false;
            }

            if (!EnablePrivilege(logComponent, hToken, NativeMethods.SE_DEBUG_NAME))
            {
                SimpleLog.Log(logComponent, "Failed to enable privilege [SeDebugPrivilege].", SimpleLog.MsgType.ERROR);
                Marshal.FreeHGlobal(hToken);
                return false;
            }

            if (!EnablePrivilege(logComponent, hToken, NativeMethods.SE_IMPERSONATE_NAME))
            {
                SimpleLog.Log(logComponent, "Failed to enable privilege [SeImpersonatePrivilege].", SimpleLog.MsgType.ERROR);
                Marshal.FreeHGlobal(hToken);
                return false;
            }

            if (!EnablePrivilege(logComponent, hToken, NativeMethods.SE_TIME_ZONE_NAME))
            {
                SimpleLog.Log(logComponent, "Failed to enable privilege [SeTimeZonePrivilege].", SimpleLog.MsgType.ERROR);
                Marshal.FreeHGlobal(hToken);
                return false;
            }

            if (!EnablePrivilege(logComponent, hToken, NativeMethods.SE_SYSTEMTIME_NAME))
            {
                SimpleLog.Log(logComponent, "Failed to enable privilege [SeSystemtimePrivilege].", SimpleLog.MsgType.ERROR);
                Marshal.FreeHGlobal(hToken);
                return false;
            }

            if (!EnablePrivilege(logComponent, hToken, NativeMethods.SE_SHUTDOWN_NAME))
            {
                SimpleLog.Log(logComponent, "Failed to enable privilege [SeShutdownPrivilege].", SimpleLog.MsgType.ERROR);
                Marshal.FreeHGlobal(hToken);
                return false;
            }

            if (!EnablePrivilege(logComponent, hToken, NativeMethods.SE_TAKE_OWNERSHIP_NAME))
            {
                SimpleLog.Log(logComponent, "Failed to enable privilege [SeTakeOwnershipPrivilege].", SimpleLog.MsgType.ERROR);
                Marshal.FreeHGlobal(hToken);
                return false;
            }

            Marshal.FreeHGlobal(hToken);
            return true;
        }

        public static bool IsAppInstalled(string logComponent, string displayName)
        {
            bool foundApp = false;

            if (Environment.Is64BitOperatingSystem)
            {
                RegistryKey localMachine64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                RegistryKey uninstallKey64 = localMachine64.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", false);

                foreach (string subKeyName in uninstallKey64.GetSubKeyNames())
                {
                    try
                    {
                        RegistryKey productKey = uninstallKey64.OpenSubKey(subKeyName, false);
                        var displayNameValue = productKey.GetValue("DisplayName");

                        if (displayNameValue != null)
                        {
                            if (displayNameValue.ToString().ToLower().Equals(displayName.ToLower()))
                            {
                                foundApp = true;
                                break;
                            }
                        }

                        productKey.Dispose();
                    }
                    catch (Exception e)
                    {
                        SimpleLog.Log(logComponent, e, "Failed to open product key [" + subKeyName + "].");
                        continue;
                    }
                }

                uninstallKey64.Dispose();
                localMachine64.Dispose();

                if (foundApp)
                {
                    return true;
                }
            }

            RegistryKey localMachine32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
            RegistryKey uninstallKey32 = localMachine32.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", false);

            foreach (string subKeyName in uninstallKey32.GetSubKeyNames())
            {
                try
                {
                    RegistryKey productKey = uninstallKey32.OpenSubKey(subKeyName, false);
                    var displayNameValue = productKey.GetValue("DisplayName");

                    if (displayNameValue != null)
                    {
                        if (displayNameValue.ToString().ToLower().Equals(displayName.ToLower()))
                        {
                            foundApp = true;
                            break;
                        }
                    }

                    productKey.Dispose();
                }
                catch (Exception e)
                {
                    SimpleLog.Log(logComponent, e, "Failed to open product key [" + subKeyName + "].");
                    continue;
                }
            }

            uninstallKey32.Dispose();
            localMachine32.Dispose();

            if (foundApp)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        public static bool IsAutoLogonConfigred(string logComponent, out string logonUser, out string logonPwd)
        {
            int autoAdminLogon = -1;
            logonUser = null;
            logonPwd = null;

            try
            {
                SimpleLog.Log(logComponent, "Read logon configuration...");
                RegistryKey winLogonKey = RegistryHelper.OpenKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", true, RegistryHive.LocalMachine);
                var curAutoAdminLogon = winLogonKey.GetValue("AutoAdminLogon");
                var curAutoLogonCount = winLogonKey.GetValue("AutoLogonCount");
                var curDefaultUserName = winLogonKey.GetValue("DefaultUserName");
                var curDefaultPassword = winLogonKey.GetValue("DefaultPassword");
                var curDisableCAD = winLogonKey.GetValue("DisableCAD");

                if (curAutoAdminLogon != null)
                {
                    if (!int.TryParse(curAutoAdminLogon.ToString(), out autoAdminLogon))
                    {
                        autoAdminLogon = -1;
                    }

                    SimpleLog.Log(logComponent, "  AutoAdminLogon: " + autoAdminLogon.ToString());
                }
                else
                {
                    SimpleLog.Log(logComponent, "  AutoAdminLogon: <Not Available>");
                }

                if (curAutoLogonCount != null)
                {
                    if (!int.TryParse(curAutoLogonCount.ToString(), out int autoLogonCount))
                    {
                        autoLogonCount = -1;
                    }

                    SimpleLog.Log(logComponent, "  AutoLogonCount: " + autoLogonCount.ToString());
                }
                else
                {
                    SimpleLog.Log(logComponent, "  AutoLogonCount: <Not Available>");
                }

                if (curDefaultUserName != null)
                {
                    logonUser = curDefaultUserName.ToString();
                    SimpleLog.Log(logComponent, "  DefaultUserName: " + logonUser);
                }
                else
                {
                    SimpleLog.Log(logComponent, "  DefaultUserName: <Not Available>");
                }

                if (curDefaultPassword != null)
                {
                    logonPwd = curDefaultPassword.ToString();
                    SimpleLog.Log(logComponent, "  DefaultPassword: <Not Displayed>");
                }
                else
                {
                    SimpleLog.Log(logComponent, "  DefaultPassword: <Not Available>");
                }

                if (curDisableCAD != null)
                {
                    if (!int.TryParse(curDisableCAD.ToString(), out int disableCAD))
                    {
                        disableCAD = -1;
                    }

                    SimpleLog.Log(logComponent, "  DisableCAD: " + disableCAD.ToString());
                }
                else
                {
                    SimpleLog.Log(logComponent, "  DisableCAD: <Not Available>");
                }

                if (autoAdminLogon == 1 && !logonUser.Equals(""))
                {
                    SimpleLog.Log(logComponent, "Automatic logon: CONFIGURED");
                    return true;
                }
                else
                {
                    SimpleLog.Log(logComponent, "Automatic logon: NOT CONFIGURED");
                    return false;
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to inspect automatic logon configuration.");
                return false;
            }
        }

        public static bool IsDomainUser(string logComponent, string userName, string domainName)
        {
            bool userExists = false;

            try
            {
                using (var domainContext = new PrincipalContext(ContextType.Domain, domainName))
                {
                    using (var foundUser = UserPrincipal.FindByIdentity(domainContext, IdentityType.SamAccountName, userName))
                    {
                        if (foundUser != null)
                        {
                            userExists = true;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to validate domain user credentials.");
            }

            return userExists;
        }

        public static bool IsLocalUser(string logComponent, string userName)
        {
            bool userExists = false;

            try
            {
                using (var localContext = new PrincipalContext(ContextType.Machine))
                {
                    using (var foundUser = UserPrincipal.FindByIdentity(localContext, IdentityType.SamAccountName, userName))
                    {
                        if (foundUser != null)
                        {
                            userExists = true;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to validate local user credentials.");
            }

            return userExists;
        }

        public static bool IsTokenElevated(string logComponent, IntPtr hToken)
        {
            if (Environment.OSVersion.Version.Major >= 6)
            {
                int cbSize = sizeof(NativeMethods.TOKEN_ELEVATION_TYPE);
                IntPtr pElevationType = Marshal.AllocHGlobal(cbSize);

                if (pElevationType == IntPtr.Zero)
                {
                    SimpleLog.Log(logComponent, "Failed to allocate memory for token elevation check.", SimpleLog.MsgType.ERROR);
                    Marshal.FreeHGlobal(hToken);
                    return false;
                }

                if (!NativeMethods.GetTokenInformation(hToken,
                    NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevationType,
                    pElevationType,
                    cbSize,
                    out cbSize))
                {
                    SimpleLog.Log(logComponent, "Failed to query user-token elevation type [GetTokenInformation=" + 
                        Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);

                    Marshal.FreeHGlobal(hToken);
                    Marshal.FreeHGlobal(pElevationType);
                    return false;
                }

                NativeMethods.TOKEN_ELEVATION_TYPE elevType = (NativeMethods.TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(pElevationType);

                if (elevType == NativeMethods.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited)
                {
                    /* Type 3 is a limited token with administrative privileges removed
                     * and administrative groups disabled. The limited token is used when
                     * User Account Control is enabled, the application does not require
                     * administrative privilege, and the user does not choose to start
                     * the program using Run as administrator.*/

                    SimpleLog.Log(logComponent, "Token elevation type: Limited.");
                    Marshal.FreeHGlobal(hToken);
                    Marshal.FreeHGlobal(pElevationType);
                    return false;
                }
                else if (elevType == NativeMethods.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault)
                {
                    /* Type 1 is a full token with no privileges removed or groups disabled.
                     * A full token is only used if User Account Control is disabled or if
                     * the user is the built -in Administrator account (for which UAC 
                     * disabled by default), service account or local system account.*/

                    SimpleLog.Log(logComponent, "Token elevation type: Default.");
                    Marshal.FreeHGlobal(hToken);
                    Marshal.FreeHGlobal(pElevationType);
                    return true;
                }
                else if (elevType == NativeMethods.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull)
                {
                    /* Type 2 is an elevated token with no privileges removed or groups
                     * disabled. An elevated token is used when User Account Control is
                     * enabled and the user chooses to start the program using Run as
                     * administrator. An elevated token is also used when an application
                     * is configured to always require administrative privilege or to
                     * always require maximum privilege, and the user is a member of the
                     * Administrators group.*/

                    SimpleLog.Log(logComponent, "Token elevation type: Full.");
                    Marshal.FreeHGlobal(hToken);
                    Marshal.FreeHGlobal(pElevationType);
                    return true;
                }
                else
                {
                    SimpleLog.Log(logComponent, "Token elevation type: Unknown.");
                    Marshal.FreeHGlobal(hToken);
                    Marshal.FreeHGlobal(pElevationType);
                    return false;
                }
            }
            else
            {
                Marshal.FreeHGlobal(hToken);
                return true;
            }
        }

        public static bool IsUACEnabled(string logComponent)
        {
            bool isUserAccountControlEnabled = false;

            try
            {
                if (Environment.Is64BitOperatingSystem)
                {
                    RegistryKey localMachine64 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                    RegistryKey systemPolicies = localMachine64.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");

                    if (systemPolicies != null)
                    {
                        int enableLua = int.Parse(systemPolicies.GetValue("EnableLUA").ToString());

                        if (enableLua == 1)
                        {
                            SimpleLog.Log(logComponent, "User account control (UAC): Enabled");
                            isUserAccountControlEnabled = true;
                        }
                        else
                        {
                            SimpleLog.Log(logComponent, "User account control (UAC): Disabled");
                            isUserAccountControlEnabled = false;
                        }
                    }

                    localMachine64.Dispose();
                }
                else
                {
                    RegistryKey localMachine32 = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32);
                    RegistryKey systemPolicies = localMachine32.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");

                    if (systemPolicies != null)
                    {
                        int enableLua = int.Parse(systemPolicies.GetValue("EnableLUA").ToString());

                        if (enableLua == 1)
                        {
                            SimpleLog.Log(logComponent, "User account control (UAC): Enabled");
                            isUserAccountControlEnabled = true;
                        }
                        else
                        {
                            SimpleLog.Log(logComponent, "User account control (UAC): Disabled");
                            isUserAccountControlEnabled = false;
                        }
                    }

                    localMachine32.Dispose();
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to determine if UAC is enabled.");
                return isUserAccountControlEnabled;
            }

            return isUserAccountControlEnabled;
        }

        public static bool IsUserInAdminGroup(string logComponent, IntPtr hToken)
        {
            // Is UAC enabled?
            /*
             * Note: In Windows Vista and newer, one cannot simply check if the user account is in
             *       the administrators group. It depends on whether or not the user possesses an
             *       elevated token. To do this, we must query the user's access token, and check
             *       for a linked token that indicates they have elevation privileges or not.
             *       Otherwise, you may get a false negative, e.g. the user is an admin, but
             *       UserPrincipal.IsInRole() returns false. Ohh the simpler times. We miss them.
             *       I feel like .NET needs a native library for this. I dislike having to user
             *       unmanaged code.
             */
            if (IsUACEnabled(logComponent))
            {
                bool fInAdminGroup = false;
                IntPtr hTokenToCheck = IntPtr.Zero;
                IntPtr pElevationType = IntPtr.Zero;
                IntPtr pLinkedToken = IntPtr.Zero;
                int cbSize = 0;

                try
                {
                    if (Environment.OSVersion.Version.Major >= 6)
                    {
                        cbSize = sizeof(NativeMethods.TOKEN_ELEVATION_TYPE);
                        pElevationType = Marshal.AllocHGlobal(cbSize);

                        if (pElevationType == IntPtr.Zero)
                        {
                            SimpleLog.Log(logComponent, "Failed to allocate memory for token elevation check.", SimpleLog.MsgType.ERROR);
                            return false;
                        }

                        if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevationType, pElevationType, cbSize, out cbSize))
                        {
                            SimpleLog.Log(logComponent, "Failed to query token elevation type [GetTokenInformation=" + Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                            return false;
                        }

                        NativeMethods.TOKEN_ELEVATION_TYPE elevType = (NativeMethods.TOKEN_ELEVATION_TYPE)Marshal.ReadInt32(pElevationType);

                        if (elevType == NativeMethods.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited)
                        {
                            SimpleLog.Log(logComponent, "Token elevation type: Limited.");
                            cbSize = IntPtr.Size;
                            pLinkedToken = Marshal.AllocHGlobal(cbSize);

                            if (pLinkedToken == IntPtr.Zero)
                            {
                                SimpleLog.Log(logComponent, "Failed to allocate memory for linked token check.", SimpleLog.MsgType.ERROR);
                                return false;
                            }

                            if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenLinkedToken, pLinkedToken, cbSize, out cbSize))
                            {
                                SimpleLog.Log(logComponent, "Failed to query LINKED token [GetTokenInformation=" + Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                                return false;
                            }
                            else
                            {
                                SimpleLog.Log(logComponent, "Token has a Linked token.", SimpleLog.MsgType.DEBUG);
                            }

                            hTokenToCheck = Marshal.ReadIntPtr(pLinkedToken);
                        }
                        else if (elevType == NativeMethods.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault)
                        {
                            SimpleLog.Log(logComponent, "Token elevation type: Default.", SimpleLog.MsgType.DEBUG);
                        }
                        else if (elevType == NativeMethods.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull)
                        {
                            SimpleLog.Log(logComponent, "Token elevation type: Full.", SimpleLog.MsgType.DEBUG);
                        }
                        else
                        {
                            SimpleLog.Log(logComponent, "Token elevation type: Unknown.", SimpleLog.MsgType.DEBUG);
                        }
                    }

                    if (hTokenToCheck == null || hTokenToCheck == IntPtr.Zero)
                    {
                        if (!NativeMethods.DuplicateToken(hToken, NativeMethods.SECURITY_IMPERSONATION_LEVEL.SecurityIdentification, out hTokenToCheck))
                        {
                            SimpleLog.Log(logComponent, "Failed to duplicate ORIGNAL access token [DuplicateToken=" + 
                                Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                            return false;
                        }
                    }

                    WindowsIdentity id = new WindowsIdentity(hTokenToCheck);
                    WindowsPrincipal principal = new WindowsPrincipal(id);
                    fInAdminGroup = principal.IsInRole(WindowsBuiltInRole.Administrator);
                    id.Dispose();
                }
                catch (Exception e)
                {
                    SimpleLog.Log(logComponent, e, "Failed to verify if user token is in admin group.");
                    return false;
                }

                finally
                {
                    if (hToken != null)
                    {
                        hToken = IntPtr.Zero;
                    }

                    if (hTokenToCheck != null)
                    {
                        hTokenToCheck = IntPtr.Zero;
                    }

                    if (pElevationType != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(pElevationType);
                        pElevationType = IntPtr.Zero;
                    }

                    if (pLinkedToken != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(pLinkedToken);
                        pLinkedToken = IntPtr.Zero;
                    }
                }

                return fInAdminGroup;
            }
            else
            {
                WindowsIdentity userId = new WindowsIdentity(hToken);
                WindowsPrincipal userPrincipal = new WindowsPrincipal(userId);

                if (userPrincipal.IsInRole("Administrators") || userPrincipal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    userId.Dispose();
                    return true;
                }
                else
                {
                    userId.Dispose();
                    return false;
                }
            }
        }

        public static bool IsUserInAdminGroup(string logComponent, WindowsIdentity userToCheck)
        {
            if (new WindowsPrincipal(userToCheck).IsInRole(WindowsBuiltInRole.Administrator))
            {
                return true;
            }

            try
            {
                uint entriesRead = 0, totalEntries = 0;

                unsafe
                {
                    int LOCALGROUP_INFO_1_SIZE = sizeof(NativeMethods.LOCALGROUP_INFO_1);
                    int LOCALGROUP_MEMBERS_INFO_1_SIZE = sizeof(NativeMethods.LOCALGROUP_MEMBERS_INFO_1);
                    IntPtr groupInfoPtr, userInfoPtr;
                    groupInfoPtr = IntPtr.Zero;
                    userInfoPtr = IntPtr.Zero;

                    NativeMethods.NetLocalGroupEnum(IntPtr.Zero, 1, ref groupInfoPtr, 0xFFFFFFFF, ref entriesRead, ref totalEntries, IntPtr.Zero);

                    for (int i = 0; i < totalEntries; i++)
                    {
                        int newOffset = 0;
                        long newOffset64 = 0;
                        NativeMethods.LOCALGROUP_INFO_1 groupInfo;

                        if (Environment.Is64BitOperatingSystem)
                        {
                            newOffset64 = groupInfoPtr.ToInt64() + LOCALGROUP_INFO_1_SIZE * i;
                            groupInfo = (NativeMethods.LOCALGROUP_INFO_1)Marshal.PtrToStructure(new IntPtr(newOffset64), typeof(NativeMethods.LOCALGROUP_INFO_1));
                        }
                        else
                        {
                            newOffset = groupInfoPtr.ToInt32() + LOCALGROUP_INFO_1_SIZE * i;
                            groupInfo = (NativeMethods.LOCALGROUP_INFO_1)Marshal.PtrToStructure(new IntPtr(newOffset), typeof(NativeMethods.LOCALGROUP_INFO_1));
                        }

                        string currentGroupName = Marshal.PtrToStringAuto(groupInfo.lpszGroupName);

                        SimpleLog.Log(logComponent, "Group: " + currentGroupName, SimpleLog.MsgType.DEBUG);

                        if (currentGroupName.ToLower().Equals("administrators"))
                        {
                            uint entriesRead1 = 0, totalEntries1 = 0;
                            NativeMethods.NetLocalGroupGetMembers(IntPtr.Zero, groupInfo.lpszGroupName, 1, ref userInfoPtr, 0xFFFFFFFF, ref entriesRead1, ref totalEntries1, IntPtr.Zero);

                            for (int j = 0; j < totalEntries1; j++)
                            {
                                NativeMethods.LOCALGROUP_MEMBERS_INFO_1 memberInfo;
                                int newOffset1 = 0;
                                long newOffset1_64 = 0;

                                if (Environment.Is64BitOperatingSystem)
                                {
                                    newOffset1_64 = userInfoPtr.ToInt64() + LOCALGROUP_MEMBERS_INFO_1_SIZE * j;
                                    memberInfo = (NativeMethods.LOCALGROUP_MEMBERS_INFO_1)Marshal.PtrToStructure(new IntPtr(newOffset1_64), typeof(NativeMethods.LOCALGROUP_MEMBERS_INFO_1));
                                }
                                else
                                {
                                    newOffset1 = userInfoPtr.ToInt32() + LOCALGROUP_MEMBERS_INFO_1_SIZE * j;
                                    memberInfo = (NativeMethods.LOCALGROUP_MEMBERS_INFO_1)Marshal.PtrToStructure(new IntPtr(newOffset1), typeof(NativeMethods.LOCALGROUP_MEMBERS_INFO_1));
                                }

                                string currentUserName = Marshal.PtrToStringAuto(memberInfo.lgrmi1_name);

                                SimpleLog.Log(logComponent, "  Member: " + currentUserName, SimpleLog.MsgType.DEBUG);

                                if (currentUserName.ToLower().Equals(userToCheck.Name.ToLower()) ||
                                    (userToCheck.Name.Contains("\\") && currentUserName.ToLower().Equals(
                                        userToCheck.Name.ToLower().Substring(userToCheck.Name.IndexOf("\\") + 1))))
                                {
                                    NativeMethods.NetApiBufferFree(userInfoPtr);
                                    NativeMethods.NetApiBufferFree(groupInfoPtr);
                                    return true;
                                }
                            }

                            NativeMethods.NetApiBufferFree(userInfoPtr);
                            break;
                        }
                    }

                    NativeMethods.NetApiBufferFree(groupInfoPtr);
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to determine admin group membership [NativeMethods.method].");
            }

            return false;
        }

        public static bool IsUserInAdminGroup(string logComponent, string userName)
        {
            try
            {
                uint entriesRead = 0, totalEntries = 0;

                unsafe
                {
                    int LOCALGROUP_INFO_1_SIZE = sizeof(NativeMethods.LOCALGROUP_INFO_1);
                    int LOCALGROUP_MEMBERS_INFO_1_SIZE = sizeof(NativeMethods.LOCALGROUP_MEMBERS_INFO_1);
                    IntPtr groupInfoPtr, userInfoPtr;
                    groupInfoPtr = IntPtr.Zero;
                    userInfoPtr = IntPtr.Zero;

                    NativeMethods.NetLocalGroupEnum(IntPtr.Zero, 1, ref groupInfoPtr, 0xFFFFFFFF, ref entriesRead, ref totalEntries, IntPtr.Zero);

                    for (int i = 0; i < totalEntries; i++)
                    {
                        int newOffset = 0;
                        long newOffset64 = 0;
                        NativeMethods.LOCALGROUP_INFO_1 groupInfo;

                        if (Environment.Is64BitOperatingSystem)
                        {
                            newOffset64 = groupInfoPtr.ToInt64() + LOCALGROUP_INFO_1_SIZE * i;
                            groupInfo = (NativeMethods.LOCALGROUP_INFO_1)Marshal.PtrToStructure(new IntPtr(newOffset64), typeof(NativeMethods.LOCALGROUP_INFO_1));
                        }
                        else
                        {
                            newOffset = groupInfoPtr.ToInt32() + LOCALGROUP_INFO_1_SIZE * i;
                            groupInfo = (NativeMethods.LOCALGROUP_INFO_1)Marshal.PtrToStructure(new IntPtr(newOffset), typeof(NativeMethods.LOCALGROUP_INFO_1));
                        }

                        string currentGroupName = Marshal.PtrToStringAuto(groupInfo.lpszGroupName);

                        SimpleLog.Log(logComponent, "Group: " + currentGroupName, SimpleLog.MsgType.DEBUG);

                        if (currentGroupName.ToLower().Equals("administrators"))
                        {
                            uint entriesRead1 = 0, totalEntries1 = 0;
                            NativeMethods.NetLocalGroupGetMembers(IntPtr.Zero, groupInfo.lpszGroupName, 1, ref userInfoPtr, 0xFFFFFFFF, ref entriesRead1, ref totalEntries1, IntPtr.Zero);

                            for (int j = 0; j < totalEntries1; j++)
                            {
                                NativeMethods.LOCALGROUP_MEMBERS_INFO_1 memberInfo;
                                int newOffset1 = 0;
                                long newOffset1_64 = 0;

                                if (Environment.Is64BitOperatingSystem)
                                {
                                    newOffset1_64 = userInfoPtr.ToInt64() + LOCALGROUP_MEMBERS_INFO_1_SIZE * j;
                                    memberInfo = (NativeMethods.LOCALGROUP_MEMBERS_INFO_1)Marshal.PtrToStructure(new IntPtr(newOffset1_64), typeof(NativeMethods.LOCALGROUP_MEMBERS_INFO_1));
                                }
                                else
                                {
                                    newOffset1 = userInfoPtr.ToInt32() + LOCALGROUP_MEMBERS_INFO_1_SIZE * j;
                                    memberInfo = (NativeMethods.LOCALGROUP_MEMBERS_INFO_1)Marshal.PtrToStructure(new IntPtr(newOffset1), typeof(NativeMethods.LOCALGROUP_MEMBERS_INFO_1));
                                }

                                string currentUserName = Marshal.PtrToStringAuto(memberInfo.lgrmi1_name);

                                SimpleLog.Log(logComponent, "  Member: " + currentUserName, SimpleLog.MsgType.DEBUG);

                                if (currentUserName.ToLower().Equals(userName.ToLower()) ||
                                    (userName.Contains("\\") && currentUserName.ToLower().Equals(
                                        userName.ToLower().Substring(userName.IndexOf("\\") + 1))))
                                {
                                    NativeMethods.NetApiBufferFree(userInfoPtr);
                                    NativeMethods.NetApiBufferFree(groupInfoPtr);
                                    return true;
                                }
                            }

                            NativeMethods.NetApiBufferFree(userInfoPtr);
                            break;
                        }
                    }

                    NativeMethods.NetApiBufferFree(groupInfoPtr);
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to determine admin group membership [NativeMethods.method].");
            }

            return false;
        }

        public static bool RebootSystem(
            string logComponent,
            uint delaySeconds = 10,
            string comment = null,
            NativeMethods.ShutdownReason shutdownReason =
                NativeMethods.ShutdownReason.MajorOther |
                NativeMethods.ShutdownReason.MinorOther)
        {
            IntPtr hProcess = Process.GetCurrentProcess().Handle;

            if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_ALL_ACCESS, out IntPtr hToken))
            {
                SimpleLog.Log(logComponent, "Unable to open specified process token [OpenProcessToken=" + Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                Marshal.FreeHGlobal(hProcess);
                return false;
            }

            if (!EnablePrivilege(logComponent, hToken, NativeMethods.SE_SHUTDOWN_NAME))
            {
                SimpleLog.Log(logComponent, "Failed to enable privilege [SeShutdownPrivilege].", SimpleLog.MsgType.WARN);
                Marshal.FreeHGlobal(hProcess);
                Marshal.FreeHGlobal(hToken);
                return false;
            }

            Marshal.FreeHGlobal(hProcess);
            Marshal.FreeHGlobal(hToken);

            if (comment == null || comment == "")
            {
                string processName = Process.GetCurrentProcess().MainModule.FileName;
                string shortName = processName.Substring(processName.LastIndexOf("\\") + 1);
                string friendlyName = shortName.Substring(0, shortName.LastIndexOf("."));
                comment = friendlyName + " initiated a reboot of the system.";
            }

            SimpleLog.Log(logComponent, $"Windows reboot [{comment}]");

            if (!NativeMethods.InitiateSystemShutdownEx(null, comment, delaySeconds, true, true, shutdownReason))
            {
                int lastError = Marshal.GetLastWin32Error();

                /* Is this an unexpected error code? 
                     1115/0x45B --> A system shutdown is in progress.     
                     1190/0x4A6 --> A system shutdown has already been scheduled.
                */
                if (lastError != 1115 && lastError != 1190)
                {
                    SimpleLog.Log(logComponent, "Failed to initiate reboot [InitiateSystemShutdownEx=" + 
                        Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                    return false;
                }
                else if (lastError == 1115)
                {
                    SimpleLog.Log(logComponent, "REBOOT: A system shutdown is in progress.");
                }
                else if (lastError == 1190)
                {
                    SimpleLog.Log(logComponent, "REBOOT: A system shutdown has already been scheduled.");
                }
            }
            else
            {
                SimpleLog.Log(logComponent, $"REBOOT: System will restart in ({delaySeconds}) seconds.");
            }

            return true;
        }

        public static string[] SynthesizeCommandLineArgs(string logComponent)
        {
            StringBuilder argCrawler = new StringBuilder(Environment.CommandLine);
            char nextChar = '\0';
            char currentChar = '\0';
            char previousChar = '\0';
            int quoteLevel = 0;
            bool inQuote = false;

            for (int i = 0; i < argCrawler.Length; i++)
            {
                // Ternary character scope
                previousChar = currentChar;
                currentChar = argCrawler[i];

                // Are we near end of string?
                if (i < argCrawler.Length - 1)
                {
                    // Scope next character
                    nextChar = argCrawler[i + 1];
                }
                else
                {
                    // Stub null char
                    nextChar = '\0';
                }

                // Is this a START QUOTE?
                if ((previousChar == '\0' && currentChar == '\"' && nextChar != '\0') || (previousChar == ' ' && currentChar == '\"' && nextChar != '\0'))
                {
                    inQuote = true;
                    quoteLevel += 1;
                }

                // Is this an END QUOTE?
                if (inQuote && ((currentChar == '\"' && nextChar == ' ') || (currentChar == '\"' && nextChar == '\0')))
                {
                    quoteLevel -= 1;

                    if (quoteLevel == 0)
                    {
                        inQuote = false;
                    }
                }

                // Is this a space character, outside of quoted text?
                if (argCrawler[i].Equals(' ') && !inQuote)
                {
                    argCrawler[i] = '\n';
                }
            }

            string[] synthArgs = argCrawler.ToString().Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);

            if (synthArgs.Length > 1)
            {
                for (int i = 1; i < synthArgs.Length; i++)
                {
                    // If quoted, unquote the argument 
                    // Note: Quotes were needed to distinctly identify the argument from other arguments, but otherwise serve no purpose.
                    // Note: Carful not to trim quotes-- we only want to trim a single/outer mathcing pair.

                    if (synthArgs[i].StartsWith("\"") && synthArgs[i].EndsWith("\""))
                    {
                        synthArgs[i] = synthArgs[i].Substring(1, synthArgs[i].Length - 2);
                    }

                    SimpleLog.Log(logComponent, "Argument [" + i.ToString() + "]: " + synthArgs[i]);
                }
            }
            else
            {
                SimpleLog.Log(logComponent, "Arguments: <None>");
            }

            return synthArgs;
        }
    }
}