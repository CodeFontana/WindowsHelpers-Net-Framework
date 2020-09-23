using LocalPolicy;
using Microsoft.Win32.SafeHandles;
using SimpleLogger;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace WindowsNative
{
    public static class FileSystemHelper
    {
        public static bool AddDirectorySecurity(string logComponent,
            string fileOrFolder,
            string userAccount,
            FileSystemRights requestedRights,
            AccessControlType controlType,
            InheritanceFlags inheritFlag = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags propFlag = PropagationFlags.None,
            bool forcePermissions = false)
        {
            try
            {
                // Is the "Remove Security Tab" Windows GPO configured?
                // Note: If so, the current user will be unable to edit file/folder
                //       security permissions. Lame.
                if (RegistryHelper.ValueExists(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                    "NoSecurityTab",
                    Microsoft.Win32.RegistryHive.CurrentUser))
                {
                    try
                    {
                        var gpo = new ComputerGroupPolicyObject();
                        string policyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";

                        using (var userRootGPO = gpo.GetRootRegistryKey(GroupPolicySection.User))
                        {
                            using (var securityTabKey = userRootGPO.OpenSubKey(policyPath, true))
                            {
                                securityTabKey.DeleteValue("NoSecurityTab");
                            }
                        }

                        gpo.Save();
                        SimpleLog.Log(logComponent, "Refresh Windows policy...");

                        ProcessHelper.RunProcess(logComponent,
                            Environment.GetEnvironmentVariable("SystemDrive") + "\\Windows\\System32\\gpupdate.exe",
                            "/force",
                            Environment.GetEnvironmentVariable("SystemDrive") + "\\Windows\\System32",
                            180, true, true, true);
                    }
                    catch (Exception e)
                    {
                        SimpleLog.Log(logComponent, e, "Failed to edit local group policy.");
                    }
                }

                if (File.Exists(fileOrFolder))
                {
                    FileSecurity fSecurity = File.GetAccessControl(fileOrFolder);
                    fSecurity.SetAccessRuleProtection(false, true);
                    fSecurity.AddAccessRule(new FileSystemAccessRule(
                    userAccount, requestedRights, controlType));
                    File.SetAccessControl(fileOrFolder, fSecurity);
                }
                else if (Directory.Exists(fileOrFolder))
                {
                    DirectorySecurity dSecurity = Directory.GetAccessControl(fileOrFolder);
                    dSecurity.SetAccessRuleProtection(false, true);
                    dSecurity.AddAccessRule(new FileSystemAccessRule(
                        userAccount, requestedRights,
                        inheritFlag, propFlag, controlType));
                    Directory.SetAccessControl(fileOrFolder, dSecurity);
                }
                else
                {
                    SimpleLog.Log(logComponent, $"Specified file or folder [{fileOrFolder}] does not exist.", SimpleLog.MsgType.ERROR);
                    return false;
                }

                return true;
            }
            catch (Exception e)
            {
                // Force permissions? (e.g. take ownership and try again)
                if (forcePermissions)
                {
                    if (!NativeMethods.OpenProcessToken(
                        Process.GetCurrentProcess().Handle,
                        NativeMethods.TOKEN_ALL_ACCESS,
                        out IntPtr hToken))
                    {
                        SimpleLog.Log(logComponent, "Unable to open specified process token [OpenProcessToken=" +
                            Marshal.GetLastWin32Error().ToString() + "].");
                        return false;
                    }

                    if (!WindowsHelper.EnablePrivilege(logComponent, hToken, NativeMethods.SE_TAKE_OWNERSHIP_NAME))
                    {
                        SimpleLog.Log(logComponent, "Failed to enable privilege [SeTakeOwnershipPrivilege].", SimpleLog.MsgType.ERROR);
                        Marshal.FreeHGlobal(hToken);
                        return false;
                    }

                    // Administrators group trustee control information.
                    NativeMethods.EXPLICIT_ACCESS adminGroupAccess = new NativeMethods.EXPLICIT_ACCESS();
                    NativeMethods.BuildExplicitAccessWithName(
                        ref adminGroupAccess,
                        "Administrators",
                        NativeMethods.ACCESS_MASK.GENERIC_ALL,
                        NativeMethods.ACCESS_MODE.SET_ACCESS,
                        NativeMethods.NO_INHERITANCE);
                    
                    IntPtr acl = IntPtr.Zero;
                    NativeMethods.SetEntriesInAcl(1, ref adminGroupAccess, IntPtr.Zero, ref acl);

                    // Allocate SID -- BUILTIN\Administrators.
                    NativeMethods.SID_IDENTIFIER_AUTHORITY sidNTAuthority = NativeMethods.SECURITY_NT_AUTHORITY;
                    IntPtr sidAdministrators = IntPtr.Zero;
                    NativeMethods.AllocateAndInitializeSid(ref sidNTAuthority,
                        2,
                        NativeMethods.SECURITY_BUILTIN_DOMAIN_RID,
                        NativeMethods.DOMAIN_ALIAS_RID_ADMINS,
                        0, 0, 0, 0, 0, 0,
                        ref sidAdministrators);

                    // Set the owner in the object's security descriptor.
                    NativeMethods.SetNamedSecurityInfo(
                        fileOrFolder,
                        NativeMethods.SE_OBJECT_TYPE.SE_FILE_OBJECT,
                        NativeMethods.SECURITY_INFORMATION.OWNER_SECURITY_INFORMATION,
                        sidAdministrators,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        IntPtr.Zero);

                    /*// Modify the object's DACL.
                    NativeMethods.SetNamedSecurityInfo(
                        fileOrFolder,
                        NativeMethods.SE_OBJECT_TYPE.SE_FILE_OBJECT,
                        NativeMethods.SECURITY_INFORMATION.DACL_SECURITY_INFORMATION,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        acl,
                        IntPtr.Zero);*/

                    NativeMethods.FreeSid(sidAdministrators);
                    NativeMethods.LocalFree(acl);

                    return AddDirectorySecurity(logComponent, fileOrFolder, userAccount, requestedRights, controlType, inheritFlag, propFlag, false);
                }
                else
                {
                    SimpleLog.Log(logComponent, e, "Failed to add filesystem permissions to [" + fileOrFolder + "].");
                    return false;
                }
            }
        }

        public static string BytesToReadableValue(long numBytes)
        {
            var suffixes = new List<string> { " B ", " KB", " MB", " GB", " TB", " PB" };

            for (int i = 0; i < suffixes.Count; i++)
            {
                // Divide by powers of 1024, as we move through the scales
                long temp = Math.Abs(numBytes / (long)Math.Pow(1024, i + 1));

                // Have we gone off scale?
                if (temp <= 0)
                {
                    // Return prior suffix value
                    return String.Format("{0,9}", String.Format("{0:0.00}", Math.Round((double)numBytes / Math.Pow(1024, i), 2)) + suffixes[i]);
                }
            }

            return numBytes.ToString();
        }

        public static bool CheckDiskStatus(string logComponent)
        {
            DriveInfo[] allDrives = DriveInfo.GetDrives();

            foreach (DriveInfo d in allDrives)
            {
                if (d.DriveType.ToString().ToLower().Equals("fixed"))
                {
                    SimpleLog.Log(logComponent, "Check drive [read-only]: " + d.Name);

                    Tuple<long, string> result = ProcessHelper.RunProcess(logComponent,
                        "chkdsk.exe",
                        d.Name.Substring(0, 2),
                        Environment.GetEnvironmentVariable("windir") + "\\System32",
                        1200, true, false, false);

                    if (result.Item2.ToLower().Contains("windows has scanned the file system and found no problems"))
                    {
                        SimpleLog.Log(logComponent, "CHKDSK result: OK");
                    }
                    else
                    {
                        SimpleLog.Log(logComponent, "CHKDSK result: FAIL");
                        return false;
                    }
                }
            }

            return true;
        }

        public static bool CheckSmartStatus(string logComponent)
        {
            try
            {
                var wmiQuery = new ManagementObjectSearcher(
                    "SELECT Model,SerialNumber,InterfaceType,Partitions,Status,Size FROM Win32_DiskDrive");
                bool smartOK = true;

                foreach (ManagementObject drive in wmiQuery.Get())
                {
                    var model = drive["Model"];
                    var serial = drive["SerialNumber"];
                    var interfacetype = drive["InterfaceType"];
                    var partitions = drive["Partitions"];
                    var smart = drive["Status"];
                    var sizeInBytes = drive["Size"];

                    SimpleLog.Log(logComponent, "Found drive: " + model.ToString());

                    if (serial != null)
                    {
                        SimpleLog.Log(logComponent, "  Serial: " + serial.ToString());
                    }

                    if (interfacetype != null)
                    {
                        SimpleLog.Log(logComponent, "  Interface: " + interfacetype.ToString());
                    }

                    if (partitions != null)
                    {
                        SimpleLog.Log(logComponent, "  Partitions: " + partitions.ToString());
                    }

                    if (sizeInBytes != null)
                    {
                        SimpleLog.Log(logComponent, "  Size: " + FileSystemHelper.BytesToReadableValue(long.Parse(sizeInBytes.ToString().Trim())));
                    }

                    if (smart != null)
                    {
                        SimpleLog.Log(logComponent, "  SMART: " + smart.ToString());

                        if (!smart.ToString().ToLower().Equals("ok"))
                        {
                            smartOK = false;
                        }
                    }
                }

                wmiQuery.Dispose();

                if (!smartOK)
                {
                    SimpleLog.Log(logComponent, "SMART status failure detected.", SimpleLog.MsgType.ERROR);
                    return false;
                }
                else
                {
                    return true;
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to verify drive SMART status.");
                return false;
            }
        }

        public static bool CopyFile(string logComponent,
            string sourceFileName,
            string destFileName,
            bool overWrite = true,
            bool verboseOutput = true,
            bool handleInUseOnReboot = false)
        {
            SimpleLog.Log(logComponent, "Copy file: " + sourceFileName);
            SimpleLog.Log(logComponent, "       To: " + destFileName);

            try
            {
                try
                {
                    if (!File.Exists(sourceFileName))
                    {
                        SimpleLog.Log(logComponent, "Source file does not exist [" + sourceFileName + "].", SimpleLog.MsgType.ERROR);
                        return false;
                    }

                    if (sourceFileName.ToLower().Equals(destFileName.ToLower()))
                    {
                        SimpleLog.Log(logComponent, "Source and destination files must be different [" + sourceFileName + "].", SimpleLog.MsgType.ERROR);
                        return false;
                    }

                    if (!Directory.Exists(ParsePath(destFileName)))
                    {
                        try
                        {
                            Directory.CreateDirectory(ParsePath(destFileName));
                        }
                        catch (Exception e)
                        {
                            SimpleLog.Log(logComponent, e, "Failed to create target directory.");
                            return false;
                        }
                    }

                    File.Copy(sourceFileName, destFileName, overWrite);

                    foreach (string file in Directory.GetFiles(ParsePath(destFileName)))
                    {
                        if (file.ToLower().Contains(".delete_on_reboot"))
                        {
                            DeleteFile(logComponent, file, false, true);
                        }
                    }

                    return true;
                }
                catch (Exception)
                {
                    if (IsFileOpen(destFileName) && overWrite)
                    {
                        try
                        {
                            string incrementFilename = destFileName + ".delete_on_reboot";
                            int fileIncrement = 0;

                            while (true)
                            {
                                if (File.Exists(incrementFilename))
                                {
                                    incrementFilename = destFileName + ".delete_on_reboot_" + (fileIncrement++).ToString();
                                }
                                else
                                {
                                    break;
                                }
                            }

                            // Attempt to rename destination file
                            // --> This may or may not succeed depending on type of
                            //     lock on the destination file.
                            File.Move(destFileName, incrementFilename);

                            // Schedule original file for deletion on next reboot
                            NativeMethods.MoveFileEx(
                                incrementFilename,
                                null,
                                NativeMethods.MoveFileFlags.DelayUntilReboot);

                            SimpleLog.Log(logComponent, "Delete after reboot: " + incrementFilename);
                        }
                        catch (Exception)
                        {
                            string pendingFilename = destFileName + ".pending";
                            int fileIncrement = 0;

                            while (true)
                            {
                                if (File.Exists(pendingFilename))
                                {
                                    pendingFilename = destFileName + ".pending_" + fileIncrement.ToString();
                                }
                                else
                                {
                                    break;
                                }
                            }

                            try
                            {
                                // Copy the file as a pending replacement
                                File.Copy(sourceFileName, pendingFilename, true);

                                // Attempt in-place file replacement (as alternative to copy/replacement)
                                bool moveSuccess = NativeMethods.MoveFileEx(
                                    pendingFilename,
                                    destFileName,
                                    NativeMethods.MoveFileFlags.ReplaceExisting);

                                if (!moveSuccess && handleInUseOnReboot)
                                {
                                    // Schedule deletion of original file
                                    NativeMethods.MoveFileEx(
                                        destFileName,
                                        null,
                                        NativeMethods.MoveFileFlags.DelayUntilReboot);

                                    // Schedule rename of pending file, to replace original destination
                                    NativeMethods.MoveFileEx(
                                        pendingFilename,
                                        destFileName,
                                        NativeMethods.MoveFileFlags.DelayUntilReboot);

                                    SimpleLog.Log(logComponent, "Reboot required: " + destFileName);
                                    return true;
                                }
                                else if (!moveSuccess && !handleInUseOnReboot)
                                {
                                    SimpleLog.Log(logComponent, "Destination file is in-use [" + destFileName + "].", SimpleLog.MsgType.ERROR);
                                    return false;
                                }
                                else
                                {
                                    return true;
                                }
                            }
                            catch (Exception e)
                            {
                                SimpleLog.Log(logComponent, e, "Unable to schedule file replacement for in-use file [" + destFileName + "].");
                                return false;
                            }
                        }
                    }

                    File.Copy(sourceFileName, destFileName, overWrite);
                    return true;
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to copy file [" + ParseShortname(sourceFileName) + "] to destination.");
            }

            return false;
        }

        public static bool CopyFolderContents(string logComponent,
            string sourceFolder,
            string targetFolder,
            string[] reservedItems = null,
            bool verboseOutput = true,
            bool recursiveCopy = true,
            bool handleInUseOnReboot = false)
        {
            if (!Directory.Exists(sourceFolder))
            {
                SimpleLog.Log(logComponent, "Source folder does not exist [" + sourceFolder + "].", SimpleLog.MsgType.ERROR);
                return false;
            }

            if (sourceFolder.ToLower().Equals(targetFolder.ToLower()))
            {
                SimpleLog.Log(logComponent, "Source and destination folders must be different [" + sourceFolder + "].", SimpleLog.MsgType.ERROR);
                return false;
            }

            if (!Directory.Exists(targetFolder))
            {
                try
                {
                    Directory.CreateDirectory(targetFolder);
                }
                catch (Exception e)
                {
                    SimpleLog.Log(logComponent, e, "Failed to create target directory.");
                    return false;
                }
            }

            bool skipItem = false;

            try
            {
                string[] fileList = Directory.GetFiles(sourceFolder);

                foreach (string sourceFile in fileList)
                {
                    if (reservedItems != null)
                    {
                        foreach (string str in reservedItems)
                        {
                            if (sourceFile.ToLower().EndsWith(str.ToLower()))
                            {
                                SimpleLog.Log(logComponent, "Reserved file: " + sourceFile, SimpleLog.MsgType.DEBUG);
                                skipItem = true;
                            }
                        }
                    }

                    if (!skipItem)
                    {
                        string destinationFile = Path.Combine(targetFolder, sourceFile.Substring(sourceFile.LastIndexOf("\\") + 1));
                        CopyFile(logComponent, sourceFile, destinationFile, true, verboseOutput, handleInUseOnReboot);
                    }

                    skipItem = false;
                }

                string[] folderList = null;

                if (recursiveCopy)
                {
                    folderList = Directory.GetDirectories(sourceFolder);

                    foreach (string sourceDir in folderList)
                    {
                        if (reservedItems != null)
                        {
                            foreach (string str in reservedItems)
                            {
                                if (sourceDir.ToLower().EndsWith(str.ToLower()))
                                {
                                    if (verboseOutput)
                                    {
                                        SimpleLog.Log(logComponent, "Reserved folder: " + sourceDir, SimpleLog.MsgType.DEBUG);
                                    }

                                    skipItem = true;
                                }
                            }
                        }

                        // SPECIAL CASE: System Volume Information
                        if (sourceDir.ToLower().Contains("system volume information"))
                        {
                            if (verboseOutput)
                            {
                                SimpleLog.Log(logComponent, "Reserved folder: " + sourceDir, SimpleLog.MsgType.DEBUG);
                            }

                            skipItem = true;
                        }

                        // SPECIAL CASE: System Volume Information
                        if (sourceDir.ToLower().Contains("$recycle"))
                        {
                            if (verboseOutput)
                            {
                                SimpleLog.Log(logComponent, "Reserved folder: " + sourceDir, SimpleLog.MsgType.DEBUG);
                            }

                            skipItem = true;
                        }

                        if (!skipItem)
                        {
                            string destinationPath = Path.Combine(targetFolder, sourceDir.Substring(sourceDir.LastIndexOf("\\") + 1));

                            if (verboseOutput)
                            {
                                SimpleLog.Log(logComponent, "Copy folder: " + sourceDir);
                                SimpleLog.Log(logComponent, "         To: " + destinationPath);
                            }

                            try
                            {
                                CopyFolderContents(logComponent, 
                                    sourceDir, destinationPath, 
                                    reservedItems, verboseOutput, 
                                    recursiveCopy, handleInUseOnReboot);
                            }
                            catch (Exception e)
                            {
                                SimpleLog.Log(logComponent, e, "Failed to copy folder [" + sourceDir + "] to desintation.");
                            }
                        }

                        skipItem = false;
                    }
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to copy directory to destination.");
                return false;
            }

            return true;
        }

        public static bool DeleteFile(string logComponent,
            string fileName,
            bool raiseException = false,
            bool handleInUseOnReboot = false)
        {
            bool fileDeleted = false;

            if (File.Exists(fileName))
            {
                try
                {
                    try
                    {
                        File.SetAttributes(fileName, FileAttributes.Normal);
                        File.Delete(fileName);
                        SimpleLog.Log(logComponent, "Deleted file: " + fileName);
                        fileDeleted = true;
                    }
                    catch (Exception)
                    {
                        // Is the specified file in-use?
                        if (IsFileOpen(fileName) &&
                            handleInUseOnReboot &&
                            !fileName.ToLower().Contains(".delete_on_reboot")) // Avoid double-scheduling
                        {
                            try
                            {
                                string deleteFilename = fileName + ".delete_on_reboot";
                                int fileIncrement = 0;

                                while (true)
                                {
                                    if (File.Exists(deleteFilename))
                                    {
                                        deleteFilename = fileName + ".delete_on_reboot_" + (fileIncrement++).ToString();
                                    }
                                    else
                                    {
                                        break;
                                    }
                                }

                                // Attempt to rename file
                                // --> This may or may not succeed depending on type of
                                //     lock on the file.
                                File.Move(fileName, deleteFilename);

                                // Schedule deletion on next reboot
                                bool scheduleDeleteion = NativeMethods.MoveFileEx(
                                    deleteFilename,
                                    null,
                                    NativeMethods.MoveFileFlags.DelayUntilReboot);

                                SimpleLog.Log(logComponent, "Delete after reboot: " + deleteFilename);
                            }
                            catch (Exception)
                            {
                                // Schedule in-place deletion on next reboot
                                NativeMethods.MoveFileEx(
                                    fileName,
                                    null,
                                    NativeMethods.MoveFileFlags.DelayUntilReboot);

                                SimpleLog.Log(logComponent, "Delete after reboot: " + fileName);
                            }
                        }
                        else if (fileName.ToLower().Contains(".delete_on_reboot"))
                        {
                            fileDeleted = false;
                            SimpleLog.Log(logComponent, "Deleted after reboot: " + fileName, SimpleLog.MsgType.DEBUG);
                        }
                        else
                        {
                            File.Delete(fileName);
                            SimpleLog.Log(logComponent, "Deleted file: " + fileName);
                            fileDeleted = true;
                        }
                    }
                }
                catch (Exception e)
                {
                    fileDeleted = false;
                    SimpleLog.Log(logComponent, e, "Exception caught deleting file.");

                    if (raiseException)
                        throw e;
                }
            }

            return fileDeleted;
        }

        public static bool DeleteFilePattern(string logComponent,
            string folderName, string filePattern, bool raiseException = false)
        {
            bool fileDeleted = false;

            try
            {
                if (!Directory.Exists(folderName))
                {
                    return false;
                }

                string[] fileList = Directory.GetFiles(folderName);

                if (fileList.Length > 0)
                {
                    string strFile;

                    for (int n = 0; n <= fileList.Length - 1; n++)
                    {
                        strFile = fileList[n].ToString().ToLower();
                        strFile = strFile.Substring(strFile.LastIndexOf("\\") + 1);

                        if (strFile.ToLower().StartsWith(filePattern.ToLower()))
                        {
                            DeleteFile(logComponent, fileList[n]);
                            fileDeleted = true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                SimpleLog.Log(logComponent, ex, "Exception caught deleting file.");

                if (raiseException)
                {
                    throw ex;
                }
            }

            return fileDeleted;
        }

        public static bool DeleteFolder(string logComponent,
            string folderName, bool raiseException = false)
        {
            bool folderDeleted = false;

            if (Directory.Exists(folderName))
            {
                try
                {
                    SimpleLog.Log(logComponent, "Delete folder: " + folderName);
                    DeleteFolderContents(logComponent, folderName, null, true);
                    Directory.Delete(folderName, true);
                    folderDeleted = true;
                }
                catch (Exception e)
                {
                    SimpleLog.Log(logComponent, e, "Exception caught deleting folder.");

                    if (raiseException)
                    {
                        throw e;
                    }
                }
            }
            else
            {
                folderDeleted = true;
            }

            return folderDeleted;
        }

        public static void DeleteFolderContents(string logComponent, 
            string targetFolder, 
            string[] reservedItems,
            bool verboseOutput = true, 
            bool recurseReservedItems = true)
        {
            if (!Directory.Exists(targetFolder))
            {
                return;
            }

            string[] fileList = Directory.GetFiles(targetFolder);
            string[] folderList = Directory.GetDirectories(targetFolder);

            try
            {
                // Adjust TargetFolder ACL, add permissions for BUILTIN\Administrators group
                var targetFolderInfo = new DirectoryInfo(targetFolder);
                var targetFolderACL = new DirectorySecurity(targetFolder, AccessControlSections.Access);
                targetFolderACL.AddAccessRule(
                    new FileSystemAccessRule(
                        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                        FileSystemRights.FullControl,
                        InheritanceFlags.ContainerInherit,
                        PropagationFlags.InheritOnly,
                        AccessControlType.Allow));
                targetFolderInfo.SetAccessControl(targetFolderACL);
            }
            catch (Exception ex)
            {
                SimpleLog.Log(logComponent, ex, "Failed to set target folder access control list.");
            }

            bool skipItem = false;

            if (folderList.Length > 0)
            {
                for (int n = 0; n <= folderList.Length - 1; n++)
                {
                    try
                    {
                        if (reservedItems != null)
                        {
                            foreach (string str in reservedItems)
                            {
                                if (folderList[n].ToString().ToLower().EndsWith(str.ToLower()))
                                {
                                    SimpleLog.Log(logComponent, "Reserved folder: " + folderList[n].ToString(), SimpleLog.MsgType.DEBUG);
                                    skipItem = true;
                                }
                            }
                        }

                        if (!skipItem)
                        {
                            var folderInfo = new DirectoryInfo(folderList[n].ToString());

                            if (folderInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                            {
                                try
                                {
                                    SimpleLog.Log(logComponent, "Remove junction: " + folderList[n].ToString());
                                    RemoveJunction(folderList[n].ToString());
                                }
                                catch (Exception ex)
                                {
                                    SimpleLog.Log(logComponent, ex, "Exception caught removing NTFS junction: " + folderList[n].ToString());
                                }
                            }
                            else
                            {
                                if (recurseReservedItems)
                                {
                                    DeleteFolderContents(logComponent, folderList[n].ToString(), reservedItems, false);
                                }
                                else
                                {
                                    DeleteFolderContents(logComponent, folderList[n].ToString(), null, false);
                                }
                            }

                            if (verboseOutput)
                            {
                                SimpleLog.Log(logComponent, "Delete folder: " + folderList[n].ToString());
                            }

                            Directory.Delete(folderList[n]);
                        }

                        skipItem = false;
                    }
                    catch (Exception ex2)
                    {
                        SimpleLog.Log(logComponent, ex2, "Exception caught deleting folder: " + folderList[n].ToString());
                    }
                }
            }

            if (fileList.Length > 0)
            {
                for (int n = 0; n <= fileList.Length - 1; n++)
                {
                    try
                    {
                        if (reservedItems != null)
                        {
                            foreach (string str in reservedItems)
                            {
                                if (fileList[n].ToString().ToLower().EndsWith(str.ToLower()))
                                {
                                    SimpleLog.Log(logComponent, "Reserved file: " + fileList[n].ToString(), SimpleLog.MsgType.DEBUG);
                                    skipItem = true;
                                }
                            }
                        }

                        if (!skipItem)
                        {
                            if (verboseOutput)
                            {
                                SimpleLog.Log(logComponent, "Delete file: " + fileList[n].ToString());
                            }

                            File.SetAttributes(fileList[n], FileAttributes.Normal);
                            File.Delete(fileList[n]);
                        }

                        skipItem = false;
                    }
                    catch (Exception ex2)
                    {
                        SimpleLog.Log(logComponent, ex2, "Exception caught deleting file: " + fileList[n].ToString());
                    }
                }
            }
        }

        public static string GetAceInformation(FileSystemAccessRule ace)
        {
            StringBuilder info = new StringBuilder();
            info.AppendLine(string.Format("Account: {0}", ace.IdentityReference.Value));
            info.AppendLine(string.Format("Type: {0}", ace.AccessControlType));
            info.AppendLine(string.Format("Rights: {0}", ace.FileSystemRights));
            info.AppendLine(string.Format("Inherited ACE: {0}", ace.IsInherited));
            return info.ToString();
        }

        public static bool IsFileOpen(string fileName)
        {
            FileInfo fileInfo = new FileInfo(fileName);
            FileStream fileStream = null;

            try
            {
                fileStream = fileInfo.Open(FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                fileStream.Dispose();
                return false;
            }
            catch (Exception)
            {
                return true;
            }
        }

        public static string ListFolderContents(string logComponent, string folderPath)
        {
            List<string[]> foldersAndFiles = new List<string[]>();

            try
            {
                if (!Directory.Exists(folderPath))
                {
                    return "Specified folder was not found [" + folderPath + "].";
                }

                foldersAndFiles.Add(new string[] { "Folder(s)", "" });
                foldersAndFiles.Add(new string[] { "---------", "" });

                foreach (string folder in Directory.GetDirectories(folderPath.Trim('\"')))
                {
                    try
                    {
                        foldersAndFiles.Add(new string[] { folder.Substring(folder.LastIndexOf("\\") + 1), BytesToReadableValue(SizeOfFileOrFolder(folder)) });
                    }
                    catch (Exception)
                    {
                        foldersAndFiles.Add(new string[] { folder.Substring(folder.LastIndexOf("\\") + 1), "<Size unavailable>" });
                    }
                }

                foldersAndFiles.Add(new string[] { "", "" });
                foldersAndFiles.Add(new string[] { "File(s)", "" });
                foldersAndFiles.Add(new string[] { "-------", "" });

                foreach (string file in Directory.GetFiles(folderPath))
                {
                    try
                    {
                        foldersAndFiles.Add(new string[] { ParseShortname(file), BytesToReadableValue(SizeOfFileOrFolder(file)) });
                    }
                    catch (Exception)
                    {
                        foldersAndFiles.Add(new string[] { ParseShortname(file), "<Size unavailable>" });
                    }
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to iterate file(s) or folder(s) for [" + folderPath + "].");
            }

            string paddedTable = "";

            try
            {
                paddedTable = DotNetHelper.PadListElements(foldersAndFiles, 5);
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to construct padded elements list.");
                string returnString = "";

                foreach (string[] s in foldersAndFiles)
                {
                    string unPaddedLine = string.Join(" ", s);
                    returnString += unPaddedLine + Environment.NewLine;
                }

                return returnString;
            }

            return paddedTable;
        }

        public static bool MoveFile(string logComponent,
            string sourceFileName,
            string destFileName,
            bool overWrite = true)
        {
            SimpleLog.Log(logComponent, "Move file: " + sourceFileName);
            SimpleLog.Log(logComponent, "       To: " + destFileName);

            try
            {
                if (overWrite)
                {
                    DeleteFile(logComponent, destFileName);
                }

                File.Move(sourceFileName, destFileName);
                return true;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to move file [" + ParseShortname(sourceFileName) + "] to destination.");
            }

            return false;
        }

        private static SafeFileHandle OpenReparsePoint(string reparsePoint, NativeMethods.EFileAccess accessMode)
        {
            // Open handle to reparse point
            SafeFileHandle reparsePointHandle = new SafeFileHandle(
                NativeMethods.CreateFile(reparsePoint,
                    accessMode,
                    NativeMethods.EFileShare.Read | NativeMethods.EFileShare.Write | NativeMethods.EFileShare.Delete,
                    IntPtr.Zero,
                    NativeMethods.ECreationDisposition.OpenExisting,
                    NativeMethods.EFileAttributes.BackupSemantics | NativeMethods.EFileAttributes.OpenReparsePoint,
                    IntPtr.Zero),
                true);

            // Reparse point opened OK?
            if (Marshal.GetLastWin32Error() != 0)
            {
                throw new Win32Exception("Unable to open reparse point.");
            }

            return reparsePointHandle;
        }

        public static string ParseFriendlyname(string filename)
        {
            string friendlyName = ParseShortname(filename);

            if (friendlyName.Contains("."))
            {
                return friendlyName.Substring(0, friendlyName.LastIndexOf("."));
            }
            else
            {
                return friendlyName;
            }
        }

        public static string ParsePath(string filename)
        {
            if (filename.Contains("\\"))
            {
                return filename.Substring(0, filename.LastIndexOf("\\"));
            }
            else
            {
                return filename;
            }
        }

        public static string ParseShortname(string filename)
        {
            if (filename.Contains("\\"))
            {
                return filename.Substring(filename.LastIndexOf("\\") + 1);
            }
            else
            {
                return filename;
            }
        }

        public static bool RemoveDirectorySecurity(string logComponent,
            string folderName,
            string userAccount,
            FileSystemRights revokedRights,
            AccessControlType controlType)
        {
            try
            {
                DirectoryInfo dInfo = new DirectoryInfo(folderName);
                DirectorySecurity dSecurity = dInfo.GetAccessControl();
                dSecurity.RemoveAccessRule(new FileSystemAccessRule(userAccount, revokedRights, controlType));
                dInfo.SetAccessControl(dSecurity);
                return true;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to revoke folder permissions from [" + folderName + "].");
                return false;
            }
        }

        public static void RemoveJunction(string junctionPoint)
        {
            if (!Directory.Exists(junctionPoint) && !File.Exists(junctionPoint))
            {
                return;
            }

            // Open the junction point
            SafeFileHandle fileHandle = OpenReparsePoint(junctionPoint, NativeMethods.EFileAccess.GenericWrite);

            // Setup reparse structure
            NativeMethods.REPARSE_DATA_BUFFER reparseDataBuffer = new NativeMethods.REPARSE_DATA_BUFFER
            {
                reparseTag = NativeMethods.IO_REPARSE_TAG_MOUNT_POINT,
                reparseDataLength = 0,
                pathBuffer = new byte[0x3FF0]
            };

            // Calculate buffer size and allocate
            int inBufferSize = Marshal.SizeOf(reparseDataBuffer);
            IntPtr inBuffer = Marshal.AllocHGlobal(inBufferSize);

            try
            {
                // Create the pointer
                Marshal.StructureToPtr(reparseDataBuffer, inBuffer, false);

                // Delete the reparse point
                bool result = NativeMethods.DeviceIoControl(
                    fileHandle.DangerousGetHandle(), 
                    NativeMethods.FSCTL_DELETE_REPARSE_POINT, 
                    inBuffer, 8, IntPtr.Zero, 0, out int BytesReturned, IntPtr.Zero);

                if (!result)
                {
                    throw new Win32Exception("ERROR: Unable to delete reparse point.");
                }
            }
            finally
            {
                fileHandle.Dispose();
                Marshal.FreeHGlobal(inBuffer);
            }
        }

        public static void ReplaceFileIn(string logComponent,
            string baseFolder,
            string replaceFile,
            string[] additionalFiles = null)
        {
            try
            {
                if (!File.Exists(replaceFile))
                {
                    return;
                }

                foreach (string subFolder in Directory.GetDirectories(baseFolder))
                {
                    ReplaceFileIn(logComponent, subFolder, replaceFile, additionalFiles);
                }

                foreach (string someFile in Directory.GetFiles(baseFolder))
                {
                    if (ParseShortname(someFile).ToLower().Equals(ParseShortname(replaceFile).ToLower()))
                    {
                        SimpleLog.Log(logComponent, "Replace file: " + someFile);
                        CopyFile(logComponent, replaceFile, someFile, true);

                        if (additionalFiles != null)
                        {
                            foreach (string addFile in additionalFiles)
                            {
                                if (File.Exists(addFile))
                                {
                                    string addFileDest = ParsePath(someFile) + "\\" + ParseShortname(addFile);
                                    SimpleLog.Log(logComponent, "Replace file: " + addFileDest);
                                    CopyFile(logComponent, addFile, addFileDest, true);
                                }
                            }
                        }

                        break;
                    }
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Recursive file replacement failure.");
            }
        }

        public static long SizeOfFileOrFolder(string fileOrFolder)
        {
            try
            {
                if (File.Exists(fileOrFolder))
                {
                    return new FileInfo(fileOrFolder).Length;
                }
                else if (Directory.Exists(fileOrFolder))
                {
                    long totalSize = 0;
                    DirectoryInfo dirInfo = new DirectoryInfo(fileOrFolder);
                    FileInfo[] files = dirInfo.GetFiles();

                    foreach (FileInfo fi in files)
                    {
                        totalSize += fi.Length;
                    }

                    DirectoryInfo[] directories = dirInfo.GetDirectories();

                    foreach (DirectoryInfo di in directories)
                    {
                        totalSize += SizeOfFileOrFolder(di.FullName);
                    }

                    return totalSize;
                }
            }
            catch (Exception) { }
            return 0;
        }

        public static bool VerifyAccess(string fileName)
        {
            try
            {
                if (File.Exists(fileName))
                {
                    FileSecurity fs = File.GetAccessControl(fileName);
                    FileInfo fileInfo = new FileInfo(fileName);
                    FileStream fileStream = fileInfo.Open(FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                    fileStream.Dispose();
                }
                else
                {
                    return false;
                }
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
        }
    }
}