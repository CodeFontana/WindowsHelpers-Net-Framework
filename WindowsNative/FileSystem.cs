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
    public static class FileSystem
    {
        public static bool AddDirectorySecurity(
            string logComponent,
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
                if (Registry.RegistryValueExists(
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                    "NoSecurityTab",
                    Microsoft.Win32.RegistryHive.CurrentUser))
                {
                    try
                    {
                        // Open GPO.
                        var gpo = new ComputerGroupPolicyObject();

                        // Registry key which represents the policy.
                        string policyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer";

                        // Retrieve root registry for user.
                        using (var userRootGPO = gpo.GetRootRegistryKey(GroupPolicySection.User))
                        {
                            // Open the policy key in question.
                            using (var securityTabKey = userRootGPO.OpenSubKey(policyPath, true))
                            {
                                // Delete the registry value.
                                securityTabKey.DeleteValue("NoSecurityTab");
                            }
                        }

                        // Save the updated GPO.
                        gpo.Save();

                        // Write debug.
                        SimpleLog.Log(logComponent, "Refresh Windows policy...");

                        // Refresh applied GPOs.
                        ProcessAPI.RunProcessEx(
                            WindowsUtility.SystemDrive + "\\Windows\\System32\\gpupdate.exe",
                            "/force",
                            WindowsUtility.SystemDrive + "\\Windows\\System32",
                            180, true, true, true);
                    }
                    catch (Exception e)
                    {
                        // Write exception.
                        SimpleLog.Log(logComponent, e, "Failed to edit local group policy.");
                    }
                }

                // File or folder?
                if (File.Exists(fileOrFolder))
                {
                    // Get the ACL.
                    FileSecurity fSecurity = File.GetAccessControl(fileOrFolder);

                    // Turn off protection.
                    fSecurity.SetAccessRuleProtection(false, true);

                    // Add specified access rule -- no inheritance with files.
                    fSecurity.AddAccessRule(new FileSystemAccessRule(
                    userAccount, requestedRights, controlType));

                    // Apply the ACL.
                    File.SetAccessControl(fileOrFolder, fSecurity);
                }
                else if (Directory.Exists(fileOrFolder))
                {
                    // Get the ACL.
                    DirectorySecurity dSecurity = Directory.GetAccessControl(fileOrFolder);

                    // Turn off protection.
                    dSecurity.SetAccessRuleProtection(false, true);

                    // Add specified access rule.
                    dSecurity.AddAccessRule(new FileSystemAccessRule(
                        userAccount, requestedRights,
                        inheritFlag, propFlag, controlType));

                    // Apply the ACL.
                    Directory.SetAccessControl(fileOrFolder, dSecurity);
                }
                else
                {
                    // Write debug.
                    Logger.WriteDebug($"ERROR: Specified file or folder [{fileOrFolder}] does not exist.");

                    // Return.
                    return false;
                }

                // Return
                return true;
            }
            catch (Exception e)
            {
                // Force permissions? (e.g. take ownership and try again)
                if (forcePermissions)
                {
                    // Are we NOT able to open target processes token?
                    if (!NativeMethods.OpenProcessToken(
                        Process.GetCurrentProcess().Handle,
                        NativeMethods.TOKEN_ALL_ACCESS,
                        out IntPtr hToken))
                    {
                        // Write debug.
                        SimpleLog.Log(logComponent, "ERROR: Unable to open specified process token [OpenProcessToken=" + Marshal.GetLastWin32Error().ToString() + "].");

                        // Return.
                        return false;
                    }

                    // Are we NOT able to enable SeTakeOwnershipPrivilege?
                    if (!WindowsUtility.EnablePrivilege(hToken, NativeMethods.SE_TAKE_OWNERSHIP_NAME))
                    {
                        // Write debug.
                        SimpleLog.Log(logComponent, "ERROR: Failed to enable privilege [SeTakeOwnershipPrivilege].");

                        // Free resource.
                        Marshal.FreeHGlobal(hToken);

                        // Return.
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

                    // Initalize replacement ACL.
                    IntPtr acl = IntPtr.Zero;

                    // Build ACL.
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

                    // Free resources.
                    NativeMethods.FreeSid(sidAdministrators);
                    NativeMethods.LocalFree(acl);

                    // Let's try this over again.
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
            // Prepare list of suffixes
            var suffixes = new List<string> { " B ", " KB", " MB", " GB", " TB", " PB" };

            // Iterate suffixes
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

            // Return raw bytes
            return numBytes.ToString();
        }

        public static bool CheckDiskStatus(string logComponent)
        {
            // Get list of drives
            DriveInfo[] allDrives = DriveInfo.GetDrives();

            // Iterate all drives
            foreach (DriveInfo d in allDrives)
            {
                // Is this a fixed drive?
                if (d.DriveType.ToString().ToLower().Equals("fixed"))
                {
                    // Write debug
                    SimpleLog.Log(logComponent, "Check drive [read-only]: " + d.Name);

                    // Run plain ChkDsk
                    Tuple<long, string> result = ProcessAPI.RunProcessEx(
                        "chkdsk.exe",
                        d.Name.Substring(0, 2),
                        WindowsUtility.WindowsFolder + "\\System32",
                        1200, true, false, false);

                    // Did ChkDsk find any problems?
                    if (result.Item2.ToLower().Contains("windows has scanned the file system and found no problems"))
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "CHKDSK result: OK");
                    }
                    else
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "CHKDSK result: FAIL");

                        // Return -- problems found
                        return false;
                    }
                }
            }

            // Return
            return true;
        }

        public static bool CheckSmartStatus(string logComponent)
        {
            try
            {
                // Setup WMI query for Disk Drives
                var wmiQuery = new ManagementObjectSearcher(
                    "SELECT Model,SerialNumber,InterfaceType,Partitions,Status,Size FROM Win32_DiskDrive");

                // Flag for SMART status
                bool smartOK = true;

                // Iterate results
                foreach (ManagementObject drive in wmiQuery.Get())
                {
                    // Read the following parameters
                    var model = drive["Model"];
                    var serial = drive["SerialNumber"];
                    var interfacetype = drive["InterfaceType"];
                    var partitions = drive["Partitions"];
                    var smart = drive["Status"];
                    var sizeInBytes = drive["Size"];

                    // Write debug
                    SimpleLog.Log(logComponent, "Found drive: " + model.ToString());

                    // Is the serial number available?
                    if (serial != null)
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "  Serial: " + serial.ToString());
                    }

                    // Is the interface available?
                    if (interfacetype != null)
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "  Interface: " + interfacetype.ToString());
                    }

                    // Is the partition count available?
                    if (partitions != null)
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "  Partitions: " + partitions.ToString());
                    }

                    // Is the size available?
                    if (sizeInBytes != null)
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "  Size: " + FileSystem.BytesToReadableValue(long.Parse(sizeInBytes.ToString().Trim())));
                    }

                    // Is the SMART status available
                    if (smart != null)
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "  SMART: " + smart.ToString());

                        // Is the SMART status OK?
                        if (!smart.ToString().ToLower().Equals("ok"))
                        {
                            // Set flag
                            smartOK = false;
                        }
                    }
                }

                // Dispose resources.
                wmiQuery.Dispose();

                // Does any drive have a SMART FAIL status?
                if (!smartOK)
                {
                    // Write debug
                    SimpleLog.Log(logComponent, "ERROR: SMART status failure detected.");

                    // Return
                    return false;
                }
                else
                {
                    // Return
                    return true;
                }
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to verify drive SMART status.");

                // Return
                return false;
            }
        }

        public static bool CopyFile(
            string logComponent,
            string sourceFileName,
            string destFileName,
            bool overWrite = true,
            bool verboseOutput = true,
            bool handleInUseOnReboot = false)
        {
            // Write debug
            SimpleLog.Log(logComponent, "Copy file: " + sourceFileName);
            SimpleLog.Log(logComponent, "       To: " + destFileName);

            try
            {
                try
                {
                    // Does the specified source file exist?
                    if (!File.Exists(sourceFileName))
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "ERROR: Source file does not exist [" + sourceFileName + "].");

                        // Return
                        return false;
                    }

                    // Is the destination file different from the source?
                    if (sourceFileName.ToLower().Equals(destFileName.ToLower()))
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "ERROR: Source and destination files must be different [" + sourceFileName + "].");

                        // Return
                        return false;
                    }

                    // Does the destination directory exist?
                    if (!Directory.Exists(ParsePath(destFileName)))
                    {
                        try
                        {
                            // Create the directory
                            Directory.CreateDirectory(ParsePath(destFileName));
                        }
                        catch (Exception e)
                        {
                            // Write debug
                            Logger.WriteDebug("EXCEPTION: " + e.Message);
                            Logger.WriteDebug("ERROR: Failed to create target directory.");

                            // Return
                            return false;
                        }
                    }

                    // Copy the file
                    File.Copy(sourceFileName, destFileName, overWrite);

                    // Iterate files in the destination folder
                    foreach (string file in Directory.GetFiles(ParsePath(destFileName)))
                    {
                        // Does the filename contain ".delete_on_reboot"?
                        if (file.ToLower().Contains(".delete_on_reboot"))
                        {
                            // Delete the file
                            DeleteFile(file, false, true);
                        }
                    }

                    // Return
                    return true;
                }
                catch (Exception)
                {
                    // Is the destination file in-use? (and the caller definitely specified overWrite option)
                    if (IsFileOpen(destFileName) && overWrite)
                    {
                        try
                        {
                            // New file extension
                            string incrementFilename = destFileName + ".delete_on_reboot";

                            // Increment
                            int fileIncrement = 0;

                            // Loop dangerously
                            while (true)
                            {
                                // Does the intended destination file already exist?
                                if (File.Exists(incrementFilename))
                                {
                                    // Update file increment
                                    incrementFilename = destFileName + ".delete_on_reboot_" + (fileIncrement++).ToString();
                                }
                                else
                                {
                                    // Stop condition
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

                            // Write debug
                            SimpleLog.Log(logComponent, "Delete after reboot: " + incrementFilename);
                        }
                        catch (Exception)
                        {
                            // New file extension
                            string pendingFilename = destFileName + ".pending";

                            // Increment
                            int fileIncrement = 0;

                            // Loop dangerously
                            while (true)
                            {
                                // Does the intended destination file already exist?
                                if (File.Exists(pendingFilename))
                                {
                                    // Update file increment
                                    pendingFilename = destFileName + ".pending_" + fileIncrement.ToString();
                                }
                                else
                                {
                                    // Stop condition
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

                                // Did in-place replacement NOT work?
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

                                    // Write debug
                                    SimpleLog.Log(logComponent, "Reboot required: " + destFileName);

                                    // Return -- copy scheduled following a reboot
                                    return true;
                                }
                                else if (!moveSuccess && !handleInUseOnReboot)
                                {
                                    // Write debug
                                    SimpleLog.Log(logComponent, "ERROR: Destination file is in-use [" + destFileName + "].");

                                    // Return
                                    return false;
                                }
                                else
                                {
                                    // Return -- in-place replacement suceeded
                                    return true;
                                }
                            }
                            catch (Exception e)
                            {
                                // Write exception.
                                Logger.WriteException(e, "Unable to schedule file replacement for in-use file [" + destFileName + "].");

                                // Return -- Exception occurred, likely with security block of MoveFileEx().
                                return false;
                            }
                        }
                    }

                    // Copy the file
                    File.Copy(sourceFileName, destFileName, overWrite);

                    // Return
                    return true;
                }
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to copy file [" + ParseShortname(sourceFileName) + "] to destination.");
            }

            // Return
            return false;
        }

        public static bool CopyFolderContents(
            string logComponent,
            string sourceFolder,
            string targetFolder,
            string[] reservedItems = null,
            bool verboseOutput = true,
            bool recursiveCopy = true,
            bool handleInUseOnReboot = false)
        {
            // Does the specified source folder exist?
            if (!Directory.Exists(sourceFolder))
            {
                // Write debug
                SimpleLog.Log(logComponent, "ERROR: Source folder does not exist [" + sourceFolder + "].");

                // Return
                return false;
            }

            // Is the destination folder different from the source?
            if (sourceFolder.ToLower().Equals(targetFolder.ToLower()))
            {
                // Write debug
                SimpleLog.Log(logComponent, "ERROR: Source and destination folders must be different [" + sourceFolder + "].");

                // Return
                return false;
            }

            // Does the specified target directory exist?
            if (!Directory.Exists(targetFolder))
            {
                try
                {
                    // Create the directory
                    Directory.CreateDirectory(targetFolder);
                }
                catch (Exception e)
                {
                    // Write debug
                    Logger.WriteDebug("EXCEPTION: " + e.Message);
                    Logger.WriteDebug("ERROR: Failed to create target directory.");

                    // Return
                    return false;
                }
            }

            // Flag for reserved items
            bool skipItem = false;

            try
            {
                // Read list of files in the directory
                string[] fileList = Directory.GetFiles(sourceFolder);

                // Iterate files for copy
                foreach (string sourceFile in fileList)
                {
                    // Reserve items specified?
                    if (reservedItems != null)
                    {
                        // Iterate reserve items
                        foreach (string str in reservedItems)
                        {
                            // Does the current file match any reserved items?
                            if (sourceFile.ToLower().EndsWith(str.ToLower()))
                            {
                                // Write debug
                                SimpleLog.Log(logComponent, "Reserved file: " + sourceFile, !verboseOutput);

                                // Set flag
                                skipItem = true;
                            }
                        }
                    }

                    // Is this file NOT reserved?
                    if (!skipItem)
                    {
                        // Form the destination filename
                        string destinationFile = Path.Combine(targetFolder, sourceFile.Substring(sourceFile.LastIndexOf("\\") + 1));

                        // Copy source file to destination
                        CopyFile(sourceFile, destinationFile, true, verboseOutput, handleInUseOnReboot);
                    }

                    // Reset flag
                    skipItem = false;
                }

                // Array of sub-folders in the directory
                string[] folderList = null;

                // Recursive copy of sub-folders?
                if (recursiveCopy)
                {
                    // Read array of sub-folders
                    folderList = Directory.GetDirectories(sourceFolder);

                    // Iterate folders for copy
                    foreach (string sourceDir in folderList)
                    {
                        // Reserve items specified?
                        if (reservedItems != null)
                        {
                            // Iterate reserve items
                            foreach (string str in reservedItems)
                            {
                                // Does the current folder match any reserved items?
                                if (sourceDir.ToLower().EndsWith(str.ToLower()))
                                {
                                    // Verbose output specified?
                                    if (verboseOutput)
                                    {
                                        // Write debug
                                        SimpleLog.Log(logComponent, "Reserved folder: " + sourceDir);
                                    }

                                    // Set flag
                                    skipItem = true;
                                }
                            }
                        }

                        // SPECIAL CASE: System Volume Information
                        if (sourceDir.ToLower().Contains("system volume information"))
                        {
                            // Verbose output specified?
                            if (verboseOutput)
                            {
                                // Write debug
                                SimpleLog.Log(logComponent, "Reserved folder: " + sourceDir);
                            }

                            // Set flag
                            skipItem = true;
                        }

                        // SPECIAL CASE: System Volume Information
                        if (sourceDir.ToLower().Contains("$recycle"))
                        {
                            // Verbose output specified?
                            if (verboseOutput)
                            {
                                // Write debug
                                SimpleLog.Log(logComponent, "Reserved folder: " + sourceDir);
                            }

                            // Set flag
                            skipItem = true;
                        }

                        // Is the sub-folder reserved?
                        if (!skipItem)
                        {
                            // Form the destination path
                            string destinationPath = Path.Combine(targetFolder, sourceDir.Substring(sourceDir.LastIndexOf("\\") + 1));

                            // Verbose output specified?
                            if (verboseOutput)
                            {
                                // Write debug
                                SimpleLog.Log(logComponent, "Copy folder: " + sourceDir);
                                SimpleLog.Log(logComponent, "         To: " + destinationPath);
                            }

                            try
                            {
                                // Recursive call
                                CopyFolderContents(sourceDir, destinationPath, reservedItems, verboseOutput, recursiveCopy, handleInUseOnReboot);
                            }
                            catch (Exception e)
                            {
                                // Write debug
                                Logger.WriteDebug("EXCEPTION: " + e.Message);
                                Logger.WriteDebug("ERROR: Failed to copy folder [" + sourceDir + "] to desintation.");
                            }
                        }

                        // Reset flag
                        skipItem = false;
                    }
                }
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to copy directory to destination.");

                // Return
                return false;
            }

            // Return
            return true;
        }

        public static bool DeleteFile(
            string logComponent,
            string fileName,
            bool raiseException = false,
            bool handleInUseOnReboot = false)
        {
            // Flag for return
            bool fileDeleted = false;

            // Specified file exists?
            if (File.Exists(fileName))
            {
                try
                {
                    try
                    {
                        // Adjust file attributes
                        File.SetAttributes(fileName, FileAttributes.Normal);

                        // Attempt to delete the file
                        File.Delete(fileName);

                        // Write debug
                        SimpleLog.Log(logComponent, "Deleted file: " + fileName);

                        // Set flag
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
                                // New file extension
                                string deleteFilename = fileName + ".delete_on_reboot";

                                // Increment
                                int fileIncrement = 0;

                                // Loop dangerously
                                while (true)
                                {
                                    // Does the intended destination file already exist?
                                    if (File.Exists(deleteFilename))
                                    {
                                        // Update file increment
                                        deleteFilename = fileName + ".delete_on_reboot_" + (fileIncrement++).ToString();
                                    }
                                    else
                                    {
                                        // Stop condition
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

                                // Write debug
                                SimpleLog.Log(logComponent, "Delete after reboot: " + deleteFilename);
                            }
                            catch (Exception)
                            {
                                // Schedule in-place deletion on next reboot
                                NativeMethods.MoveFileEx(
                                    fileName,
                                    null,
                                    NativeMethods.MoveFileFlags.DelayUntilReboot);

                                // Write debug
                                SimpleLog.Log(logComponent, "Delete after reboot: " + fileName);
                            }
                        }
                        else if (fileName.ToLower().Contains(".delete_on_reboot"))
                        {
                            // Set flag
                            fileDeleted = false;

                            // Write debug
                            SimpleLog.Log(logComponent, "Deleted after reboot: " + fileName, true);
                        }
                        else
                        {
                            // Delete the file
                            File.Delete(fileName);

                            // Write debug
                            SimpleLog.Log(logComponent, "Deleted file: " + fileName);

                            // Set flag
                            fileDeleted = true;
                        }
                    }
                }
                catch (Exception e)
                {
                    // Set flag
                    fileDeleted = false;

                    // Write debug
                    Logger.WriteDebug("WARN: Exception caught deleting file.");
                    Logger.WriteDebug(e.Message);
                    Logger.WriteDebug(e.StackTrace);

                    // Raise an exception?
                    if (raiseException)
                        throw e;
                }
            }

            // Return
            return fileDeleted;
        }

        public static bool DeleteFilePattern(string logComponent, string folderName, string filePattern, bool raiseException = false)
        {
            // Flag for return
            bool fileDeleted = false;

            try
            {
                // Does the specified folder exist?
                if (!Directory.Exists(folderName))
                    return false;

                // Read list of files
                string[] fileList = Directory.GetFiles(folderName);

                // Does the directory contain any files?
                if (fileList.Length > 0)
                {
                    string strFile;

                    // Iterate the files
                    for (int n = 0; n <= fileList.Length - 1; n++)
                    {
                        // Parse file shortname
                        strFile = fileList[n].ToString().ToLower();
                        strFile = strFile.Substring(strFile.LastIndexOf("\\") + 1);

                        // Does the shortname match the provided pattern?
                        if (strFile.ToLower().StartsWith(filePattern.ToLower()))
                        {
                            // Delete the file
                            DeleteFile(fileList[n]);

                            // Set flag
                            fileDeleted = true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                // Write debug
                Logger.WriteDebug("Warning: Exception caught deleting file.");
                Logger.WriteDebug(ex.Message);

                // Raise an exception?
                if (raiseException)
                    throw ex;
            }

            // Return
            return fileDeleted;
        }

        public static bool DeleteFolder(string logComponent, string folderName, bool raiseException = false)
        {
            // Flag for return
            bool folderDeleted = false;

            // Does the folder exist?
            if (Directory.Exists(folderName))
            {
                try
                {
                    // Write debug
                    SimpleLog.Log(logComponent, "Delete folder: " + folderName);

                    // Delete contents of the folder first
                    DeleteFolderContents(folderName, null, true);

                    // Delete the folder
                    Directory.Delete(folderName, true);

                    // Set flag
                    folderDeleted = true;
                }
                catch (Exception e)
                {
                    // Write debug
                    Logger.WriteDebug("Warning: Exception caught deleting folder.");
                    Logger.WriteDebug(e.Message);
                    Logger.WriteDebug(e.StackTrace);

                    // Raise an exception?
                    if (raiseException)
                        throw e;
                }
            }
            else
            {
                // Set flag
                folderDeleted = true;
            }

            // Return
            return folderDeleted;
        }

        public static void DeleteFolderContents(string logComponent, 
            string targetFolder, 
            string[] reservedItems,
            bool verboseOutput = true, 
            bool recurseReservedItems = true)
        {
            // Does the specified directory exist?
            if (!Directory.Exists(targetFolder))
                return;

            // Get list of files and folders in the targer directory
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
                // Write debug
                Logger.WriteDebug("ERROR: Failed to set target folder access control list.");
                Logger.WriteDebug(ex.Message);
            }

            // Flag for skipping an item from the reserved list
            bool skipItem = false;

            // Does the directory contain sub-folders?
            if (folderList.Length > 0)
            {
                // Iterate subfolders
                for (int n = 0; n <= folderList.Length - 1; n++)
                {
                    try
                    {
                        // Reserve items specified?
                        if (reservedItems != null)
                        {
                            // Iterate reserve items
                            foreach (string str in reservedItems)
                            {
                                // Does the current folder match any reserved items?
                                if (folderList[n].ToString().ToLower().EndsWith(str.ToLower()))
                                {
                                    // Write debug
                                    SimpleLog.Log(logComponent, "Reserved folder: " + folderList[n].ToString());

                                    // Set flag
                                    skipItem = true;
                                }
                            }
                        }

                        // Is the sub-folder reserved?
                        if (!skipItem)
                        {
                            // Get directory properties
                            var folderInfo = new DirectoryInfo(folderList[n].ToString());

                            // Is this a reparse point (NTFS junction)?
                            if (folderInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
                            {
                                try
                                {
                                    // Write debug
                                    SimpleLog.Log(logComponent, "Remove junction: " + folderList[n].ToString());

                                    // Remove NTFS junction point
                                    FileSystem.RemoveJunction(folderList[n].ToString());
                                }
                                catch (Exception ex)
                                {
                                    // Write debug
                                    Logger.WriteDebug("Warning: Exception caught removing NTFS junction: " + folderList[n].ToString());
                                    Logger.WriteDebug(ex.Message);
                                }
                            }
                            else
                            {
                                // Recurse reserved items?
                                if (recurseReservedItems)
                                    DeleteFolderContents(folderList[n].ToString(), reservedItems, false);
                                else
                                    DeleteFolderContents(folderList[n].ToString(), null, false);
                            }

                            // Verbose output specified?
                            if (verboseOutput)
                            {
                                // Write debug
                                SimpleLog.Log(logComponent, "Delete folder: " + folderList[n].ToString());
                            }

                            // After recurse is finished, delete the folder
                            Directory.Delete(folderList[n]);
                        }

                        // Reset flag
                        skipItem = false;
                    }
                    catch (Exception ex2)
                    {
                        // Write debug
                        Logger.WriteDebug("Warning: Exception caught deleting folder: " + folderList[n].ToString());
                        Logger.WriteDebug(ex2.Message);
                    }
                }
            }

            // Does the directory contain any files?
            if (fileList.Length > 0)
            {
                // Iterate files
                for (int n = 0; n <= fileList.Length - 1; n++)
                {
                    try
                    {
                        // Reserve items specified?
                        if (reservedItems != null)
                        {
                            // Iterate reserve items
                            foreach (string str in reservedItems)
                            {
                                // Does the current file match any reserved items?
                                if (fileList[n].ToString().ToLower().EndsWith(str.ToLower()))
                                {
                                    // Write debug
                                    SimpleLog.Log(logComponent, "Reserved file: " + fileList[n].ToString());

                                    // Set flag
                                    skipItem = true;
                                }
                            }
                        }

                        // Is this file reserved?
                        if (!skipItem)
                        {
                            // Verbose output specified?
                            if (verboseOutput)
                            {
                                // Write debug
                                SimpleLog.Log(logComponent, "Delete file: " + fileList[n].ToString());
                            }

                            // Unset read-only parameter (in case it's set)
                            File.SetAttributes(fileList[n], FileAttributes.Normal);

                            // Delete the file
                            File.Delete(fileList[n]);
                        }

                        // Reset flag
                        skipItem = false;
                    }
                    catch (Exception ex2)
                    {
                        // Write debug
                        Logger.WriteDebug("Warning: Exception caught deleting file: " + fileList[n].ToString());
                        Logger.WriteDebug(ex2.Message);
                    }
                }
            }
        }

        public static string GetAceInformation(FileSystemAccessRule ace)
        {
            // Build string representation of the ACE
            StringBuilder info = new StringBuilder();
            info.AppendLine(string.Format("Account: {0}", ace.IdentityReference.Value));
            info.AppendLine(string.Format("Type: {0}", ace.AccessControlType));
            info.AppendLine(string.Format("Rights: {0}", ace.FileSystemRights));
            info.AppendLine(string.Format("Inherited ACE: {0}", ace.IsInherited));

            // Return
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
            // List for storing results
            List<string[]> foldersAndFiles = new List<string[]>();

            try
            {
                // Does the input folder exist?
                if (!Directory.Exists(folderPath))
                {
                    // Return
                    return "Specified folder was not found [" + folderPath + "].";
                }

                // Add header for folders
                foldersAndFiles.Add(new string[] { "Folder(s)", "" });
                foldersAndFiles.Add(new string[] { "---------", "" });

                // Iterate all folders at the specified path
                foreach (string folder in Directory.GetDirectories(folderPath.Trim('\"')))
                {
                    try
                    {
                        // Add folder name and calculated size
                        foldersAndFiles.Add(new string[] { folder.Substring(folder.LastIndexOf("\\") + 1), BytesToReadableValue(SizeOfFileOrFolder(folder)) });
                    }
                    catch (Exception)
                    {
                        // Add folder name without size
                        foldersAndFiles.Add(new string[] { folder.Substring(folder.LastIndexOf("\\") + 1), "<Size unavailable>" });
                    }
                }

                // Add header for files
                foldersAndFiles.Add(new string[] { "", "" });
                foldersAndFiles.Add(new string[] { "File(s)", "" });
                foldersAndFiles.Add(new string[] { "-------", "" });

                // Iterate all files at the specified path
                foreach (string file in Directory.GetFiles(folderPath))
                {
                    try
                    {
                        // Add file name and calculated size
                        foldersAndFiles.Add(new string[] { ParseShortname(file), BytesToReadableValue(SizeOfFileOrFolder(file)) });
                    }
                    catch (Exception)
                    {
                        // Add filename without size
                        foldersAndFiles.Add(new string[] { ParseShortname(file), "<Size unavailable>" });
                    }
                }
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to iterate file(s) or folder(s) for [" + folderPath + "].");
            }

            // For storing padded table
            string paddedTable = "";

            try
            {
                // Obtain padded elements table
                paddedTable = DotNetHelpers.PadListElements(foldersAndFiles, 5);
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to construct padded elements list.");

                // Build un-padded return string
                string returnString = "";

                // Iterate folders and files
                foreach (string[] s in foldersAndFiles)
                {
                    // Delimit the line with a single space
                    string unPaddedLine = string.Join(" ", s);

                    // Add to return string
                    returnString += unPaddedLine + Environment.NewLine;
                }

                // Return
                return returnString;
            }

            // Return
            return paddedTable;
        }

        public static bool MoveFile(string logComponent,
            string sourceFileName,
            string destFileName,
            bool overWrite = true)
        {
            // Write debug
            SimpleLog.Log(logComponent, "Move file: " + sourceFileName);
            SimpleLog.Log(logComponent, "       To: " + destFileName);

            try
            {
                // Overwrite destination file?
                if (overWrite)
                {
                    // Delete destination file (if it exists), before moving file
                    DeleteFile(destFileName);
                }

                // Move the file
                File.Move(sourceFileName, destFileName);

                // Return
                return true;
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to move file [" + ParseShortname(sourceFileName) + "] to destination.");
            }

            // Return
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
                throw new Win32Exception("Unable to open reparse point.");

            return reparsePointHandle;
        }

        public static string ParseFriendlyname(string filename)
        {
            string friendlyName = ParseShortname(filename);
            if (friendlyName.Contains("."))
                return friendlyName.Substring(0, friendlyName.LastIndexOf("."));
            else
                return friendlyName;
        }

        public static string ParsePath(string filename)
        {
            if (filename.Contains("\\"))
                return filename.Substring(0, filename.LastIndexOf("\\"));
            else
                return filename;
        }

        public static string ParseShortname(string filename)
        {
            if (filename.Contains("\\"))
                return filename.Substring(filename.LastIndexOf("\\") + 1);
            else
                return filename;
        }

        public static bool RemoveDirectorySecurity(
            string logComponent,
            string folderName,
            string userAccount,
            FileSystemRights revokedRights,
            AccessControlType controlType)
        {
            try
            {
                // Create a new DirectoryInfo object
                DirectoryInfo dInfo = new DirectoryInfo(folderName);

                // Get a DirectorySecurity object that represents the current security settings.
                DirectorySecurity dSecurity = dInfo.GetAccessControl();

                // Remove the FileSystemAccessRule to the security settings
                dSecurity.RemoveAccessRule(new FileSystemAccessRule(userAccount, revokedRights, controlType));

                // Set the new access settings
                dInfo.SetAccessControl(dSecurity);

                // Return
                return true;
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to revoke folder permissions from [" + folderName + "].");

                // Return
                return false;
            }
        }

        public static void RemoveJunction(string junctionPoint)
        {
            // Does the junction point exist?
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
                bool result = NativeMethods.DeviceIoControl(fileHandle.DangerousGetHandle(), NativeMethods.FSCTL_DELETE_REPARSE_POINT, inBuffer, 8, IntPtr.Zero, 0, out int BytesReturned, IntPtr.Zero);

                // Success?
                if (!result)
                    throw new Win32Exception("ERROR: Unable to delete reparse point.");
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
                // Does the source file exist?
                if (!File.Exists(replaceFile))
                {
                    // Do nothing
                    return;
                }

                // Base folder -- iterate subfolders
                foreach (string subFolder in Directory.GetDirectories(baseFolder))
                {
                    // Recurse file replacement on each subfolder
                    ReplaceFileIn(subFolder, replaceFile, additionalFiles);
                }

                // Base folder -- iterate files
                foreach (string someFile in Directory.GetFiles(baseFolder))
                {
                    // Does the file shortname match (case insensitive)?
                    if (ParseShortname(someFile).ToLower().Equals(ParseShortname(replaceFile).ToLower()))
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "Replace file: " + someFile);

                        // Copy/overwrite replacement file
                        CopyFile(replaceFile, someFile, true);

                        // Are there additional files to replace in this location?
                        if (additionalFiles != null)
                        {
                            // Iterate additonal replacement files
                            foreach (string addFile in additionalFiles)
                            {
                                // Does the additional file exist?
                                if (File.Exists(addFile))
                                {
                                    // Calculate destination filename
                                    string addFileDest = ParsePath(someFile) + "\\" + ParseShortname(addFile);

                                    // Write debug
                                    SimpleLog.Log(logComponent, "Replace file: " + addFileDest);

                                    // Copy/overwrite additonal replacement file
                                    CopyFile(addFile, addFileDest, true);
                                }
                            }
                        }

                        // Break loop (can't have more than one of same filename in a folder)
                        break;
                    }
                }
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Recursive file replacement failure.");
            }
        }

        public static long SizeOfFileOrFolder(string fileOrFolder)
        {
            try
            {
                // Is this a file or a folder?
                if (File.Exists(fileOrFolder))
                {
                    // Return size of file
                    return new FileInfo(fileOrFolder).Length;
                }
                else if (Directory.Exists(fileOrFolder))
                {
                    // For accumulating total size
                    long totalSize = 0;

                    // Retrieve directory info
                    DirectoryInfo dirInfo = new DirectoryInfo(fileOrFolder);

                    // Retrieve list of files
                    FileInfo[] files = dirInfo.GetFiles();

                    // Iterate files
                    foreach (FileInfo fi in files)
                    {
                        // Add size of each file
                        totalSize += fi.Length;
                    }

                    // Retrieve list of subfolders
                    DirectoryInfo[] directories = dirInfo.GetDirectories();

                    // Iterate subfolders
                    foreach (DirectoryInfo di in directories)
                    {
                        // Add directory size
                        totalSize += SizeOfFileOrFolder(di.FullName);
                    }

                    // Return
                    return totalSize;
                }
            }
            catch (Exception)
            {
                // Do nothing
            }

            // Return
            return 0;
        }

        public static bool VerifyAccess(string fileName)
        {
            try
            {
                // File or folder?
                if (File.Exists(fileName))
                {
                    // Attempt to read file ACL.
                    // Note: This will raise an exception if the path is readonly or unauthorized access. 
                    FileSecurity fs = File.GetAccessControl(fileName);

                    // Attempt to read file.
                    FileInfo fileInfo = new FileInfo(fileName);
                    FileStream fileStream = fileInfo.Open(FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite);
                    fileStream.Dispose();
                }
                else
                {
                    // Return.
                    return false;
                }

                // Return.
                return true;
            }
            catch (UnauthorizedAccessException)
            {
                // Return.
                return false;
            }
        }
    }
}