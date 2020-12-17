using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using SimpleLogger;

namespace WindowsNative
{
    public class PageFile
    {
        public static List<PageFile> PageFiles = new List<PageFile>();

        public string Name { get; set; }
        public string DriveLetter { get; set; }
        public string Comment { get; set; }
        public bool AutomaticManagement { get; set; }
        public int InitialSize { get; set; }
        public int MaximumSize { get; set; }
        public int AllocatedBaseSize { get; set; }
        public int CurrentUsage { get; set; }
        public int PeakUsage { get; set; }
        public long AvailableSpace { get; set; }

        private PageFile()
        {

        }

        public static bool ReadConfig(string logComponent)
        {
            try
            {
                PageFiles = new List<PageFile>();

                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    if (d.DriveType.ToString().ToLower().Equals("fixed"))
                    {
                        var p = new PageFile();
                        p.Name = "<No page file>";
                        p.DriveLetter = d.Name.ToUpper();
                        p.Comment = "No page file";
                        p.AutomaticManagement = false;
                        p.InitialSize = 0;
                        p.MaximumSize = 0;
                        p.AllocatedBaseSize = 0;
                        p.CurrentUsage = 0;
                        p.PeakUsage = 0;
                        p.AvailableSpace = d.TotalFreeSpace / 1048576; // 1MB = 1,048,576 bytes.

                        PageFiles.Add(p);
                    }
                }

                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PageFileUsage");

                foreach (ManagementBaseObject obj in searcher.Get())
                {
                    string driveLetter = obj["Name"].ToString().ToUpper().Substring(0, 3);

                    // Iterate known drives.
                    foreach (PageFile pf in PageFiles)
                    {
                        // Does this page file drive letter match a system disk drive?
                        if (pf.DriveLetter.ToUpper().Equals(driveLetter.ToUpper()))
                        {
                            // Set page file usage details.
                            pf.Name = obj["Name"].ToString();
                            pf.AllocatedBaseSize = int.Parse(obj["AllocatedBaseSize"].ToString());
                            pf.CurrentUsage = int.Parse(obj["CurrentUsage"].ToString());
                            pf.PeakUsage = int.Parse(obj["PeakUsage"].ToString());

                            // ******************************
                            // Query PageFile Settings by Drive.
                            // ******************************

                            // WMI query for page file settings.
                            var settingsQuery = new ObjectQuery("SELECT * FROM Win32_PageFileSetting");
                            var innerSearcher = new ManagementObjectSearcher(scope, settingsQuery);
                            ManagementObjectCollection queryCollection = innerSearcher.Get();

                            // Iterate results.
                            foreach (ManagementObject m in queryCollection)
                            {
                                // Do these settings match the current page file name?
                                if (m["Name"].ToString().ToUpper().Equals(pf.Name.ToUpper()))
                                {
                                    // Capture settings.
                                    pf.InitialSize = int.Parse(m["InitialSize"].ToString());
                                    pf.MaximumSize = int.Parse(m["MaximumSize"].ToString());

                                    // Are the values matching?
                                    if (pf.MaximumSize == 0 && pf.InitialSize == pf.MaximumSize)
                                    {
                                        // Set comment.
                                        pf.Comment = "System Managed [Dynamic]";
                                    }
                                    else if (pf.InitialSize == pf.MaximumSize)
                                    {
                                        // Set comment.
                                        pf.Comment = "Custom Managed [Fixed]";
                                    }
                                    else
                                    {
                                        // Set comment.
                                        pf.Comment = "Custom Managed [Dynamic]";
                                    }

                                    // End inner iteration.
                                    break;
                                }
                            }

                            // Dispose resources.
                            innerSearcher.Dispose();

                            // End inner iteration.
                            break;
                        }
                    }
                }

                // WMI query for page file settings.
                var autoQuery = new ObjectQuery("SELECT AutomaticManagedPagefile FROM Win32_ComputerSystem");
                searcher = new ManagementObjectSearcher(scope, autoQuery);

                // Iterate result.
                foreach (ManagementObject m in searcher.Get())
                {
                    // Is automatic page file management turned ON?
                    if (m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("TRUE"))
                    {
                        // Iterate all page files.
                        foreach (PageFile p in PageFiles)
                        {
                            // Set properties.
                            p.Comment = "Automatic Management";
                            p.AutomaticManagement = true;
                        }
                    }
                }

                // Dispose resource.
                searcher.Dispose();

                // Return.
                return true;
            }
            catch (Exception e)
            {
                // Write exception.
                SimpleLog.Log(logComponent, e, "Failed to read page file configuration.");

                // Return.
                return false;
            }
        }

        public static void DisplayConfig(string logComponent)
        {
            // Read page file configuration.
            ReadConfig(logComponent);

            // Iterate page files.
            foreach (PageFile p in PageFiles)
            {
                // Write debug.
                SimpleLog.Log(logComponent, $"Drive: {p.DriveLetter}");
                SimpleLog.Log(logComponent, $"  Comment: {p.Comment}");
                SimpleLog.Log(logComponent, $"  Initial Size: {p.InitialSize}MB");
                SimpleLog.Log(logComponent, $"  Maximum Size: {p.MaximumSize}MB");
                SimpleLog.Log(logComponent, $"  Allocated Size: {p.AllocatedBaseSize}MB");
                SimpleLog.Log(logComponent, $"  Current usage: {p.CurrentUsage}MB");
                SimpleLog.Log(logComponent, $"  Peak usage: {p.PeakUsage}MB");
            }
        }

        public static bool ConfigureAutomaticPageFile(string logComponent, bool enable)
        {
            try
            {
                // Get handle to current process.
                IntPtr hProcess = Process.GetCurrentProcess().Handle;

                // Are we able to open target processes token?
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_ALL_ACCESS, out IntPtr hToken))
                {
                    // Write debug
                    SimpleLog.Log(logComponent, "ERROR: Unable to open specified process token [OpenProcessToken=" + Marshal.GetLastWin32Error().ToString() + "].");
                }

                // Enable privilege.
                WindowsHelper.EnablePrivilege(logComponent, hToken, NativeMethods.SE_CREATE_PAGEFILE_NAME);

                // Write debug.
                SimpleLog.Log(logComponent, $"Configure automatic page file management [Enable={enable.ToString().ToUpper()}]...");

                // WMI query for page file settings.
                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var query = new ObjectQuery($"SELECT * FROM Win32_ComputerSystem");
                var searcher = new ManagementObjectSearcher(scope, query);

                // Iterate result.
                foreach (ManagementObject m in searcher.Get())
                {
                    // Enable or disable?
                    if (enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("FALSE"))
                    {
                        // Write debug.
                        SimpleLog.Log(logComponent, "Current setting: OFF");
                        SimpleLog.Log(logComponent, "New setting: ON");

                        // Set property.
                        m["AutomaticManagedPagefile"] = true;

                        // Commit change.
                        m.Put();

                        // Write debug.
                        SimpleLog.Log(logComponent, "Configuration successful.");
                    }
                    else if (enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("TRUE"))
                    {
                        // Write debug.
                        SimpleLog.Log(logComponent, "Current setting: ON");
                        SimpleLog.Log(logComponent, "No configuration changes required.");
                    }
                    else if (!enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("FALSE"))
                    {
                        // Write debug.
                        SimpleLog.Log(logComponent, "Current setting: OFF");
                        SimpleLog.Log(logComponent, "No configuration changes required.");
                    }
                    else if (!enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("TRUE"))
                    {
                        // Write debug.
                        SimpleLog.Log(logComponent, "Current setting: ON");
                        SimpleLog.Log(logComponent, "New setting: OFF");

                        // Set property.
                        m["AutomaticManagedPagefile"] = false;

                        // Commit change.
                        m.Put();

                        // Write debug.
                        SimpleLog.Log(logComponent, "Configuration successful.");
                    }
                }

                // Return.
                return true;
            }
            catch (Exception e)
            {
                // Write exception.
                SimpleLog.Log(logComponent, e, "Failed to update automatic page file configuration.");

                // Return.
                return false;
            }
        }

        public static bool ConfigureManualPageFile(string logComponent, string driveLetter, int initSize, int maxSize)
        {
            try
            {
                // Write debug.
                SimpleLog.Log(logComponent, "Ensure automatic page file management is OFF...");

                // Ensure automatic page file configuration is OFF.
                // Note: This will also enable SeCreatePagefilePrivilege.
                bool success = ConfigureAutomaticPageFile(logComponent, false);

                // Automatic management NOT successfully turned off?
                if (!success)
                {
                    // Write debug.
                    SimpleLog.Log(logComponent, "ERROR: Failed to TURN OFF automatic page file management, further actions cancelled.");

                    // Return.
                    return false;
                }

                // Write debug.
                SimpleLog.Log(logComponent, "Perform manual configuration...");
                SimpleLog.Log(logComponent, $"  Drive letter: {driveLetter}:\\");
                SimpleLog.Log(logComponent, $"  Initial Size: {initSize}");
                SimpleLog.Log(logComponent, $"  Maximum Size: {maxSize}");

                // Iterate all drives.
                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    // Is this the disk to configure?
                    if (d.Name.ToUpper().Substring(0, 1).Equals(driveLetter.ToUpper()))
                    {
                        // Get free space in MB.
                        long freeSpaceMB = d.TotalFreeSpace / 1048576; // 1 MB = 1,048,576 bytes

                        // Does it have enough free space?
                        if (maxSize > freeSpaceMB)
                        {
                            // Write debug.
                            SimpleLog.Log(logComponent, $"ERROR: Page file maximum size [{maxSize}MB] exceeds available free disk space [{freeSpaceMB}MB].");

                            // Return.
                            return false;
                        }
                        else
                        {
                            // End iteration.
                            break;
                        }
                    }
                }

                // WMI query for page file settings.
                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT * FROM Win32_PageFileSetting");
                var searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection queryCollection = searcher.Get();

                // Flag.
                bool matchFound = false;

                // Iterate results.
                foreach (ManagementObject m in queryCollection)
                {
                    // Drive letter match for configuration?
                    if (m["Name"].ToString().ToUpper().StartsWith(driveLetter.ToUpper()))
                    {
                        // Write debug.
                        SimpleLog.Log(logComponent, "Update existing page file configuration...");

                        // Set flag.
                        matchFound = true;

                        // Set new values.
                        m["InitialSize"] = initSize;
                        m["MaximumSize"] = maxSize;

                        // Commit changes.
                        m.Put();

                        // End iteration.
                        break;
                    }
                }

                // No results or no match -- Add new instance to configuration.
                if (queryCollection.Count == 0 || !matchFound)
                {
                    // Write debug.
                    SimpleLog.Log(logComponent, "Create new page file configuration...");

                    // Initialize class instance.
                    var mc = new ManagementClass(@"\\.\root\cimv2", "Win32_PageFileSetting", null);
                    ManagementObject mo = mc.CreateInstance();

                    // Set values.
                    mo["Caption"] = $"{driveLetter.ToUpper()}:\\ 'pagefile.sys'";
                    mo["Description"] = $"'pagefile.sys' @ {driveLetter.ToUpper()}:\\";
                    mo["InitialSize"] = initSize;
                    mo["MaximumSize"] = maxSize;
                    mo["Name"] = $"{driveLetter.ToUpper()}:\\pagefile.sys";
                    mo["SettingID"] = $"pagefile.sys @ {driveLetter.ToUpper()}:";

                    // Commit changes.
                    var options = new PutOptions();
                    options.Type = PutType.CreateOnly;
                    mo.Put(options);

                    // Dispose resources.
                    mo.Dispose();
                    mc.Dispose();
                }

                // Dispose resources.
                searcher.Dispose();

                // Write debug.
                SimpleLog.Log(logComponent, "Configuration successful.");

                // Return.
                return true;
            }
            catch (Exception e)
            {
                // Write exception.
                SimpleLog.Log(logComponent, e, "Failed to update page file configuration.");

                // Return.
                return false;
            }
        }

        public static bool RemovePageFile(string logComponent, string driveLetter)
        {
            try
            {
                // Write debug.
                SimpleLog.Log(logComponent, "Ensure automatic page file management is OFF...");

                // Turn off automatic page file configuration.
                // Note: This will also enable SeCreatePagefilePrivilege.
                bool success = ConfigureAutomaticPageFile(logComponent, false);

                // Automatic management NOT successfully turned off?
                if (!success)
                {
                    // Write debug.
                    SimpleLog.Log(logComponent, "ERROR: Failed to TURN OFF automatic page file management, further actions cancelled.");

                    // Return.
                    return false;
                }

                // Write debug.
                SimpleLog.Log(logComponent, "Remove page file configuration...");
                SimpleLog.Log(logComponent, $"  Drive letter: {driveLetter}");

                // WMI query for page file settings.
                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT * FROM Win32_PageFileSetting");
                var searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection queryCollection = searcher.Get();

                // Flag.
                bool matchFound = false;

                // Iterate results.
                foreach (ManagementObject m in queryCollection)
                {
                    // Drive letter match for configuration?
                    if (m["Name"].ToString().ToUpper().StartsWith(driveLetter.ToUpper()))
                    {
                        // Write debug.
                        SimpleLog.Log(logComponent, "Found page file configuration, removing...");

                        // Set flag.
                        matchFound = true;

                        // Delete instance.
                        m.Delete();

                        // End iteration.
                        break;
                    }
                }

                // No results or no match -- Add new instance to configuration.
                if (queryCollection.Count == 0 || !matchFound)
                {
                    // Write debug.
                    SimpleLog.Log(logComponent, $"ERROR: Removal failed, no page file is currently configured for {driveLetter}:\\.");

                    // Return.
                    return false;
                }

                // Dispose resources.
                searcher.Dispose();

                // Write debug.
                SimpleLog.Log(logComponent, "Removal successful.");

                // Return.
                return true;
            }
            catch (Exception e)
            {
                // Write exception.
                SimpleLog.Log(logComponent, e, "Failed to update page file configuration.");

                // Return.
                return false;
            }
        }
    }
}