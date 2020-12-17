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

                // ******************************
                // Index Page Files by Fixed-Disk Drives.
                // ******************************Z

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

                // ******************************
                // Query PageFile Usage Stats by Disk Drive.
                // ******************************

                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PageFileUsage");

                foreach (ManagementBaseObject obj in searcher.Get())
                {
                    string driveLetter = obj["Name"].ToString().ToUpper().Substring(0, 3);

                    foreach (PageFile pf in PageFiles)
                    {
                        if (pf.DriveLetter.ToUpper().Equals(driveLetter.ToUpper()))
                        {
                            pf.Name = obj["Name"].ToString();
                            pf.AllocatedBaseSize = int.Parse(obj["AllocatedBaseSize"].ToString());
                            pf.CurrentUsage = int.Parse(obj["CurrentUsage"].ToString());
                            pf.PeakUsage = int.Parse(obj["PeakUsage"].ToString());

                            // ******************************
                            // Query PageFile Settings by Drive.
                            // ******************************

                            var settingsQuery = new ObjectQuery("SELECT * FROM Win32_PageFileSetting");
                            var innerSearcher = new ManagementObjectSearcher(scope, settingsQuery);
                            ManagementObjectCollection queryCollection = innerSearcher.Get();

                            foreach (ManagementObject m in queryCollection)
                            {
                                if (m["Name"].ToString().ToUpper().Equals(pf.Name.ToUpper()))
                                {
                                    pf.InitialSize = int.Parse(m["InitialSize"].ToString());
                                    pf.MaximumSize = int.Parse(m["MaximumSize"].ToString());

                                    if (pf.MaximumSize == 0 && pf.InitialSize == pf.MaximumSize)
                                    {
                                        pf.Comment = "System Managed [Dynamic]";
                                    }
                                    else if (pf.InitialSize == pf.MaximumSize)
                                    {
                                        pf.Comment = "Custom Managed [Fixed]";
                                    }
                                    else
                                    {
                                        pf.Comment = "Custom Managed [Dynamic]";
                                    }

                                    break;
                                }
                            }

                            innerSearcher.Dispose();
                            break;
                        }
                    }
                }

                // ******************************
                // Query PageFile Automatic Management Setting.
                // ******************************

                var autoQuery = new ObjectQuery("SELECT AutomaticManagedPagefile FROM Win32_ComputerSystem");
                searcher = new ManagementObjectSearcher(scope, autoQuery);

                foreach (ManagementObject m in searcher.Get())
                {
                    if (m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("TRUE"))
                    {
                        foreach (PageFile p in PageFiles)
                        {
                            p.Comment = "Automatic Management";
                            p.AutomaticManagement = true;
                        }
                    }
                }

                searcher.Dispose();
                return true;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to read page file configuration.");
                return false;
            }
        }

        public static void DisplayConfig(string logComponent)
        {
            ReadConfig(logComponent);

            foreach (PageFile p in PageFiles)
            {
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
                IntPtr hProcess = Process.GetCurrentProcess().Handle;

                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_ALL_ACCESS, out IntPtr hToken))
                {
                    SimpleLog.Log(logComponent, "ERROR: Unable to open specified process token [OpenProcessToken=" + Marshal.GetLastWin32Error().ToString() + "].");
                }

                WindowsHelper.EnablePrivilege(logComponent, hToken, NativeMethods.SE_CREATE_PAGEFILE_NAME);
                SimpleLog.Log(logComponent, $"Configure automatic page file management [Enable={enable.ToString().ToUpper()}]...");

                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var query = new ObjectQuery($"SELECT * FROM Win32_ComputerSystem");
                var searcher = new ManagementObjectSearcher(scope, query);

                foreach (ManagementObject m in searcher.Get())
                {
                    if (enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("FALSE"))
                    {
                        SimpleLog.Log(logComponent, "Current setting: OFF");
                        SimpleLog.Log(logComponent, "New setting: ON");
                        m["AutomaticManagedPagefile"] = true;
                        m.Put();
                        SimpleLog.Log(logComponent, "Configuration successful.");
                    }
                    else if (enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("TRUE"))
                    {
                        SimpleLog.Log(logComponent, "Current setting: ON");
                        SimpleLog.Log(logComponent, "No configuration changes required.");
                    }
                    else if (!enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("FALSE"))
                    {
                        SimpleLog.Log(logComponent, "Current setting: OFF");
                        SimpleLog.Log(logComponent, "No configuration changes required.");
                    }
                    else if (!enable && m["AutomaticManagedPagefile"].ToString().ToUpper().Equals("TRUE"))
                    {
                        SimpleLog.Log(logComponent, "Current setting: ON");
                        SimpleLog.Log(logComponent, "New setting: OFF");
                        m["AutomaticManagedPagefile"] = false;
                        m.Put();
                        SimpleLog.Log(logComponent, "Configuration successful.");
                    }
                }

                return true;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to update automatic page file configuration.");
                return false;
            }
        }

        public static bool ConfigureManualPageFile(string logComponent, string driveLetter, int initSize, int maxSize)
        {
            try
            {
                // ******************************
                // Turn OFF Automatic Page File Management.
                // ******************************

                SimpleLog.Log(logComponent, "Ensure automatic page file management is OFF...");
                bool success = ConfigureAutomaticPageFile(logComponent, false);

                if (!success)
                {
                    SimpleLog.Log(logComponent, "ERROR: Failed to TURN OFF automatic page file management, further actions cancelled.");
                    return false;
                }

                SimpleLog.Log(logComponent, "Perform manual configuration...");
                SimpleLog.Log(logComponent, $"  Drive letter: {driveLetter}:\\");
                SimpleLog.Log(logComponent, $"  Initial Size: {initSize}");
                SimpleLog.Log(logComponent, $"  Maximum Size: {maxSize}");

                // ******************************
                // Verify Free Disk Space Available.
                // ******************************

                foreach (DriveInfo d in DriveInfo.GetDrives())
                {
                    if (d.Name.ToUpper().Substring(0, 1).Equals(driveLetter.ToUpper()))
                    {
                        long freeSpaceMB = d.TotalFreeSpace / 1048576; // 1 MB = 1,048,576 bytes

                        if (maxSize > freeSpaceMB)
                        {
                            SimpleLog.Log(logComponent, $"ERROR: Page file maximum size [{maxSize}MB] exceeds available free disk space [{freeSpaceMB}MB].");
                            return false;
                        }
                        else
                        {
                            break;
                        }
                    }
                }

                // ******************************
                // Update Page File Settings.
                // ******************************

                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT * FROM Win32_PageFileSetting");
                var searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection queryCollection = searcher.Get();
                bool matchFound = false;

                foreach (ManagementObject m in queryCollection)
                {
                    if (m["Name"].ToString().ToUpper().StartsWith(driveLetter.ToUpper()))
                    {
                        SimpleLog.Log(logComponent, "Update existing page file configuration...");
                        matchFound = true;
                        m["InitialSize"] = initSize;
                        m["MaximumSize"] = maxSize;
                        m.Put();
                        break;
                    }
                }

                if (queryCollection.Count == 0 || !matchFound)
                {
                    SimpleLog.Log(logComponent, "Create new page file configuration...");
                    var mc = new ManagementClass(@"\\.\root\cimv2", "Win32_PageFileSetting", null);
                    ManagementObject mo = mc.CreateInstance();
                    mo["Caption"] = $"{driveLetter.ToUpper()}:\\ 'pagefile.sys'";
                    mo["Description"] = $"'pagefile.sys' @ {driveLetter.ToUpper()}:\\";
                    mo["InitialSize"] = initSize;
                    mo["MaximumSize"] = maxSize;
                    mo["Name"] = $"{driveLetter.ToUpper()}:\\pagefile.sys";
                    mo["SettingID"] = $"pagefile.sys @ {driveLetter.ToUpper()}:";
                    var options = new PutOptions();
                    options.Type = PutType.CreateOnly;
                    mo.Put(options);
                    mo.Dispose();
                    mc.Dispose();
                }

                searcher.Dispose();
                SimpleLog.Log(logComponent, "Configuration successful.");
                return true;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to update page file configuration.");
                return false;
            }
        }

        public static bool RemovePageFile(string logComponent, string driveLetter)
        {
            try
            {
                // ******************************
                // Turn OFF Automatic Page File Management.
                // ******************************

                SimpleLog.Log(logComponent, "Ensure automatic page file management is OFF...");
                bool success = ConfigureAutomaticPageFile(logComponent, false);

                if (!success)
                {
                    SimpleLog.Log(logComponent, "ERROR: Failed to TURN OFF automatic page file management, further actions cancelled.");
                    return false;
                }

                // ******************************
                // Remove Page File Configuration.
                // ******************************

                SimpleLog.Log(logComponent, "Remove page file configuration...");
                SimpleLog.Log(logComponent, $"  Drive letter: {driveLetter}");
                var scope = new ManagementScope(@"\\.\root\cimv2");
                scope.Connect();
                var query = new ObjectQuery("SELECT * FROM Win32_PageFileSetting");
                var searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection queryCollection = searcher.Get();
                bool matchFound = false;

                foreach (ManagementObject m in queryCollection)
                {
                    if (m["Name"].ToString().ToUpper().StartsWith(driveLetter.ToUpper()))
                    {
                        SimpleLog.Log(logComponent, "Found page file configuration, removing...");
                        matchFound = true;
                        m.Delete();
                        break;
                    }
                }

                if (queryCollection.Count == 0 || !matchFound)
                {
                    SimpleLog.Log(logComponent, $"ERROR: Removal failed, no page file is currently configured for {driveLetter}:\\.");
                    return false;
                }

                searcher.Dispose();
                SimpleLog.Log(logComponent, "Removal successful.");
                return true;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to update page file configuration.");
                return false;
            }
        }
    }
}