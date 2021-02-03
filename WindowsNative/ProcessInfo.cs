using System;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Security.Principal;
using System.IO;

namespace WindowsLibrary
{
    public class ProcessInfo
    {
        public string ProcessName { get; private set; }
        public string ProcessShortName { get; private set; }
        public string ProcessFriendlyName { get; private set; }
        public string ProcessFilePath { get; private set; }
        public int PID { get; private set; }
        public string UserName { get; private set; }
        public string CPUTime { get; private set; }
        public long NumBytes { get; private set; }
        public int HandleCount { get; private set; }
        public int ThreadCount { get; private set; }
        public string CommandLineArgs { get; private set; }

        public ProcessInfo(Process p)
        {
            ProcessName = p.MainModule.FileName;
            ProcessShortName = Path.GetFileName(ProcessName);
            ProcessFriendlyName = p.ProcessName;
            ProcessFilePath = Path.GetDirectoryName(ProcessName);
            PID = p.Id;
            UserName = GetProcessOwner(p.Handle);
            CPUTime = p.TotalProcessorTime.ToString().Substring(0, 11);
            NumBytes = p.WorkingSet64;
            HandleCount = p.HandleCount;
            ThreadCount = p.Threads.Count;
            CommandLineArgs = GetProcessCLIArgsWMI(PID);
        }

        public override string ToString()
        {
            return ProcessName + "|" +
                PID.ToString() + "|" +
                UserName + "|" +
                CPUTime + "|" +
                NumBytes.ToString() + "|" +
                HandleCount.ToString() + "|" +
                ThreadCount.ToString() + "|" +
                CommandLineArgs;
        }

        public string[] ToStringArray()
        {
            return new string[] {
                ProcessShortName,
                PID.ToString(),
                UserName,
                CPUTime,
                new FileSystemHelper(null).BytesToReadableValue(NumBytes),
                HandleCount.ToString(),
                ThreadCount.ToString(),
                ProcessName + " " + CommandLineArgs };
        }

        public static string GetProcessCLIArgsWMI(int processId)
        {
            using (var searcher = new ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId = " + processId.ToString()))
            {
                using (ManagementObjectCollection objects = searcher.Get())
                {
                    return objects.Cast<ManagementBaseObject>().SingleOrDefault()?["CommandLine"]?.ToString();
                }
            }
        }

        public static string GetProcessOwnerWMI(int processID)
        {
            // NOTE: This was replaced by GetProcessOwner(IntPtr hProcess), since native
            //       P/Invoke is significantly faster than WMI.

            string wmiQuery = "Select * From Win32_Process Where ProcessID = " + processID;
            var wmiSearcher = new ManagementObjectSearcher(wmiQuery);
            ManagementObjectCollection processList = wmiSearcher.Get();

            foreach (ManagementObject obj in processList)
            {
                string[] argList = new string[] { string.Empty, string.Empty };
                int returnVal = Convert.ToInt32(obj.InvokeMethod("GetOwner", argList));
                if (returnVal == 0)
                {
                    return argList[1] + "\\" + argList[0];
                }
            }

            wmiSearcher.Dispose();
            processList.Dispose();

            return "<Unavailable>";
        }

        public static string GetProcessOwner(IntPtr hProcess)
        {
            IntPtr hToken = IntPtr.Zero;
            try
            {
                NativeMethods.OpenProcessToken(hProcess, 8, out hToken);
                var wi = new WindowsIdentity(hToken).Name;
                return wi;
            }
            catch
            {
                return "<Not Available>";
            }
            finally
            {
                if (hToken != IntPtr.Zero)
                {
                    NativeMethods.CloseHandle(hToken);
                }
            }
        }
    }
}