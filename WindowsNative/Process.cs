using SimpleLogger;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;

namespace WindowsNative
{
    public static class Process
    {
        public static Tuple<bool, int> CreateProcessAsUser(string logComponent, IntPtr hUserToken, string appFileName, string appArgs)
        {
            try
            {
                // Identify user from access token.
                WindowsIdentity userId = new WindowsIdentity(hUserToken);
                SimpleLog.Log(logComponent, "Create process for: " + userId.Name + " [" + appFileName + " " + appArgs + "].");
                userId.Dispose();

                // Obtain duplicated user token (elevated if UAC is turned on/enabled).
                IntPtr hDuplicateToken = WindowsUtility.DuplicateToken(logComponent, hUserToken);

                // Initialize process info and startup info
                NativeMethods.PROCESS_INFORMATION pi = new NativeMethods.PROCESS_INFORMATION();
                NativeMethods.STARTUPINFO si = new NativeMethods.STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = "winsta0\\default";
                NativeMethods.SECURITY_ATTRIBUTES lpProcessAttributes = new NativeMethods.SECURITY_ATTRIBUTES();
                NativeMethods.SECURITY_ATTRIBUTES lpThreadAttributes = new NativeMethods.SECURITY_ATTRIBUTES();
                IntPtr hEnvironment = IntPtr.Zero;

                if (!NativeMethods.CreateEnvironmentBlock(out hEnvironment, hDuplicateToken, true))
                {
                    SimpleLog.Log(logComponent, "Unable to create environment block [CreateEnvironmentBlock=" + Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.WARN);
                }

                if (!NativeMethods.CreateProcessAsUser(
                    hDuplicateToken,
                    null,
                    appFileName + " " + appArgs,
                    ref lpProcessAttributes,
                    ref lpThreadAttributes,
                    false,
                    (uint)NativeMethods.CreateProcessFlags.NORMAL_PRIORITY_CLASS |
                    (uint)NativeMethods.CreateProcessFlags.CREATE_UNICODE_ENVIRONMENT |
                    (uint)NativeMethods.CreateProcessFlags.CREATE_NEW_CONSOLE,
                    hEnvironment,
                    FileSystem.ParsePath(appFileName),
                    ref si,
                    out pi))
                {
                    SimpleLog.Log(logComponent, "Unable to create user process [CreateProcessAsUser=" + Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);

                    Marshal.FreeHGlobal(hDuplicateToken);
                    Marshal.FreeHGlobal(hEnvironment);
                    Marshal.FreeHGlobal(hUserToken);
                    return new Tuple<bool, int>(false, -1);
                }
                else
                {
                    SimpleLog.Log(logComponent, "Created new process: " + pi.dwProcessId.ToString() + "/" + appFileName + " " + appArgs);
                    var newProcess = System.Diagnostics.Process.GetProcessById(pi.dwProcessId);

                    try
                    {
                        // For UI apps, wait for idle state, before continuing.
                        newProcess.WaitForInputIdle(2000);
                    }
                    catch (InvalidOperationException)
                    {
                        // Must be a non-UI app, just give it a sec to start.
                        Thread.Sleep(1000);
                    }

                    newProcess.Dispose();
                    Marshal.FreeHGlobal(hDuplicateToken);
                    Marshal.FreeHGlobal(hEnvironment);
                    Marshal.FreeHGlobal(hUserToken);
                    return new Tuple<bool, int>(true, pi.dwProcessId);
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to create process as user.");
                return new Tuple<bool, int>(false, -1);
            }
        }

        public static bool CreateProcessAsUser(string logComponent, WindowsIdentity userId, string appFileName, string appArgs)
        {
            try
            {
                SimpleLog.Log(logComponent, "Create process for: " + userId.Name);
                List<Tuple<uint, string>> userSessions = WindowsUtility.GetUserSessions(logComponent);
                int sessionId = -1;

                foreach (Tuple<uint, string> logonSession in userSessions)
                {
                    if (logonSession.Item2.ToLower().Equals(userId.Name.ToLower()))
                    {
                        sessionId = (int)logonSession.Item1;
                        break;
                    }
                }

                if (sessionId == -1)
                {
                    SimpleLog.Log(logComponent, "Failed to match any/existing logon session with user [" + userId.Name + "].", SimpleLog.MsgType.ERROR);
                    return false;
                }

                if (!NativeMethods.WTSQueryUserToken((uint)sessionId, out IntPtr hUserToken))
                {
                    SimpleLog.Log(logComponent, "Failed to query user token [WTSQueryUserToken=" + Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                    return false;
                }

                // Obtain duplicated user token (elevated if UAC is turned on/enabled)
                IntPtr hDuplicateToken = WindowsUtility.DuplicateToken(logComponent, hUserToken, (uint)sessionId);
                Marshal.FreeHGlobal(hUserToken);

                // Initialize process info and startup info
                NativeMethods.PROCESS_INFORMATION pi = new NativeMethods.PROCESS_INFORMATION();
                NativeMethods.STARTUPINFO si = new NativeMethods.STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.lpDesktop = "winsta0\\default";
                NativeMethods.SECURITY_ATTRIBUTES lpProcessAttributes = new NativeMethods.SECURITY_ATTRIBUTES();
                NativeMethods.SECURITY_ATTRIBUTES lpThreadAttributes = new NativeMethods.SECURITY_ATTRIBUTES();
                IntPtr hEnvironment = IntPtr.Zero;

                if (!NativeMethods.CreateEnvironmentBlock(out hEnvironment, hDuplicateToken, true))
                {
                    SimpleLog.Log(logComponent, "Unable to create environment block [CreateEnvironmentBlock=" + Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.WARN);
                }

                if (!NativeMethods.CreateProcessAsUser(
                    hDuplicateToken,
                    null,
                    appFileName + " " + appArgs,
                    ref lpProcessAttributes,
                    ref lpThreadAttributes,
                    false,
                    (uint)NativeMethods.CreateProcessFlags.NORMAL_PRIORITY_CLASS |
                    (uint)NativeMethods.CreateProcessFlags.CREATE_UNICODE_ENVIRONMENT |
                    (uint)NativeMethods.CreateProcessFlags.CREATE_NEW_CONSOLE,
                    hEnvironment,
                    FileSystem.ParsePath(appFileName),
                    ref si,
                    out pi))
                {
                    SimpleLog.Log(logComponent, "ERROR: Unable to create user process [CreateProcessAsUser=" + Marshal.GetLastWin32Error().ToString() + "].");
                    return false;
                }
                else
                {
                    SimpleLog.Log(logComponent, "Created new process: " + pi.dwProcessId.ToString() + "/" + appFileName + " " + appArgs);
                    var newProcess = System.Diagnostics.Process.GetProcessById(pi.dwProcessId);

                    try
                    {
                        // For UI apps, wait for idle state, before continuing.
                        newProcess.WaitForInputIdle(2000);
                    }
                    catch (InvalidOperationException)
                    {
                        // Must be a non-UI app, just give it a sec to start.
                        Thread.Sleep(1000);
                    }

                    return true;
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to create process as user.");
                return false;
            }
        }

        public static string GetInstanceNameForProcessId(int processId)
        {
            var process = System.Diagnostics.Process.GetProcessById(processId);
            string processName = Path.GetFileNameWithoutExtension(process.ProcessName);
            PerformanceCounterCategory cat = new PerformanceCounterCategory("Process");

            // Get all instances that match the process by name
            string[] instances = cat.GetInstanceNames()
                .Where(inst => inst.StartsWith(processName))
                .ToArray();

            foreach (string instance in instances)
            {
                using (PerformanceCounter cnt = new PerformanceCounter("Process", "ID Process", instance, true))
                {
                    int val = (int)cnt.RawValue;

                    if (val == processId)
                    {
                        return instance;
                    }
                }
            }

            return null;
        }

        public static bool IsProcessRunning(string logComponent, string processFriendlyName, bool moreInfo = false)
        {
            processFriendlyName = FileSystem.ParseFriendlyname(processFriendlyName);

            foreach (System.Diagnostics.Process runningProcess in System.Diagnostics.Process.GetProcesses())
            {
                if (runningProcess.ProcessName.ToLower().Equals(processFriendlyName.ToLower()))
                {
                    if (moreInfo)
                    {
                        string commandLine = null;

                        try
                        {
                            var wmiQuery = new ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId='" + runningProcess.Id.ToString() + "'");

                            foreach (ManagementObject wmiProcess in wmiQuery.Get())
                            {
                                commandLine = wmiProcess["CommandLine"].ToString();
                            }

                            wmiQuery.Dispose();
                        }
                        catch (Exception)
                        {
                            commandLine = "unavailable";
                        }

                        SimpleLog.Log(logComponent, "IsProcessRunning() found: " + runningProcess.Id.ToString() + "/" + runningProcess.ProcessName + " [" + commandLine + "]");

                        try
                        {
                            int currentID = runningProcess.Id;

                            List<uint> loopSafety = new List<uint>
                            {
                                (uint)currentID
                            };

                            // Iterate no more than the process count, divided by 2
                            for (int i = 0; i <= System.Diagnostics.Process.GetProcesses().Count() / 2; i++)
                            {
                                var wmiQuery = new ManagementObjectSearcher("SELECT ParentProcessId FROM Win32_Process WHERE ProcessId=" + currentID);
                                var wmiResult = wmiQuery.Get().GetEnumerator();
                                wmiResult.MoveNext();
                                var queryObj = wmiResult.Current;
                                var parentId = (uint)queryObj["ParentProcessId"]; // Query PPID

                                wmiQuery.Dispose();
                                wmiResult.Dispose();
                                queryObj.Dispose();

                                if (int.TryParse(parentId.ToString(), out int result))
                                {
                                    break; // Invalid PPID
                                }

                                if (loopSafety.Contains(parentId))
                                {
                                    break; // Loop safety
                                }
                                else
                                {
                                    loopSafety.Add(parentId);
                                }

                                try
                                {
                                    string parentName = System.Diagnostics.Process.GetProcessById((int)parentId).ProcessName;
                                    SimpleLog.Log(logComponent, "IsProcessRunning() parent: " + parentId.ToString() + "/" + parentName);
                                    currentID = (int)parentId;
                                }
                                catch (ArgumentException)
                                {
                                    break;
                                }
                            }
                        }
                        catch (Exception) { }
                    }

                    runningProcess.Dispose();
                    return true;
                }

                runningProcess.Dispose();
            }

            return false;
        }

        public static int IsProcessRunningCount(string processFriendlyName)
        {
            int processCount = 0;
            processFriendlyName = FileSystem.ParseFriendlyname(processFriendlyName);

            foreach (System.Diagnostics.Process runningProcess in System.Diagnostics.Process.GetProcesses())
            {
                if (runningProcess.ProcessName.ToLower().Equals(processFriendlyName.ToLower()))
                {
                    processCount += 1;
                }

                runningProcess.Dispose();
            }

            return processCount;
        }

        public static bool KillProcess(string logComponent, string friendlyOrShortName, bool moreInfo = false)
        {
            bool matchFound = false;

            // ******************************
            // Match Process by Friendly Name [myApp].
            // ******************************

            try
            {
                foreach (System.Diagnostics.Process runningProcess in System.Diagnostics.Process.GetProcesses())
                {
                    if (runningProcess.ProcessName.ToLower().Equals(friendlyOrShortName.ToLower()))
                    {
                        matchFound = true;
                        string commandLine = null;

                        if (moreInfo)
                        {
                            try
                            {
                                var wmiQuery = new ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId='" + 
                                    runningProcess.Id.ToString() + "'");

                                foreach (ManagementObject wmiProcess in wmiQuery.Get())
                                {
                                    commandLine = wmiProcess["CommandLine"].ToString();
                                }

                                wmiQuery.Dispose();
                            }
                            catch (Exception)
                            {
                                commandLine = "unavailable";
                            }
                        }

                        runningProcess.Kill();

                        if (moreInfo)
                        {
                            SimpleLog.Log(logComponent, "Killed: " + runningProcess.Id.ToString() + "/" + runningProcess.MainModule.FileName + " [" + commandLine + "]");
                        }
                        else
                        {
                            SimpleLog.Log(logComponent, "Killed: " + runningProcess.Id.ToString() + "/" + runningProcess.MainModule.FileName);
                        }
                    }

                    runningProcess.Dispose();
                }

                if (matchFound)
                {
                    return matchFound;
                }
            }
            catch (Exception) { }

            // ******************************
            // Match Process by Shortname [myApp.exe].
            // ******************************

            try
            {
                var wmiQuery = new ManagementObjectSearcher("SELECT ProcessID FROM Win32_Process WHERE Name='" + friendlyOrShortName + "'");

                foreach (ManagementObject wmiProcess in wmiQuery.Get())
                {
                    string processId = null;

                    if (wmiProcess["ProcessID"] != null)
                    {
                        processId = wmiProcess["ProcessID"].ToString();
                        wmiProcess.Dispose();
                    }
                    else
                    {
                        wmiProcess.Dispose();
                        continue; // Skip -- Missing required attribute[ProcessID]
                    }

                    matchFound = true;
                    KillProcess(logComponent, int.Parse(processId), moreInfo);
                }

                wmiQuery.Dispose();
            }
            catch (Exception) { }

            return matchFound;
        }

        public static bool KillProcess(string logComponent, int processID, bool moreInfo = false)
        {
            try
            {
                foreach (System.Diagnostics.Process runningProcess in System.Diagnostics.Process.GetProcesses())
                {
                    if (runningProcess.Id == processID)
                    {
                        string commandLine = null;

                        if (moreInfo)
                        {
                            try
                            {
                                var wmiQuery = new ManagementObjectSearcher("SELECT CommandLine FROM Win32_Process WHERE ProcessId='" +
                                    runningProcess.Id.ToString() + "'");

                                foreach (ManagementObject wmiProcess in wmiQuery.Get())
                                {
                                    commandLine = wmiProcess["CommandLine"].ToString();
                                }

                                wmiQuery.Dispose();
                            }
                            catch (Exception)
                            {
                                commandLine = "unavailable";
                            }
                        }

                        runningProcess.Kill();

                        if (moreInfo)
                        {
                            SimpleLog.Log(logComponent, "Killed: " + runningProcess.Id.ToString() + "/" + runningProcess.MainModule.FileName + " [" + commandLine + "]");
                        }
                        else
                        {
                            SimpleLog.Log(logComponent, "Killed: " + runningProcess.Id.ToString() + "/" + runningProcess.MainModule.FileName);
                        }

                        runningProcess.Dispose();
                        return true;
                    }

                    runningProcess.Dispose();
                }
            }
            catch (Exception) { }

            return false;
        }

        public static bool KillProcessByCommandLine(string logComponent, string processShortName, string containsCommandLine, bool moreInfo = false)
        {
            bool matchFound = false;

            try
            {
                var wmiQuery = new ManagementObjectSearcher("SELECT ProcessID,CommandLine FROM Win32_Process WHERE Name='" + processShortName + "'");

                foreach (ManagementObject wmiProcess in wmiQuery.Get())
                {
                    string processId = null;
                    string commandLine = null;

                    if (wmiProcess["ProcessID"] != null && wmiProcess["CommandLine"] != null)
                    {
                        processId = wmiProcess["ProcessID"].ToString();
                        commandLine = wmiProcess["CommandLine"].ToString();
                        wmiProcess.Dispose();
                    }
                    else
                    {
                        wmiProcess.Dispose();
                        continue; // Skip -- Missing required attribute[CommandLine]
                    }

                    if (commandLine != null && commandLine.ToLower().Contains(containsCommandLine.ToLower()))
                    {
                        matchFound = true;
                        KillProcess(logComponent, int.Parse(processId), moreInfo);
                    }
                }

                wmiQuery.Dispose();
            }
            catch (Exception) { }

            return matchFound;
        }

        public static bool KillProcessByPath(string logComponent, string processShortName, string processPathContains)
        {
            bool processFound = false;

            try
            {
                var wmiQuery = new ManagementObjectSearcher("SELECT ProcessID,ExecutablePath FROM Win32_Process WHERE Name='" + processShortName + "'");

                foreach (ManagementObject wmiProcess in wmiQuery.Get())
                {
                    string processId = null;
                    string executablePath = null;

                    if (wmiProcess["ProcessID"] != null && wmiProcess["ExecutablePath"] != null)
                    {
                        processId = wmiProcess["ProcessID"].ToString();
                        executablePath = wmiProcess["ExecutablePath"].ToString();
                        wmiProcess.Dispose();
                    }
                    else
                    {
                        wmiProcess.Dispose();
                        continue; // Skip -- Missing required attribute [ExecutablePath]
                    }

                    if (executablePath != null && executablePath.ToLower().Contains(processPathContains.ToLower()))
                    {
                        processFound = true;
                        KillProcess(logComponent, int.Parse(processId));
                    }
                }

                wmiQuery.Dispose();
            }
            catch (Exception) { }

            return processFound;
        }

        public static string ReadProcessList()
        {
            List<string[]> runningProcesses = new List<string[]>();
            string[] outputHeader = { "Process", "PID", "User", "CPU Time", "Memory", "Handles", "Threads", "Command Line" };
            runningProcesses.Add(outputHeader);

            foreach (System.Diagnostics.Process p in System.Diagnostics.Process.GetProcesses())
            {
                try
                {
                    var pi = new ProcessInfo(p);
                    runningProcesses.Add(pi.ToStringArray());
                    p.Dispose();
                }
                catch (Exception) { }
            }

            return DotNetHelpers.PadListElements(runningProcesses, 1);
        }

        public static Tuple<long, string> RunProcessEx(
            string logComponent,
            string appFileName,
            string arguments = "",
            string workingDirectory = "",
            int execTimeoutSeconds = Timeout.Infinite,
            bool hideWindow = false,
            bool hideStreamOutput = false,
            bool hideExecution = false)
        {
            // ******************************
            // Resolve Explicit Path of App to Run.
            // ******************************

            try
            {
                // Is a relative path to the filename provided?
                if (appFileName.Contains("\\") && !appFileName.Contains(":\\"))
                {
                    // Relative path starts with a backslash?
                    if (appFileName.StartsWith("\\"))
                    {
                        // Pre-pend our path (WITHOUT a trailing '\')
                        appFileName = AppAPI.ProcessFilePath + appFileName;
                    }
                    else
                    {
                        // Pre-pend our path (WITH a trailing '\')
                        appFileName = AppAPI.ProcessFilePath + "\\" + appFileName;
                    }
                }
                else if (!appFileName.Contains("\\") && !appFileName.Contains(":\\"))
                {
                    // Pre-pend our path (WITH a trailing '\')
                    appFileName = AppAPI.ProcessFilePath + "\\" + appFileName;
                }

                // Application executable exists? Note: File.Exists() accepts relative paths via current working directory
                if (!File.Exists(appFileName) && !File.Exists(appFileName.TrimStart('\\')))
                {
                    // Take a copy of the original string
                    string origAppToExecute = appFileName;

                    // Does the filename contain a backslash (e.g. path to the executable)
                    if (appFileName.Contains("\\"))
                    {
                        // As file does not exist, remove the path to the executable
                        appFileName = appFileName.Substring(appFileName.LastIndexOf("\\") + 1);
                    }

                    // Read PATH enironment variable
                    var pathValues = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine);

                    // Iterate PATH variable
                    foreach (var path in pathValues.Split(';'))
                    {
                        // Build full filename using PATH entry
                        var pathFilename = Path.Combine(path, appFileName);

                        // Does this file exist?
                        if (File.Exists(pathFilename))
                        {
                            // Assign it
                            appFileName = pathFilename;

                            // Break the iteration
                            break;
                        }
                    }

                    // One last check
                    if (!File.Exists(appFileName) && !File.Exists(appFileName.TrimStart('\\')))
                    {
                        // Write debug
                        SimpleLog.Log(logComponent, "ERROR: Application not found [" + origAppToExecute + "].");

                        // Return
                        return Tuple.Create((long)-1, "");
                    }
                }
            }
            catch (Exception e)
            {
                // Write exception.
                SimpleLog.Log(logComponent, e, $"Failed to resolve explicit path for app [{appFileName}].");

                // Return.
                return Tuple.Create((long)-1, "");
            }

            // ******************************
            // Resolve Working Directory.
            // ******************************

            try
            {
                // Working directory provided?
                if (workingDirectory == null || workingDirectory.Equals(""))
                {
                    // Does the specified application contain a path?
                    if (appFileName.Contains("\\"))
                    {
                        // Take the working directory from the application path
                        workingDirectory = FileSystem.ParsePath(appFileName);

                        // Is it valid?
                        if (!Directory.Exists(workingDirectory))
                        {
                            // Just use our processes working directory
                            workingDirectory = AppAPI.ProcessFilePath;
                        }
                    }
                    else
                    {
                        // Just use our processes working directory
                        workingDirectory = AppAPI.ProcessFilePath;
                    }
                }
            }
            catch (Exception e)
            {
                // Write exception.
                SimpleLog.Log(logComponent, e, $"Failed to resolve working directory for app [{appFileName}].");

                // Return.
                return Tuple.Create((long)-1, "");
            }

            // ******************************
            // Prepare New Process.
            // ******************************

            // Create new process.
            System.Diagnostics.Process p = new System.Diagnostics.Process();

            // String for storing combined STDOUT+STDERR from external process.
            List<string> combinedOutput = new List<string>();

            // Async threads for consuming STDOUT/STDERR.
            Thread consumeStdOut = null;
            Thread consumeStdErr = null;

            // Cancellation source for async threads.
            var cts = new CancellationTokenSource();

            try
            {
                // Configure a new process.
                p.StartInfo.FileName = appFileName.Replace("\\\\", "\\");
                p.StartInfo.Arguments = arguments;
                p.StartInfo.WorkingDirectory = workingDirectory;
                p.StartInfo.UseShellExecute = false; // Use CreateProcess() API, *NOT* ShellExecute() API
                p.StartInfo.RedirectStandardOutput = true; // Redirect STDOUT
                p.StartInfo.RedirectStandardError = true; // Redirect STDERR
                p.StartInfo.CreateNoWindow = hideWindow; // Passed into function
                p.StartInfo.Verb = "runas"; // Elevate (note sure if this works with UseShellExecute=false)

                // Is STDOUT/STDERR being suppressed?
                if (hideStreamOutput)
                {
                    p.StartInfo.RedirectStandardOutput = false; // Don't redirect STDOUT.
                    p.StartInfo.RedirectStandardError = false; // Don't redirect STDERR.
                }

                // Hide execution?
                if (!hideExecution)
                {
                    // Write debug.
                    SimpleLog.Log(logComponent, "Create process: " + appFileName + " " + arguments + " [Timeout=" + execTimeoutSeconds.ToString() + "s]");
                }
            }
            catch (Exception e)
            {
                // Write exception.
                SimpleLog.Log(logComponent, e, $"Failed to prepare new process for execution [{appFileName}].");

                // Return.
                return Tuple.Create((long)-1, "");
            }

            // ******************************
            // Start New Process.
            // ******************************

            try
            {
                // Start the process.
                p.Start();

                // Capture STDOUT/STDERR?
                if (!hideStreamOutput)
                {
                    // Create async threads for consuming the STDOUT/STDERR streams.
                    consumeStdOut = new Thread(async () =>
                    {
                        // Ensure the thread awaits the result of ConsumeReader().
                        await ConsumeReader(logComponent, p.StandardOutput, combinedOutput, hideStreamOutput, hideExecution, cts.Token);
                    });
                    consumeStdErr = new Thread(async () =>
                    {
                        // Ensure the thread awaits the result of ConsumeReader().
                        await ConsumeReader(logComponent, p.StandardError, combinedOutput, hideStreamOutput, hideExecution, cts.Token);
                    });

                    // Start async threads.
                    consumeStdOut.Start();
                    consumeStdErr.Start();
                }
            }
            catch (Exception e)
            {
                // Write exception.
                SimpleLog.Log(logComponent, e, "Failed to start new process.");

                // Return.
                return Tuple.Create((long)-1, "");
            }

            // ******************************
            // Monitor Process -- Wait for Process Exit or Timeout.
            // ******************************

            try
            {
                // Timeout specified?
                if (execTimeoutSeconds >= 0)
                {
                    // Adjust timeout (seconds --> milliseconds).
                    execTimeoutSeconds *= 1000;
                }

                // Wait the specified timeout for the process to exit.
                p.WaitForExit(execTimeoutSeconds);

                // Check if the process is still running?
                if (!p.HasExited)
                {
                    // Timeout breach -- kill the process.
                    p.Kill();

                    // Write debug.
                    SimpleLog.Log(logComponent, "Killed: " + FileSystem.ParseShortname(appFileName) + " [Timeout breached]");
                }
                else
                {
                    // Is the child process a batch file?
                    if (appFileName.ToLower().EndsWith(".bat") || appFileName.ToLower().EndsWith(".cmd"))
                    {
                        // Signal task cancellation for STDOUT/STDERR streams.
                        // Note: This is because batch files, if nested, automatically inherit STDOUT/STDERR
                        //       handles. Thus if the immediate child batch file has terminated, we need to
                        //       signal the ConsumeReader() threads to abort, so RunProcessEx() can continue.
                        cts.Cancel();
                    }

                    // Wait for async threads to stop.
                    if (consumeStdOut != null) consumeStdOut.Join();
                    if (consumeStdErr != null) consumeStdErr.Join();
                }

                // Save the exit code.
                int ExitCode = p.ExitCode;

                // Hide execution?
                if (!hideExecution)
                {
                    // Write debug.
                    SimpleLog.Log(logComponent, FileSystem.ParseShortname(appFileName) + " return code: " + ExitCode.ToString());
                }

                // Dispose resources.
                cts.Dispose();
                p.Dispose();

                // Return tuple of (Return Code, Copy of Combined output)
                return Tuple.Create((long)ExitCode, String.Join(Environment.NewLine, combinedOutput.ToList()));
            }
            catch (Exception e)
            {
                // Write exception.
                SimpleLog.Log(logComponent, e, "New process monitoring failure.");

                // Return.
                return Tuple.Create((long)-1, "");
            }
        }

        private async static Task ConsumeReader(string logComponent,
            TextReader reader,
            List<string> combinedOutput,
            bool hideStreamOutput,
            bool hideExecution,
            CancellationToken cancelToken)
        {
            try
            {
                string textLine;

                while (!cancelToken.IsCancellationRequested &&
                    (textLine = await reader.ReadLineAsync()) != null)
                {
                    combinedOutput.Add(textLine);

                    if (!hideStreamOutput && !hideExecution)
                    {
                        Logger.WriteDebug(textLine);
                    }
                }

                return;
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Async read operation failure.");
                return;
            }
        }

        public static bool RunProcessDetached(
            string logComponent,
            string appFileName,
            string arguments,
            string workingDirectory = "",
            bool hideWindow = false,
            bool hideExecution = false)
        {
            // Is a relative path to the filename provided?
            if (appFileName.Contains("\\") && !appFileName.Contains(":\\"))
            {
                // Relative path starts with a backslash?
                if (appFileName.StartsWith("\\"))
                {
                    // Pre-pend our path (WITHOUT a trailing '\')
                    appFileName = AppAPI.ProcessFilePath + appFileName;
                }
                else
                {
                    // Pre-pend our path (WITH a trailing '\')
                    appFileName = AppAPI.ProcessFilePath + "\\" + appFileName;
                }
            }
            else if (!appFileName.Contains("\\") && !appFileName.Contains(":\\"))
            {
                // Pre-pend our path (WITH a trailing '\')
                appFileName = AppAPI.ProcessFilePath + "\\" + appFileName;
            }

            // Application executable exists? Note: File.Exists() accepts relative paths via current working directory
            if (!File.Exists(appFileName) && !File.Exists(appFileName.TrimStart('\\')))
            {
                // Take a copy of the original string
                string origAppToExecute = appFileName;

                // Does the filename contain a backslash (e.g. path to the executable)
                if (appFileName.Contains("\\"))
                {
                    // As file does not exist, remove the path to the executable
                    appFileName = appFileName.Substring(appFileName.LastIndexOf("\\") + 1);
                }

                // Read PATH enironment variable
                var pathValues = Environment.GetEnvironmentVariable("PATH", EnvironmentVariableTarget.Machine);

                // Iterate PATH variable
                foreach (var path in pathValues.Split(';'))
                {
                    // Build full filename using PATH entry
                    var pathFilename = Path.Combine(path, appFileName);

                    // Does this file exist?
                    if (File.Exists(pathFilename))
                    {
                        // Assign it
                        appFileName = pathFilename;

                        // Break the iteration
                        break;
                    }
                }

                // One last check
                if (!File.Exists(appFileName) && !File.Exists(appFileName.TrimStart('\\')))
                {
                    // Write debug
                    SimpleLog.Log(logComponent, "ERROR: Application not found [" + origAppToExecute + "].");

                    // Return
                    return false;
                }
            }

            // Working directory provided?
            if (workingDirectory == null || workingDirectory.Equals(""))
            {
                // Does the specified application contain a path?
                if (appFileName.Contains("\\"))
                {
                    // Take the working directory from the application path
                    workingDirectory = FileSystem.ParsePath(appFileName);

                    // Is it valid?
                    if (!Directory.Exists(workingDirectory))
                    {
                        // Just use our processes working directory
                        workingDirectory = AppAPI.ProcessFilePath;
                    }
                }
                else
                {
                    // Just use our processes working directory
                    workingDirectory = AppAPI.ProcessFilePath;
                }
            }

            // Create and configure a new process
            System.Diagnostics.Process p = new System.Diagnostics.Process();
            p.StartInfo.FileName = appFileName.Replace("\\\\", "\\");
            p.StartInfo.Arguments = arguments;
            p.StartInfo.WorkingDirectory = workingDirectory;
            p.StartInfo.UseShellExecute = false; // Use CreateProcess() API, *NOT* ShellExecute() API
            p.StartInfo.CreateNoWindow = hideWindow; // Passed into function
            p.StartInfo.Verb = "runas"; // Elevate (note sure if this works with UseShellExecute=false)

            // Hide execution?
            if (!hideExecution)
            {
                // Write debug
                SimpleLog.Log(logComponent, "Execute [Detached]: " + appFileName + " " + arguments);
            }

            try
            {
                // Start the process
                p.Start();

                // Write debug
                SimpleLog.Log(logComponent, "Created detached process: " + p.Id.ToString() + "/" + appFileName.Replace("\\\\", "\\") + " " + arguments);

                // Brief delay for app startup, before continuing.
                // Note: This is for the scenario where the parent app (this app)
                //       is up against termination. We need to pause briefly to
                //       allow the child process to establish before continuing.
                Thread.Sleep(3000);

                // We used to do it this way, but WaitForInputIdle only works
                // for UI apps, and not batch or console apps. Adding a simple
                // delay accomplishes the same, but leaving this code for
                // reference, in case anyone gets any bright ideas.
                /*try
                {
                    // For UI apps, wait for idle state, before continuing.
                    p.WaitForInputIdle(2000);

                    // Wait short delay before continuing.
                    p.WaitForExit(3000);
                }
                catch (InvalidOperationException)
                {
                    // Must be a non-UI app, just give it a sec to start.
                    Thread.Sleep(5000);
                }*/
            }
            catch (Exception e)
            {
                // Write exception.
                SimpleLog.Log(logComponent, e, "Failed to start new detached process.");

                // Return.
                return false;
            }

            // Return.
            return true;
        }
    }
}