using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using WindowsNative;


namespace SimpleLogger
{
    public class SimpleLog
    {
        private FileStream LogStream = null;
        private StreamWriter LogWriter = null;
        private readonly object lockObj = new object();

        public string LogFilename = "";
        public string LogFolder = "";
        public uint LogIncrement = 0;
        public uint LogFileMaxCount = 10;
        public uint LogFileMaxSize = 50;

        public SimpleLog(string logName, string logPath)
        {




            try
            {
                string processName = Process.GetCurrentProcess().MainModule.FileName;
                Console.WriteLine(FileSystem.ParseFriendlyname(processName));

                var logFiles = Directory.EnumerateFiles(LogFolder)
                    .Where(f => f.StartsWith(LogFolder + "\\" + FileSystem.ParseFriendlyname(processName)))
                    .OrderBy(f => f);

                int logCount = Enumerable.Count(logFiles);

                for (int i = 0; i <= logCount - LogFileMaxCount; i++)
                {
                    FileSystem.DeleteFile(logFiles.ElementAt(i));
                }
            }
            catch (Exception e)
            {
                LogException(e, "ERROR: Failed to clean excess log files.");
            }
        }

        public void Log(string message)
        {
            lock (lockObj)
            {
                if (!string.IsNullOrEmpty(message) && !string.IsNullOrWhiteSpace(message))
                    LogWriter.WriteLine(message);
            }
        }

        public void LogException(Exception e, string message)
        {
            lock (lockObj)
            {
                LogWriter.WriteLine("EXCEPTION: " + e.Message);
                
                if (!string.IsNullOrEmpty(message) && !string.IsNullOrWhiteSpace(message))
                    LogWriter.WriteLine(message);
            }
        }

        public bool Close()
        {
            try
            {
                LogWriter.Dispose();
                LogStream.Dispose();
                return true;
            }
            catch (Exception e)
            {
                return false;
            }
        }
    }
}