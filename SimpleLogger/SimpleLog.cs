using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace SimpleLogger
{
    public class SimpleLog
    {
        public static List<Tuple<string, SimpleLog>> LogManager { get; } = new List<Tuple<string, SimpleLog>>();

        protected FileStream _logStream = null;
        protected StreamWriter _logWriter = null;
        private readonly object _lockObj = new object();

        public string LogComponent { get; set; }
        public string LogFilename { get; private set; }
        public string LogFolder { get; private set; } = "";
        public int LogIncrement { get; private set; } = 0;
        public long LogMaxBytes { get; set; } = 50 * 1048576;
        public uint LogMaxCount { get; set; } = 10;

        public enum MsgType { NONE, INFO, DEBUG, WARN, ERROR };

        public SimpleLog(string logName, string logPath = null, long maxBytes = 50 * 1048576, uint maxCount = 10)
        {
            Open(logName, logPath, maxBytes, maxCount);
            Log("##################################################");
            Log("Log start.");
        }

        private void Open(string logName, string logPath = null, long maxBytes = 50 * 1048576, uint maxCount = 10)
        {
            // If open, close the log file.
            if (LogFilename != null &&
                _logWriter != null &&
                _logWriter.BaseStream != null)
            {
                Close();
            }

            string processName = Process.GetCurrentProcess().MainModule.FileName;
            string shortName = processName.Substring(processName.LastIndexOf("\\") + 1);
            string friendlyName = shortName.Substring(0, shortName.LastIndexOf("."));
            string processPath = processName.Substring(0, processName.LastIndexOf("\\"));

            // Resolve path to store log file.
            if (logPath == null)
            {
                LogFolder = logPath = processPath;
            }
            else if (!Directory.Exists(logPath))
            {
                Directory.CreateDirectory(logPath);
                LogFolder = logPath;
            }
            else
            {
                LogFolder = logPath;
            }

            // Set properties
            LogComponent = logName;
            LogMaxBytes = maxBytes;
            LogMaxCount = maxCount;

            // Retrieve sorted directory listing for log file path.
            List<string> localFiles = Directory.GetFiles(LogFolder).OrderBy(f => f).ToList();
            localFiles.RemoveAll(f => !f.ToLower().Contains("\\" + logName.ToLower() + "_") && !f.ToLower().EndsWith(".log"));

            // If any existing log file(s), select first file that is not full.
            if (localFiles.Count > 0)
            {
                for (int i = 0; i < localFiles.Count; i++)
                {
                    long length = new FileInfo(localFiles[i]).Length;

                    if (length < LogMaxBytes)
                    {
                        LogFilename = localFiles[i];
                        LogIncrement = i;
                        break;
                    }
                    else if (length >= LogMaxBytes && (i + 1) >= localFiles.Count && (i + 1) < LogMaxCount)
                    {
                        LogFilename = $"{LogFolder}\\{logName}_{i + 1}.log";
                        LogIncrement = i + 1;
                        break;
                    }
                }
            }

            // If no existing log files, formualte the first one.
            if (LogFilename == null)
            {
                LogFilename = $"{LogFolder}\\{logName}_0.log";
                LogIncrement = 0;
            }

            // Start the log file.
            _logStream = new FileStream(LogFilename, FileMode.Append, FileAccess.Write, FileShare.Read);
            _logWriter = new StreamWriter(_logStream);
            _logWriter.AutoFlush = true;

            // Add to log manager.
            LogManager.Add(new Tuple<string, SimpleLog>(LogComponent, this));
        }

        public bool Close()
        {
            try
            {
                Log("Log end.");
                Log("##################################################");
                _logWriter.Dispose();
                _logStream.Dispose();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static string MsgHeader(MsgType entryType)
        {
            string header = DateTime.Now.ToString("yyyy-MM-dd--HH.mm.ss|");

            switch (entryType)
            {
                case MsgType.NONE:
                    header += "";
                    break;
                case MsgType.INFO:
                    header += " INFO|";
                    break;
                case MsgType.DEBUG:
                    header += "DEBUG|";
                    break;
                case MsgType.WARN:
                    header += " WARN|";
                    break;
                case MsgType.ERROR:
                    header += "ERROR|";
                    break;
            }

            return header;
        }

        public void Log(string message, MsgType logLevel = MsgType.INFO)
        {
            if (!string.IsNullOrEmpty(message) && !string.IsNullOrWhiteSpace(message))
            {
                long logSizeBytes = new FileInfo(LogFilename).Length;

                if (logSizeBytes >= LogMaxBytes)
                {
                    Close();
                    Open(LogComponent, LogFolder, LogMaxBytes, LogMaxCount);
                }

                lock (_lockObj)
                {
                    Console.WriteLine(MsgHeader(logLevel) + message);
                    _logWriter.WriteLine(MsgHeader(logLevel) + message);
                }
            }
        }

        public static void Log(string component, string message, MsgType logLevel = MsgType.INFO) 
        {
            var logger = LogManager
                .Where(l => l.Item1.ToLower().Equals(component.ToLower()))
                .FirstOrDefault();

            if (logger != null)
            {
                logger.Item2.Log(message, logLevel);
            }
            else
            {
                Console.WriteLine(MsgHeader(logLevel) + message);
            }
        }

        public void Log(Exception e, string message)
        {
            long logSizeBytes = new FileInfo(LogFilename).Length;

            if (logSizeBytes >= LogMaxBytes)
            {
                Close();
                Open(LogComponent, LogFolder, LogMaxBytes, LogMaxCount);
            }

            lock (_lockObj)
            {
                Console.WriteLine(MsgHeader(MsgType.ERROR) + e.Message);
                _logWriter.WriteLine(MsgHeader(MsgType.ERROR) + e.Message);

                if (!string.IsNullOrEmpty(message) && !string.IsNullOrWhiteSpace(message))
                {
                    Console.WriteLine(MsgHeader(MsgType.ERROR) + message);
                    _logWriter.WriteLine(MsgHeader(MsgType.ERROR) + message);
                }
            }
        }

        public static void Log(string component, Exception e, string message)
        {
            var logger = LogManager
                .Where(l => l.Item1.ToLower().Equals(component.ToLower()))
                .FirstOrDefault();

            if (logger != null)
            {
                logger.Item2.Log(e, message);
            }
            else
            {
                Console.WriteLine(MsgHeader(MsgType.ERROR) + message);
            }
        }
    }
}