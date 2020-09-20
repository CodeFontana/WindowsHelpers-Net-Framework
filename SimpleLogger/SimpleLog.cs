using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;

namespace SimpleLogger
{
    public class SimpleLog
    {
        private static List<Tuple<string, SimpleLog>> _logManager = new List<Tuple<string, SimpleLog>>();
        public static List<Tuple<string, SimpleLog>> LogManager
        {
            get { return _logManager; }
        }

        protected FileStream _logStream = null;
        protected StreamWriter _logWriter = null;
        private readonly object _lockObj = new object();

        private string _logComponent;
        public string LogComponent
        {
            get { return _logComponent; }
            set { _logComponent = value; }
        }

        private string _logFilename;
        public string LogFilename
        {
            get { return _logFilename; }
        }

        private string _logFolder = "";
        public string LogFolder
        {
            get { return _logFolder; }
        }

        private int _logIncrement = 0;
        public int LogIncrement
        {
            get { return _logIncrement; }
        }

        private long _logMaxBytes = 50 * 1048576;
        public long LogMaxBytes
        {
            get { return _logMaxBytes; }
            set { _logMaxBytes = value; }
        }

        private uint _logMaxCount = 10;
        public uint LogMaxCount
        {
            get { return _logMaxCount; }
            set { _logMaxCount = value; }
        }

        public enum MsgType { INFO, DEBUG, WARN, ERROR };

        public SimpleLog(string logName, string logPath = null, long maxBytes = 50 * 1048576, uint maxCount = 10)
        {
            Open(logName, logPath, maxBytes, maxCount);
        }

        private void Open(string logName, string logPath = null, long maxBytes = 50 * 1048576, uint maxCount = 10)
        {
            // If open, close the log file.
            if (LogFilename != null &&
                _logWriter != null &&
                _logWriter.BaseStream != null)
                Close();

            string processName = Process.GetCurrentProcess().MainModule.FileName;
            string shortName = processName.Substring(processName.LastIndexOf("\\") + 1);
            string friendlyName = shortName.Substring(0, shortName.LastIndexOf("."));
            string processPath = processName.Substring(0, processName.LastIndexOf("\\"));

            // DEBUG
            Console.WriteLine(processName);
            Console.WriteLine(shortName);
            Console.WriteLine(friendlyName);
            Console.WriteLine(processPath);

            // Resolve path to store log file.
            if (logPath == null)
            {
                _logFolder = logPath = processPath;
            }
            else if (!Directory.Exists(logPath))
            {
                Directory.CreateDirectory(logPath);
                _logFolder = logPath;
            }
            else
            {
                _logFolder = logPath;
            }

            // Set properties
            _logComponent = logName;
            _logMaxBytes = maxBytes;
            _logMaxCount = maxCount;

            // Retrieve sorted directory listing for log file path.
            List<string> localFiles = Directory.GetFiles(_logFolder).OrderBy(f => f).ToList();
            localFiles.RemoveAll(f => !f.ToLower().Contains("\\" + logName.ToLower() + "_") && !f.ToLower().EndsWith(".log"));

            // If any existing log file(s), select first file that is not full.
            if (localFiles.Count > 0)
            {
                for (int i = 0; i < localFiles.Count; i++)
                {
                    long length = new FileInfo(localFiles[i]).Length;

                    if (length < _logMaxBytes)
                    {
                        _logFilename = localFiles[i];
                        _logIncrement = i;
                        break;
                    }
                    else if (length >= _logMaxBytes && (i + 1) >= localFiles.Count && (i + 1) < _logMaxCount)
                    {
                        _logFilename = $"{_logFolder}\\{logName}_{i + 1}.log";
                        _logIncrement = i + 1;
                        break;
                    }
                }
            }

            // If no existing log files, formualte the first one.
            if (LogFilename == "")
            {
                _logFilename = $"{_logFolder}\\{logName}_0.log";
                _logIncrement = 0;
            }

            // Start the log file.
            _logStream = new FileStream(LogFilename, FileMode.Append, FileAccess.Write, FileShare.Read);
            _logWriter = new StreamWriter(_logStream);
            _logWriter.AutoFlush = true;

            // Add to log manager.
            _logManager.Add(new Tuple<string, SimpleLog>(_logComponent, this));
        }

        public bool Close()
        {
            try
            {
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
                long logSizeBytes = new FileInfo(_logFilename).Length;

                if (logSizeBytes >= _logMaxBytes)
                {
                    Close();
                    Open(_logComponent, _logFolder, _logMaxBytes, _logMaxCount);
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
            var logger = _logManager.Where(l => l.Item1.ToLower().Equals(component.ToLower())).FirstOrDefault();
            if (logger != null)
                logger.Item2.Log(message, logLevel);
            else
                throw new Exception($"Log component {component} does not exist.");
        }

        public void Log(Exception e, string message)
        {
            long logSizeBytes = new FileInfo(_logFilename).Length;

            if (logSizeBytes >= _logMaxBytes)
            {
                Close();
                Open(_logComponent, _logFolder, _logMaxBytes, _logMaxCount);
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
            var logger = _logManager.Where(l => l.Item1.ToLower().Equals(component.ToLower())).FirstOrDefault();
            if (logger != null)
                logger.Item2.Log(e, message);
            else
                throw new Exception($"Log component {component} does not exist.");
        }
    }
}