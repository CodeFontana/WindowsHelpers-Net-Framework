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

        private FileStream _logStream = null;
        private StreamWriter _logWriter = null;
        private readonly object _lockObj = new object();
        private bool _rollMode = false;

        public string LogComponent { get; set; }
        public string LogFilename { get; private set; }
        public string LogFolder { get; private set; } = "";
        public int LogIncrement { get; private set; } = 0;
        public long LogMaxBytes { get; set; } = 50 * 1048576;
        public uint LogMaxCount { get; set; } = 10;

        public enum MsgType { NONE, INFO, DEBUG, WARN, ERROR };

        // For reference:
        //   1 MB = 1000000 Bytes (in decimal)
        //   1 MB = 1048576 Bytes (in binary)

        public SimpleLog(string logName, string logPath = null, long maxBytes = 50 * 1048576, uint maxCount = 10)
        {
            Open(logName, logPath, maxBytes, maxCount);
            Log("####################################################################################################");
            Log($"Log start -- {LogComponent}");
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

            // Set log path.
            if (logPath == null)
            {
                string processName = Process.GetCurrentProcess().MainModule.FileName;
                string processPath = processName.Substring(0, processName.LastIndexOf("\\"));
                LogFolder = processPath;
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

            // Set log properties.
            LogComponent = logName;
            LogMaxBytes = maxBytes;
            LogMaxCount = maxCount;

            // Select next available log increment.
            IncrementLog();

            // Append the log file.
            _logStream = new FileStream(LogFilename, FileMode.Append, FileAccess.Write, FileShare.Read);
            _logWriter = new StreamWriter(_logStream);
            _logWriter.AutoFlush = true;

            // Add to log manager for static reference by component name.
            //   --> This is for static calls to Log() functions.
            //   --> E.g. Calling Log(component) from a Class Library function.
            //   --> Rather than passing around instances of this class, the log
            //       message can route to the correct instance, by calling the
            //       static Log() function, and passing the component name of an
            //       existing instance.
            if (!LogManager.Any(tup => tup.Item1.ToLower().Equals(LogComponent.ToLower())))
            {
                LogManager.Add(new Tuple<string, SimpleLog>(LogComponent, this));
            }
        }

        private void IncrementLog()
        {
            if (!_rollMode)
            {
                // After we find our starting point, we will
                // permanetly be in rollMode, meaning we will
                // always increment/wrap to the next available
                // log increment.
                _rollMode = true;

                // Base case -- Find nearest unfilled log to continue
                //              appending, or nearest unused increment
                //              to start writing a new file.
                for (int i = 0; i < LogMaxCount; i++)
                {
                    string fileName = $"{LogFolder}\\{LogComponent}_{i}.log";

                    if (File.Exists(fileName))
                    {
                        long length = new FileInfo(fileName).Length;

                        if (length < LogMaxBytes)
                        {
                            // Append unfilled log.
                            LogFilename = fileName;
                            LogIncrement = i;
                            return;
                        }
                    }
                    else
                    {
                        // Take this unused increment.
                        LogFilename = fileName;
                        LogIncrement = i;
                        return;
                    }
                }

                // Full house? -- Start over from the top.
                LogFilename = $"{LogFolder}\\{LogComponent}_0.log";
                LogIncrement = 0;
                File.Delete(LogFilename);
            }
            else
            {
                // Inductive case -- We are in roll mode, so we just
                //                   use the next increment file, or
                //                   wrap around to the starting point.
                if (LogIncrement + 1 < LogMaxCount)
                {
                    // Next log increment.
                    LogFilename = $"{LogFolder}\\{LogComponent}_{++LogIncrement}.log";
                    File.Delete(LogFilename);
                }
                else
                {
                    // Start over from the top.
                    LogFilename = $"{LogFolder}\\{LogComponent}_0.log";
                    LogIncrement = 0;
                    File.Delete(LogFilename);
                }
            }
        }

        public bool Close()
        {
            try
            {
                lock (_lockObj)
                {
                    // Write the closing message direct. If you call the Log() function,
                    // this will generate a StackOverflow -- trust me.
                    Console.WriteLine(MsgHeader(LogComponent, MsgType.INFO) + $"Log end -- {LogComponent}");
                    _logWriter.WriteLine(MsgHeader(LogComponent, MsgType.INFO) + $"Log end -- {LogComponent}");
                    
                    Console.WriteLine(MsgHeader(LogComponent, MsgType.INFO) + 
                        "####################################################################################################");
                    _logWriter.Write(MsgHeader(LogComponent, MsgType.INFO) +
                        "####################################################################################################");

                    _logWriter.Dispose();
                    _logStream.Dispose();
                    _logWriter = null;
                    _logStream = null;
                    LogFilename = null;
                    return true;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        private static string MsgHeader(string component, MsgType entryType)
        {
            string header = DateTime.Now.ToString("yyyy-MM-dd--HH.mm.ss|");
            header += component + "|";

            switch (entryType)
            {
                case MsgType.NONE:
                    header += "     |";
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

        /* Instance Log() methods. Typically the main assembly will create and own
         * an instance of the SimpleLog class. It will call member Log() functions
         * to log messages to it's instance. Obvously you can create and use as
         * many instances, for as many log files as you like.
         */

        public void Log(string message, MsgType logLevel = MsgType.INFO)
        {
            if (!string.IsNullOrEmpty(message) && !string.IsNullOrWhiteSpace(message))
            {
                long logSizeBytes = new FileInfo(LogFilename).Length;

                if (logSizeBytes >= LogMaxBytes)
                {
                    Open(LogComponent, LogFolder, LogMaxBytes, LogMaxCount);
                }

                lock (_lockObj)
                {
                    Console.WriteLine(MsgHeader(LogComponent, logLevel) + message);
                    _logWriter.WriteLine(MsgHeader(LogComponent, logLevel) + message);
                }
            }
        }

        public void Log(Exception e, string message)
        {
            long logSizeBytes = new FileInfo(LogFilename).Length;

            if (logSizeBytes >= LogMaxBytes)
            {
                Open(LogComponent, LogFolder, LogMaxBytes, LogMaxCount);
            }

            lock (_lockObj)
            {
                Console.WriteLine(MsgHeader(LogComponent, MsgType.ERROR) + e.Message);
                _logWriter.WriteLine(MsgHeader(LogComponent, MsgType.ERROR) + e.Message);

                if (!string.IsNullOrEmpty(message) && !string.IsNullOrWhiteSpace(message))
                {
                    Console.WriteLine(MsgHeader(LogComponent, MsgType.ERROR) + message);
                    _logWriter.WriteLine(MsgHeader(LogComponent, MsgType.ERROR) + message);
                }
            }
        }

        /* Static Log() methods. Consider the scenario where you have a main assembly and
         * one or more class libraries in your solution. Rather than pass around instances
         * of your SimpleLog for logging purposes, you can call these static functions
         * from within your library methods. When a new instance of SimpleLog is created,
         * it adds a static reference in the public static LogManager. Thus all you have
         * to pass to your class library method calls, is the component name string for
         * your SimpleLog instance. When the static Log() method is called, it will
         * forward the Log() call to the matching instance. Passing a string should save
         * significant memory from passing an entire instance!
         */

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
                Console.WriteLine(MsgHeader(component, logLevel) + message);
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
                Console.WriteLine(MsgHeader(component, MsgType.ERROR) + message);
            }
        }
    }
}