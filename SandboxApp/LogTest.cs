using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using SimpleLogger;
using WindowsNative;

namespace SandboxApp
{
    public static class LogTest
    {
        public static void RolloverTest()
        {
            // Identify process.
            string processName = Process.GetCurrentProcess().MainModule.FileName;
            string processPath = Path.GetDirectoryName(processName);

            // Open log.
            SimpleLog testLog = new SimpleLog("Lorem_Ipsum", processPath, 524288, 5);

            // Randomize.
            var rand = new Random();

            // Test log rollover.
            for (int i = 0; i < 10000; i++)
            {
                testLog.Log(DotNetHelper.LoremIpsum());
                int delay = rand.Next(10, 30);
                Thread.Sleep(delay);
            }

            // Close log.
            testLog.Close();
        }
    }
}
