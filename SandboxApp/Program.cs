using SimpleLogger;
using System;

namespace SandboxApp
{
    class Program
    {
        static void Main(string[] args)
        {
            SimpleLog mainLog = new SimpleLog("SandboxApp");
            mainLog.Log("Hello, world!");
            mainLog.Close();
            Console.ReadLine();
        }
    }
}
