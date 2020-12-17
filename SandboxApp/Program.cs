using System;

namespace SandboxApp
{
    class Program
    {
        static void Main(string[] args)
        {
            // Todo: Sandbox testing code here!
            WindowsNative.PageFile.DisplayConfig("Sandbox");

            Console.WriteLine("Press any key to exit...");
            Console.ReadLine();
        }
    }
}
