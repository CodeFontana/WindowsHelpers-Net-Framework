using SimpleLogger;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.ServiceProcess;

namespace WindowsNative
{
    public static class ServiceHelper
    {
        public enum ServiceStart // For reference.
        {
            Boot = 0,
            System = 1,
            Automatic = 2,
            Manual = 3,
            Disabled = 4
        }

        public static bool ChangeLogonUser(string logComponent, string serviceName, string logonUser, string logonPassword)
        {
            /* Built-in logonUsers:
             *   Local Service: logonUser="nt authority\\localservice"  logonPassword=""
             *   Local System:  logonUser=".\\localsystem"              logonPassword=""
             */

            IntPtr scManagerHandle = IntPtr.Zero;
            IntPtr serviceHandle = IntPtr.Zero;

            try
            {
                scManagerHandle = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_ALL_ACCESS);

                if (scManagerHandle == IntPtr.Zero)
                {
                    SimpleLog.Log(logComponent, "Unable to open service control manager.", SimpleLog.MsgType.ERROR);
                    return false;
                }

                serviceHandle = NativeMethods.OpenService(
                    scManagerHandle,
                    serviceName,
                    NativeMethods.SERVICE_QUERY_CONFIG | NativeMethods.SERVICE_CHANGE_CONFIG);

                if (serviceHandle == IntPtr.Zero)
                {
                    SimpleLog.Log(logComponent, "Unable to open specified service [" + serviceName + "].", SimpleLog.MsgType.ERROR);
                    return false;
                }

                var configSuccess = NativeMethods.ChangeServiceConfig(
                    serviceHandle,
                    NativeMethods.SERVICE_NO_CHANGE,
                    NativeMethods.SERVICE_NO_CHANGE,
                    NativeMethods.SERVICE_NO_CHANGE,
                    null,
                    null,
                    IntPtr.Zero,
                    null,
                    logonUser,
                    logonPassword,
                    null);

                if (!configSuccess)
                {
                    SimpleLog.Log(logComponent, "Unable to configure service logon user [ChangeServiceConfig=" +
                        Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                    return false;
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to change service logon user.");
            }
            finally
            {
                if (serviceHandle != IntPtr.Zero)
                    NativeMethods.CloseServiceHandle(serviceHandle);
                if (scManagerHandle != IntPtr.Zero)
                    NativeMethods.CloseServiceHandle(scManagerHandle);
            }

            return true;
        }

        public static bool ChangeStartMode(string logComponent, string serviceName, ServiceStartMode startMode)
        {
            IntPtr scManagerHandle = IntPtr.Zero;
            IntPtr serviceHandle = IntPtr.Zero;

            try
            {
                scManagerHandle = NativeMethods.OpenSCManager(null, null, NativeMethods.SC_MANAGER_ALL_ACCESS);

                if (scManagerHandle == IntPtr.Zero)
                {
                    SimpleLog.Log(logComponent, "Unable to open service control manager.", SimpleLog.MsgType.ERROR);
                    return false;
                }

                serviceHandle = NativeMethods.OpenService(
                    scManagerHandle,
                    serviceName,
                    NativeMethods.SERVICE_QUERY_CONFIG | NativeMethods.SERVICE_CHANGE_CONFIG);

                if (serviceHandle == IntPtr.Zero)
                {
                    SimpleLog.Log(logComponent, "Unable to open specified service [" + serviceName + "].", SimpleLog.MsgType.ERROR);
                    return false;
                }

                var configSuccess = NativeMethods.ChangeServiceConfig(
                    serviceHandle,
                    NativeMethods.SERVICE_NO_CHANGE,
                    (uint)startMode,
                    NativeMethods.SERVICE_NO_CHANGE,
                    null,
                    null,
                    IntPtr.Zero,
                    null,
                    null,
                    null,
                    null);

                if (!configSuccess)
                {
                    SimpleLog.Log(logComponent, "Unable to configure service startup mode [ChangeServiceConfig=" +
                        Marshal.GetLastWin32Error().ToString() + "].", SimpleLog.MsgType.ERROR);
                    return false;
                }
            }
            catch (Exception e)
            {
                SimpleLog.Log(logComponent, e, "Failed to change service startup mode.");
            }
            finally
            {
                if (serviceHandle != IntPtr.Zero)
                    NativeMethods.CloseServiceHandle(serviceHandle);
                if (scManagerHandle != IntPtr.Zero)
                    NativeMethods.CloseServiceHandle(scManagerHandle);
            }

            return true;
        }

        public static bool ServiceExists(string serviceName)
        {
            ServiceController[] sc = ServiceController.GetServices();
            var service = sc.FirstOrDefault(s => s.ServiceName.ToLower() == serviceName.ToLower());
            return service != null;
        }
    }
}