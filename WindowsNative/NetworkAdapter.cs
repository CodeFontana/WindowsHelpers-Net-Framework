using LoggerLibrary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;

namespace WindowsLibrary
{
    public class NetworkAdapter
    {
        public int AdapterIndex { get; set; }
        public string AdapterName { get; set; }
        public bool AdapterEnabled { get; set; }
        public int AdapterStatusCode { get; set; }
        public string AdapterStatusPhrase { get; set; }
        public string IPAddress { get; set; }
        public string SubnetMask { get; set; }
        public string DefaultGateway { get; set; }
        public bool IsDHCPEnabled { get; set; }

        /*
        NetConnectionStatus (AdapterStatusCode):
            Disconnected (0)
            Connecting (1)
            Connected (2)
            Disconnecting (3)
            Hardware Not Present (4)
            Hardware Disabled (5)
            Hardware Malfunction (6)
            Media Disconnected (7)
            Authenticating (8)
            Authentication Succeeded (9)
            Authentication Failed (10)
            Invalid Address (11)
            Credentials Required (12)
            Other (13–65535)
        */

        public NetworkAdapter(int index, string name, bool enabled, int status)
        {
            AdapterIndex = index;
            AdapterName = name;
            AdapterEnabled = enabled;
            AdapterStatusCode = status;
            FillAdapterStatusPhrase();
        }

        public void FillAdapterStatusPhrase()
        {
            switch (AdapterStatusCode)
            {
                case 0:
                    AdapterStatusPhrase = "DISCONNECTED";
                    break;
                case 1:
                    AdapterStatusPhrase = "CONNECTING";
                    break;
                case 2:
                    AdapterStatusPhrase = "CONNECTED";
                    break;
                case 3:
                    AdapterStatusPhrase = "DISCONNECTING";
                    break;
                case 4:
                    AdapterStatusPhrase = "HARDWARE NOT PRESENT";
                    break;
                case 5:
                    AdapterStatusPhrase = "HARDWARE DISABLED";
                    break;
                case 6:
                    AdapterStatusPhrase = "HARDWARE MALFUNCTION";
                    break;
                case 7:
                    AdapterStatusPhrase = "MEDIA DISCONNECTED";
                    break;
                case 8:
                    AdapterStatusPhrase = "AUTHENTICATING";
                    break;
                case 9:
                    AdapterStatusPhrase = "AUTHENTICATION SUCEEDED";
                    break;
                case 10:
                    AdapterStatusPhrase = "AUTHENTICATION FAILED";
                    break;
                case 11:
                    AdapterStatusPhrase = "INVALID ADDRESS";
                    break;
                case 12:
                    AdapterStatusPhrase = "CREDENTIALS REQUIRED";
                    break;
                default:
                    AdapterStatusPhrase = "UNKNOWN";
                    break;
            }
        }

        public void ChangeStatus(int newCode)
        {
            AdapterStatusCode = newCode;
            FillAdapterStatusPhrase();
        }

        public bool Equals(NetworkAdapter compareAdapter)
        {
            if (AdapterIndex != compareAdapter.AdapterIndex) return false;
            if (AdapterName != compareAdapter.AdapterName) return false;
            return true;
        }

        public bool EnableAdapter(Logger logger)
        {
            try
            {
                var searchProcedure = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE Index = " + AdapterIndex);

                foreach (ManagementObject item in searchProcedure.Get())
                {
                    item.InvokeMethod("Enable", null);
                }

                AdapterEnabled = true;
                return true;
            }
            catch (Exception e)
            {
                logger.Log(e, $"Failed to ENABLE adapter [{ AdapterName }].");
                return false;
            }
        }

        public bool ConfigStaticAddress(Logger logger, string newAddress, string newSubnet, string newGateway)
        {
            try
            {
                var configQuery = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapterConfiguration WHERE Index = " + AdapterIndex.ToString());

                foreach (ManagementObject configResult in configQuery.Get())
                {
                    var EnableStaticAddrMethod = configResult.GetMethodParameters("EnableStatic");
                    EnableStaticAddrMethod["IPAddress"] = new string[] { newAddress };
                    EnableStaticAddrMethod["SubnetMask"] = new string[] { newSubnet };

                    var SetGatewayMethod = configResult.GetMethodParameters("SetGateways");
                    SetGatewayMethod["DefaultIPGateway"] = new string[] { newGateway };
                    SetGatewayMethod["GatewayCostMetric"] = new int[] { 1 };

                    configResult.InvokeMethod("EnableStatic", EnableStaticAddrMethod, null);
                    configResult.InvokeMethod("SetGateways", SetGatewayMethod, null);
                }

                return true;
            }
            catch (Exception e)
            {
                logger.Log(e, $"Failed to configure adapter [{ AdapterName }] for static IP address.");
                return false;
            }
        }
    }
}