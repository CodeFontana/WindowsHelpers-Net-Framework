using System;
using System.Collections.Generic;
using System.Management;

namespace WindowsNative
{
    public class NetworkAdapter
    {
        public int AdapterIndex;
        public string AdapterName;
        public bool AdapterEnabled;
        public int AdapterStatusCode;
        public string AdapterStatusPhrase;
        public string IPAddress;
        public string SubnetMask;
        public string DefaultGateway;
        public bool IsDHCPEnabled;

        /*
        NetConnectionStatus (AdapterStatus):
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

        public Tuple<bool, NetworkAdapter> In(List<NetworkAdapter> adapterList)
        {
            Tuple<bool, NetworkAdapter> returnTuple = new Tuple<bool, NetworkAdapter>(false, null);
            
            foreach (NetworkAdapter nic in adapterList)
            {
                if (Equals(nic))
                {
                    returnTuple = new Tuple<bool, NetworkAdapter>(true, nic);
                    break;
                }
            }

            return returnTuple;
        }

        public bool EnableAdapter()
        {
            try
            {
                ManagementObjectSearcher searchProcedure = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter WHERE Index = " + AdapterIndex);

                foreach (ManagementObject item in searchProcedure.Get())
                    item.InvokeMethod("Enable", null);

                AdapterEnabled = true;
                return true;
            }
            catch (Exception e)
            {
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to ENABLE adapter [" + AdapterName + "].");
                return false;
            }
        }

        public bool ConfigStaticAddress(string newAddress, string newSubnet, string newGateway)
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
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to configure adapter [" + AdapterName + "] for static IP address.");
                return false;
            }
        }

        public static List<NetworkAdapter> QueryNetworkAdapters()
        {
            List<NetworkAdapter> adapterList = new List<NetworkAdapter>();
            var adapterQuery = new ManagementObjectSearcher("SELECT NetConnectionId,Index,Name,NetEnabled,NetConnectionStatus FROM Win32_NetworkAdapter WHERE NetConnectionId != NULL");

            foreach (ManagementObject adapterResult in adapterQuery.Get())
            {
                var netConnectionId = adapterResult["NetConnectionId"];

                if (netConnectionId != null && !netConnectionId.ToString().Equals(""))
                {
                    int adapterIndex = int.Parse(adapterResult["Index"].ToString());
                    string adapterName = adapterResult["Name"].ToString();
                    bool adapterEnabled = bool.Parse(adapterResult["NetEnabled"].ToString());
                    int adapterStatus = int.Parse(adapterResult["NetConnectionStatus"].ToString());
                    NetworkAdapter newAdapter = new NetworkAdapter(adapterIndex, adapterName, adapterEnabled, adapterStatus);
                    var configQuery = new ManagementObjectSearcher("SELECT DHCPEnabled,IPAddress,IPSubnet,DefaultIPGateway FROM Win32_NetworkAdapterConfiguration WHERE Index = " + newAdapter.AdapterIndex.ToString());

                    foreach (ManagementObject configResult in configQuery.Get())
                    {
                        try
                        {
                            var rawIsDHCPEnabled = configResult["DHCPEnabled"];
                            var rawCurrentIPAddr = configResult["IPAddress"];
                            var rawCurrentSubnet = configResult["IPSubnet"];
                            var rawCurrentGatewayAddr = configResult["DefaultIPGateway"];

                            if (!bool.TryParse(rawIsDHCPEnabled.ToString(), out newAdapter.IsDHCPEnabled))
                                newAdapter.IsDHCPEnabled = true;

                            if (rawCurrentIPAddr != null)
                                newAdapter.IPAddress = ((string[])rawCurrentIPAddr)[0].ToString();
                            else
                                newAdapter.IPAddress = "<Not configured>";

                            if (rawCurrentSubnet != null)
                                newAdapter.SubnetMask = ((string[])rawCurrentSubnet)[0].ToString();
                            else
                                newAdapter.SubnetMask = "<Not configured>";

                            if (rawCurrentGatewayAddr != null)
                                newAdapter.DefaultGateway = ((string[])rawCurrentGatewayAddr)[0].ToString();
                            else
                                newAdapter.DefaultGateway = "<Not configured>";
                        }
                        catch (Exception e)
                        {
                            Logger.WriteDebug("EXCEPTION: " + e.Message);
                            Logger.WriteDebug("ERROR: Failed to query adapter current configuration for [" + newAdapter.AdapterName + "].");
                        }
                    }

                    adapterList.Add(newAdapter);
                }
            }

            return adapterList;
        }
    }
}