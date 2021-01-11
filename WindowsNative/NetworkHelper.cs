using LoggerLibrary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace WindowsLibrary
{
    public static class NetworkHelper
    {
        public static Tuple<bool, List<string>> ResolveHostToIP(string logComponent,
            string hostAddress, bool hideOutput = false)
        {
            try
            {
                if (Uri.CheckHostName(hostAddress).Equals(UriHostNameType.IPv4))
                {
                    if (!hideOutput)
                    {
                        Logger.Log(logComponent, hostAddress + " resolved to: " + hostAddress);
                    }

                    return new Tuple<bool, List<string>>(true, new List<string> { hostAddress });
                }

                bool successFlag = false;
                List<string> addresses = new List<string>();
                IPHostEntry hostEntry = Dns.GetHostEntry(hostAddress);

                if (hostEntry.AddressList.Length > 0)
                {
                    successFlag = true;

                    foreach (IPAddress addr in hostEntry.AddressList)
                    {
                        if (addr.AddressFamily == AddressFamily.InterNetwork)
                        {
                            addresses.Add(addr.ToString());
                            if (!hideOutput)
                            {
                                Logger.Log(logComponent, hostAddress + " resolved to: " + addr.ToString());
                            }
                        }
                    }
                }

                return new Tuple<bool, List<string>>(successFlag, addresses);
            }
            catch (SocketException)
            {
                if (!hideOutput)
                {
                    Logger.Log(logComponent, "Unable to resolve: " + hostAddress);
                }

                return new Tuple<bool, List<string>>(false, null);
            }
            catch (Exception e)
            {
                if (!hideOutput)
                {
                    Logger.Log(logComponent, e, "Address resolution failure.");
                }

                return new Tuple<bool, List<string>>(false, null);
            }
        }

        public static string ResolveIPtoHost(string logComponent, string inputAddress, bool hideOutput = false)
        {
            try
            {
                if (Uri.CheckHostName(inputAddress).Equals(UriHostNameType.Dns))
                {
                    if (!hideOutput)
                    {
                        Logger.Log(logComponent, inputAddress + " reversed to: " + inputAddress);
                    }

                    return inputAddress;
                }

                IPHostEntry HostEntry = Dns.GetHostEntry(IPAddress.Parse(inputAddress));

                if (HostEntry != null)
                {
                    if (!hideOutput)
                    {
                        Logger.Log(logComponent, inputAddress + " reversed to: " + HostEntry.HostName);
                    }

                    return HostEntry.HostName;
                }
                else
                {
                    return null;
                }
            }
            catch (SocketException)
            {
                if (!hideOutput)
                {
                    Logger.Log(logComponent, "Unable to reverse [" + inputAddress + "] to hostname.");
                }

                return null;
            }
            catch (Exception e)
            {
                if (!hideOutput)
                {
                    Logger.Log(logComponent, e, "Reverse name lookup exception.");
                }

                return null;
            }
        }

        public static bool ValidateIPv4(string ipString)
        {
            if (string.IsNullOrWhiteSpace(ipString))
            {
                return false;
            }

            string[] splitValues = ipString.Split('.');

            if (splitValues.Length != 4)
            {
                return false;
            }

            // Return true, only if each octet can be successfully parsed as an 8-bit unsigned integer (byte).
            byte tempForParsing;
            return splitValues.All(r => byte.TryParse(r, out tempForParsing));
        }

        public static bool TestURL(string logComponent, string url, TimeSpan timeout)
        {
            Logger.Log(logComponent, "Test URL: " + url + " [Timeout=" + timeout.TotalSeconds + "s]");

            try
            {
                var client = new HttpClient();
                var result = client.GetAsync(url);
                result.Wait(timeout);

                if (result.Status == System.Threading.Tasks.TaskStatus.RanToCompletion)
                {
                    Logger.Log(logComponent, "HTTP Response: " + result.Result.StatusCode.ToString());

                    if (result.Result.StatusCode == HttpStatusCode.OK)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }
                else
                {
                    Logger.Log(logComponent, "HTTP Response: TIMEOUT ERROR [" + result.Status.ToString() + "].");
                    return false;
                }
            }
            catch (Exception e)
            {
                Logger.Log(logComponent, e, "Test connection failed to [" + url + "].");
                return false;
            }
        }
    }
}