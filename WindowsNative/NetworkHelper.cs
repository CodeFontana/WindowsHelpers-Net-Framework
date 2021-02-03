using LoggerLibrary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;

namespace WindowsLibrary
{
    public class NetworkHelper
    {
        private Logger _logger;

        public NetworkHelper(Logger logger)
        {
            _logger = logger;
        }

        public Tuple<bool, List<string>> ResolveHostToIP(
            string hostAddress, bool hideOutput = false)
        {
            try
            {
                if (Uri.CheckHostName(hostAddress).Equals(UriHostNameType.IPv4))
                {
                    if (!hideOutput)
                    {
                        _logger.Log(hostAddress + " resolved to: " + hostAddress);
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
                                _logger.Log(hostAddress + " resolved to: " + addr.ToString());
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
                    _logger.Log("Unable to resolve: " + hostAddress);
                }

                return new Tuple<bool, List<string>>(false, null);
            }
            catch (Exception e)
            {
                if (!hideOutput)
                {
                    _logger.Log(e, "Address resolution failure.");
                }

                return new Tuple<bool, List<string>>(false, null);
            }
        }

        public string ResolveIPtoHost(string inputAddress, bool hideOutput = false)
        {
            try
            {
                if (Uri.CheckHostName(inputAddress).Equals(UriHostNameType.Dns))
                {
                    if (!hideOutput)
                    {
                        _logger.Log(inputAddress + " reversed to: " + inputAddress);
                    }

                    return inputAddress;
                }

                IPHostEntry HostEntry = Dns.GetHostEntry(IPAddress.Parse(inputAddress));

                if (HostEntry != null)
                {
                    if (!hideOutput)
                    {
                        _logger.Log(inputAddress + " reversed to: " + HostEntry.HostName);
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
                    _logger.Log("Unable to reverse [" + inputAddress + "] to hostname.");
                }

                return null;
            }
            catch (Exception e)
            {
                if (!hideOutput)
                {
                    _logger.Log(e, "Reverse name lookup exception.");
                }

                return null;
            }
        }

        public bool ValidateIPv4(string ipString)
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

        public bool TestURL(string url, TimeSpan timeout)
        {
            _logger.Log("Test URL: " + url + " [Timeout=" + timeout.TotalSeconds + "s]");

            try
            {
                var client = new HttpClient();
                var result = client.GetAsync(url);
                result.Wait(timeout);

                if (result.Status == System.Threading.Tasks.TaskStatus.RanToCompletion)
                {
                    _logger.Log("HTTP Response: " + result.Result.StatusCode.ToString());

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
                    _logger.Log("HTTP Response: TIMEOUT ERROR [" + result.Status.ToString() + "].");
                    return false;
                }
            }
            catch (Exception e)
            {
                _logger.Log(e, "Test connection failed to [" + url + "].");
                return false;
            }
        }
    }
}