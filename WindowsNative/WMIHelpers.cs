﻿using LoggerLibrary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;

namespace WindowsLibrary
{
    public class WMIHelper
    {
        private Logger _logger;

        public WMIHelper(Logger logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Quick sample usages for the WMI helpers to obtain system information.
        /// </summary>
        public static void SampleUsage()
        {
            var logFile = new Logger("WMI_Sample_Usage");
            WMIHelper wmi = new WMIHelper(logFile);

            // EXAMPLE: Get Manufacturer + Model info.
            logFile.Log("Example: Win32_ComputerSystem [Manufacturer and Model]\n");
            List<string[]> wmiData = wmi.GetWMIData("root\\cimv2", "Win32_ComputerSystem", new List<string> { "Manufacturer", "Model" });
            logFile.Log($"Manufacturer: {wmiData[1][0]}");
            logFile.Log($"Model: {wmiData[1][1]}");

            // EXAMPLE: Get all columns.
            logFile.Log("Example: Win32_QuickFixEngineering [ALL COLUMNS]\n" +
                wmi.GetFormattedWMIData(
                    "root\\cimv2",
                    "Win32_QuickFixEngineering",
                    null));

            // EXAMPLE: Get specified columns.
            logFile.Log("Example: Win32_QuickFixEngineering [SPECIFIC COLUMNS]\n" +
                wmi.GetFormattedWMIData(
                    "root\\cimv2",
                    "Win32_QuickFixEngineering",
                    new List<string> { "HotFixID", "Description", "InstalledOn", "Caption" },
                    4));

            logFile.Close();
        }

        /// <summary>
        /// Gets the available WMI namespaces for the specified management scope.
        /// </summary>
        /// <param name="rootPath">WMI Management Scope path. Default is "root".</param>
        /// <returns>Returns a list of available WMI namespaces.</returns>
        public List<string> GetWmiNamespaces(string rootPath = "root")
        {
            var namespaces = new List<string>();

            try
            {
                ManagementClass nsClass = new ManagementClass(new ManagementScope(rootPath), new ManagementPath("__namespace"), null);

                foreach (ManagementObject ns in nsClass.GetInstances())
                {
                    string namespaceName = rootPath + "\\" + ns["Name"].ToString();
                    namespaces.Add(namespaceName);
                    namespaces.AddRange(GetWmiNamespaces(namespaceName));
                }
            }
            catch (Exception e)
            {
                _logger.Log(e, "Failed to query list of WMI namespaces.");
            }

            return namespaces?.OrderBy(s => s).ToList() ?? namespaces;
        }

        /// <summary>
        /// Gets the available WMI classes for the specified namespace.
        /// </summary>
        /// <param name="wmiNamespaceName">The WMI namespace for obtaining the class list, e.g. root\\cimv2.</param>
        /// <returns>Returns a list of available classes in the WMI namespace.</returns>
        public List<string> GetClassNamesWithinWmiNamespace(string wmiNamespaceName)
        {
            var classes = new List<string>();

            try
            {
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    new ManagementScope(wmiNamespaceName),
                    new WqlObjectQuery("SELECT * FROM meta_class"));
                ManagementObjectCollection objectCollection = searcher.Get();

                foreach (ManagementClass wmiClass in objectCollection)
                {
                    string stringified = wmiClass.ToString();
                    string[] parts = stringified.Split(new char[] { ':' });
                    classes.Add(parts[1]);
                }
            }
            catch (Exception e)
            {
                _logger.Log(e, $"Failed to query class name list for namespace '{wmiNamespaceName}'.");
            }

            return classes?.OrderBy(s => s).ToList() ?? classes;
        }

        /// <summary>
        /// Gets a list of properties (column names) for the specified WMI class.
        /// </summary>
        /// <param name="namespaceName">The WMI namespace which contains the class, e.g. root\\cimv2.</param>
        /// <param name="wmiClassName">The WMI class for obtaining the properties list.</param>
        /// <returns>A list of properties.</returns>
        public List<string> GetPropertiesOfWmiClass(string namespaceName, string wmiClassName)
        {
            var output = new List<string>();

            try
            {
                ManagementPath managementPath = new ManagementPath();
                managementPath.Path = namespaceName;
                ManagementScope managementScope = new ManagementScope(managementPath);
                ObjectQuery objectQuery = new ObjectQuery($"SELECT * FROM {wmiClassName}");
                ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(managementScope, objectQuery);
                ManagementObjectCollection objectCollection = objectSearcher.Get();

                foreach (ManagementObject obj in objectCollection)
                {
                    PropertyDataCollection props = obj.Properties;

                    foreach (PropertyData p in props)
                    {
                        output.Add(p.Name);
                    }

                    break;
                }
            }
            catch (Exception e)
            {
                _logger.Log(e, $"Failed to query properties of specified class '{namespaceName}\\{wmiClassName}'.");
            }

            return output;
        }

        /// <summary>
        /// Gets a list of WMI data, including property names, for the specified WMI class.
        /// </summary>
        /// <param name="namespaceName">The WMI namespace which contains the class, e.g. root\\cimv2.</param>
        /// <param name="wmiClassName">The WMI class for obtaining the properties list.</param>
        /// <param name="columns">The list of columns to retrieve, the default is null/* for all columns.</param>
        /// <returns>A list representing each row of data from the WMI class.</returns>
        public List<string[]> GetWMIData(
            string namespaceName,
            string wmiClassName,
            List<string> columns = null)
        {
            var output = new List<string[]>();

            try
            {
                ManagementPath managementPath = new ManagementPath();
                managementPath.Path = namespaceName;
                ManagementScope managementScope = new ManagementScope(managementPath);
                ObjectQuery objectQuery = new ObjectQuery($"SELECT * FROM {wmiClassName}");

                if (columns == null || columns[0].Equals("*"))
                {
                    objectQuery = new ObjectQuery($"SELECT * FROM {wmiClassName}");
                }
                else
                {
                    objectQuery = new ObjectQuery($"SELECT {string.Join(",", columns)} FROM {wmiClassName}");
                }

                ManagementObjectSearcher searcher = new ManagementObjectSearcher(managementScope, objectQuery);
                ManagementObjectCollection objectCollection = searcher.Get();

                foreach (ManagementObject obj in objectCollection)
                {
                    var row = new List<string>();
                    PropertyDataCollection props = obj.Properties;

                    if (output.Count == 0)
                    {
                        var columnNames = new List<string>();

                        foreach (PropertyData p in props)
                        {
                            columnNames.Add(p.Name);
                        }

                        output.Add(columnNames.ToArray());
                    }

                    foreach (PropertyData p in props)
                    {
                        if (p.Value == null || string.IsNullOrWhiteSpace(p.Value.ToString()))
                        {
                            row.Add("");
                        }
                        else
                        {
                            row.Add(p.Value.ToString());
                        }
                    }

                    output.Add(row.ToArray());
                }

            }
            catch (Exception e)
            {
                _logger.Log(e, $"Failed to query data from '{namespaceName}\\{wmiClassName}'.");
            }

            return output;
        }

        /// <summary>
        /// Gets a formatted list of WMI data, including property names, for the specified WMI class.
        /// </summary>
        /// <param name="namespaceName">The WMI namespace which contains the class, e.g. root\\cimv2.</param>
        /// <param name="wmiClassName">The WMI class for obtaining the properties list.</param>
        /// <param name="columns">The list of columns to retrieve, the default is null/* for all columns.</param>
        /// <param name="columnPadding">Padding (number of spaces) to add between columns of data in the return string.</param>
        /// <returns></returns>
        public string GetFormattedWMIData(
            string namespaceName,
            string wmiClassName,
            List<string> columns = null,
            int columnPadding = 1)
        {
            var output = new List<string[]>();

            try
            {
                ManagementPath managementPath = new ManagementPath();
                managementPath.Path = namespaceName;
                ManagementScope managementScope = new ManagementScope(managementPath);
                ObjectQuery objectQuery = new ObjectQuery($"SELECT * FROM {wmiClassName}");

                if (columns == null || columns[0].Equals("*"))
                {
                    objectQuery = new ObjectQuery($"SELECT * FROM {wmiClassName}");
                }
                else
                {
                    objectQuery = new ObjectQuery($"SELECT {string.Join(",", columns)} FROM {wmiClassName}");
                }

                ManagementObjectSearcher searcher = new ManagementObjectSearcher(managementScope, objectQuery);
                ManagementObjectCollection objectCollection = searcher.Get();

                foreach (ManagementObject obj in objectCollection)
                {
                    var row = new List<string>();
                    PropertyDataCollection props = obj.Properties;

                    if (output.Count == 0)
                    {
                        var columnNames = new List<string>();

                        foreach (PropertyData p in props)
                        {
                            columnNames.Add(p.Name);
                        }

                        output.Add(columnNames.ToArray());
                    }

                    foreach (PropertyData p in props)
                    {
                        if (p.Value == null || string.IsNullOrWhiteSpace(p.Value.ToString()))
                        {
                            row.Add("");
                        }
                        else
                        {
                            row.Add(p.Value.ToString());
                        }
                    }

                    output.Add(row.ToArray());
                }

            }
            catch (Exception e)
            {
                _logger.Log(e, $"Failed to query data from '{namespaceName}\\{wmiClassName}'.");
            }

            return DotNetHelper.GetInstance().PadListElements(output, columnPadding);
        }
    }
}