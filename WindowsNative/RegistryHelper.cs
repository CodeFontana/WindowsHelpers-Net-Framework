using Microsoft.Win32;
using LoggerLibrary;
using System;
using System.Linq;

namespace WindowsLibrary
{
    public class RegistryHelper
    {
        private Logger _logger;

        public RegistryHelper(Logger logger)
        {
            _logger = logger;
        }

        public void CopyKey(RegistryKey sourceKey, RegistryKey destKey)
        {
            try
            {
                foreach (string regValue in sourceKey.GetValueNames())
                {
                    destKey.SetValue(regValue, sourceKey.GetValue(regValue, regValue, RegistryValueOptions.DoNotExpandEnvironmentNames), sourceKey.GetValueKind(regValue));
                }
            }
            catch (Exception e)
            {
                _logger.Log(e, "Failed to copy registry values from [" + sourceKey.Name + "] to [" + destKey.Name + "].");
            }

            foreach (string strSubKey in sourceKey.GetSubKeyNames())
            {
                try
                {
                    using (RegistryKey regSubKey = sourceKey.OpenSubKey(strSubKey, false))
                    {
                        RegistryKey dstSubKey = destKey.CreateSubKey(strSubKey);
                        CopyKey(regSubKey, dstSubKey);
                        dstSubKey.Dispose();
                    }
                }
                catch (Exception e)
                {
                    _logger.Log(e, "Failed to copy registry subkey [" + strSubKey + "] to destination.");
                }
            }
        }

        public void CopyValue(RegistryKey sourceKey, RegistryKey destKey, string sourceValueName, string destValueName)
        {
            try
            {
                if (sourceKey.GetValue(sourceValueName) == null)
                {
                    _logger.Log("Source value [" + sourceValueName + "] does not exist in [" + sourceKey.Name + "].", Logger.MsgType.ERROR);
                }

                destKey.SetValue(destValueName,
                    sourceKey.GetValue(sourceValueName, sourceValueName, RegistryValueOptions.DoNotExpandEnvironmentNames),
                    sourceKey.GetValueKind(sourceValueName));
            }
            catch (Exception e)
            {
                _logger.Log(e, "Failed to move registry value [" + sourceValueName + "] from [" + sourceKey.Name + "] to [" + destKey.Name + "].");
            }
        }

        public bool DeleteSubKeysWithValue(RegistryHive regHive, string regKey, string valueName, string valueData)
        {
            try
            {
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry32);
                RegistryKey baseKey64 = null;

                if (Environment.Is64BitOperatingSystem)
                {
                    baseKey64 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry64);
                }

                RegistryKey regTest = baseKey32.OpenSubKey(regKey, false);

                // Does the specified key exist?
                if (regTest == null)
                {
                    if (baseKey64 != null)
                    {
                        regTest = baseKey64.OpenSubKey(regKey, false);

                        if (regTest == null)
                        {
                            return false;
                        }
                    }
                }

                foreach (string subKey in regTest.GetSubKeyNames())
                {
                    RegistryKey regSubKey = regTest.OpenSubKey(subKey, false);

                    if (regSubKey == null)
                    {
                        continue;
                    }

                    string subKeyValue = (string)regSubKey.GetValue(valueName);

                    // Was a matching value found, and if so, does its data match the specified input?
                    if (subKeyValue != null && subKeyValue.ToString().ToLower().Equals(valueData.ToLower()))
                    {
                        regSubKey.Dispose();

                        return DeleteSubKeyTree(regHive, regKey + "\\" + subKey);
                    }
                    else if (subKeyValue == null && regSubKey.SubKeyCount > 0)
                    {
                        // Does the subkey of the subkey contain a matching value-data entry?
                        if (DeleteSubKeysWithValue(regHive, regKey + "\\" + subKey, valueName, valueData))
                        {
                            regSubKey.Dispose();
                            _logger.Log("Delete registry: " + regHive.ToString() + "\\" + regKey + "\\" + valueName + " = " + valueData);
                            return DeleteSubKeyTree(regHive, regKey + "\\" + subKey);
                        }
                    }
                    else
                    {
                        regSubKey.Dispose();
                        continue;
                    }
                }

                regTest.Dispose();
                return false;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool DeleteSubKeyTree(RegistryHive regHive, string regKey)
        {
            try
            {
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry32);
                RegistryKey baseKey64 = null;
                bool isFound = false;

                if (Environment.Is64BitOperatingSystem)
                {
                    baseKey64 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry64);
                }

                RegistryKey regTest = baseKey32.OpenSubKey(regKey, false);

                if (regTest != null)
                {
                    regTest.Dispose();
                    _logger.Log("Delete registry (32-bit): " + regHive + "\\" + regKey);
                    baseKey32.DeleteSubKeyTree(regKey, false);
                    isFound = true;
                }

                baseKey32.Dispose();

                if (baseKey64 != null)
                {
                    regTest = baseKey64.OpenSubKey(regKey, false);

                    if (regTest != null)
                    {
                        regTest.Dispose();
                        _logger.Log("Delete registry (64-bit): " + regHive + "\\" + regKey);
                        baseKey64.DeleteSubKeyTree(regKey, false);
                        isFound = true;
                    }

                    baseKey64.Dispose();
                }

                return isFound;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool DeleteValue(RegistryHive regHive, string regKey, string regValue)
        {
            bool valueDeleted = false;

            try
            {
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry32);
                RegistryKey baseKey64 = null;
                RegistryKey regTest = null;

                if (Environment.Is64BitOperatingSystem)
                {
                    baseKey64 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry64);
                    regTest = baseKey64.OpenSubKey(regKey, true);

                    if (regTest != null && regTest.GetValue(regValue) != null)
                    {
                        object regData = regTest.GetValue(regValue);
                        _logger.Log("Delete value: " + regHive.ToString() + "\\" + regKey + "\\" + regValue + $" [{regData}]");
                        regTest.DeleteValue(regValue);
                        valueDeleted = true;
                        baseKey64.Dispose();
                        regTest.Dispose();
                    }

                    baseKey64.Dispose();
                }

                regTest = baseKey32.OpenSubKey(regKey, true);
                baseKey32.Dispose();

                if (regTest != null && regTest.GetValue(regValue) != null)
                {
                    object regData = regTest.GetValue(regValue);
                    _logger.Log("Delete value: " + regHive.ToString() + "\\" + regKey + "\\" + regValue + $" [{regData}]");
                    regTest.DeleteValue(regValue);
                    valueDeleted = true;
                    regTest.Dispose();
                }

                return valueDeleted;
            }
            catch (Exception e)
            {
                _logger.Log(e, "Failed to delete registry value.");
                return valueDeleted;
            }
        }

        public RegistryKey GetParentKey(RegistryKey childKey, bool writable)
        {
            string[] regPath = childKey.Name.Split('\\');
            string childHive = regPath.First();
            string parentKeyName = String.Join("\\", regPath.Skip(1).Reverse().Skip(1).Reverse());

            // Local function for mapping hiveName(str) --> hiveName(registry).
            RegistryHive GetHive()
            {
                if (childHive.Equals("HKEY_CLASSES_ROOT", StringComparison.OrdinalIgnoreCase))
                    return RegistryHive.ClassesRoot;
                else if (childHive.Equals("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase))
                    return RegistryHive.CurrentUser;
                else if (childHive.Equals("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase))
                    return RegistryHive.LocalMachine;
                else if (childHive.Equals("HKEY_USERS", StringComparison.OrdinalIgnoreCase))
                    return RegistryHive.Users;
                else if (childHive.Equals("HKEY_CURRENT_CONFIG", StringComparison.OrdinalIgnoreCase))
                    return RegistryHive.CurrentConfig;
                else
                    throw new NotImplementedException(childHive);
            }

            RegistryHive parentHive = GetHive();

            using (var baseKey = RegistryKey.OpenBaseKey(parentHive, childKey.View))
            {
                return baseKey.OpenSubKey(parentKeyName, writable);
            }
        }

        public bool KeyExists(string regKey, RegistryHive regHive = RegistryHive.LocalMachine)
        {
            try
            {
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry32);

                if (Environment.Is64BitOperatingSystem)
                {
                    RegistryKey baseKey64 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry64);
                    RegistryKey testKey = baseKey64.OpenSubKey(regKey, false);

                    if (testKey != null)
                    {
                        testKey.Dispose();
                        baseKey64.Dispose();
                        baseKey32.Dispose();
                        return true;
                    }

                    testKey = baseKey32.OpenSubKey(regKey, false);

                    if (testKey != null)
                    {
                        testKey.Dispose();
                        baseKey64.Dispose();
                        baseKey32.Dispose();
                        return true;
                    }

                    return false;
                }
                else
                {
                    RegistryKey TestKey = baseKey32.OpenSubKey(regKey, false);

                    if (TestKey != null)
                    {
                        TestKey.Dispose();
                        baseKey32.Dispose();
                        return true;
                    }

                    baseKey32.Dispose();
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }

        public void MoveKey(RegistryKey sourceKey, RegistryKey destKey)
        {
            try
            {
                foreach (string regValue in sourceKey.GetValueNames())
                {
                    destKey.SetValue(regValue, sourceKey.GetValue(regValue, regValue, RegistryValueOptions.DoNotExpandEnvironmentNames), sourceKey.GetValueKind(regValue));
                    sourceKey.DeleteValue(regValue, false);
                }
            }
            catch (Exception e)
            {
                _logger.Log(e, "Failed to move registry values from [" + sourceKey.Name + "] to [" + destKey.Name + "].");
            }

            foreach (string strSubKey in sourceKey.GetSubKeyNames())
            {
                try
                {
                    using (RegistryKey regSubKey = sourceKey.OpenSubKey(strSubKey, false))
                    {
                        RegistryKey dstSubKey = destKey.CreateSubKey(strSubKey);
                        MoveKey(regSubKey, dstSubKey);
                        destKey.Dispose();

                        using (RegistryKey parentKey = GetParentKey(regSubKey, true))
                        {
                            string strChildKey = regSubKey.Name.Split('\\').Last();
                            parentKey.DeleteSubKeyTree(strChildKey);
                        }
                    }
                }
                catch (Exception e)
                {
                    _logger.Log(e, "Failed to copy registry subkey [" + strSubKey + "] to destination.");
                }
            }
        }

        public void MoveValue(RegistryKey sourceKey, RegistryKey destKey, string sourceValueName, string destValueName)
        {
            try
            {
                if (sourceKey.GetValue(sourceValueName) == null)
                {
                    _logger.Log("Source value [" + sourceValueName + "] does not exist in [" + sourceKey.Name + "].", Logger.MsgType.ERROR);
                }

                destKey.SetValue(destValueName,
                    sourceKey.GetValue(sourceValueName, sourceValueName, RegistryValueOptions.DoNotExpandEnvironmentNames),
                    sourceKey.GetValueKind(sourceValueName));

                sourceKey.DeleteValue(sourceValueName, false);
            }
            catch (Exception e)
            {
                _logger.Log(e, "Failed to move registry value [" + sourceValueName + "] from [" + sourceKey.Name + "] to [" + destKey.Name + "].");
            }
        }

        public RegistryKey OpenKey(string regKey, bool writable = false, RegistryHive regTree = RegistryHive.LocalMachine)
        {
            try
            {
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regTree, RegistryView.Registry32);
                RegistryKey baseKey64 = null;
                RegistryKey regTest = null;

                if (Environment.Is64BitOperatingSystem)
                {
                    baseKey64 = RegistryKey.OpenBaseKey(regTree, RegistryView.Registry64);
                    regTest = baseKey64.OpenSubKey(regKey, writable);

                    if (regTest != null)
                    {
                        baseKey64.Dispose();
                        baseKey32.Dispose();
                        return regTest;
                    }

                    baseKey64.Dispose();
                }

                regTest = baseKey32.OpenSubKey(regKey, writable);
                baseKey32.Dispose();

                if (regTest != null)
                {
                    return regTest;
                }

                return null;
            }
            catch (Exception)
            {
                return null;
            }
        }

        public bool ValueExists(string regKey, string regValueName, RegistryHive regHive = RegistryHive.LocalMachine)
        {
            try
            {
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry32);

                if (Environment.Is64BitOperatingSystem)
                {
                    RegistryKey baseKey64 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry64);
                    RegistryKey testKey = baseKey64.OpenSubKey(regKey, false);

                    if (testKey != null && testKey.GetValue(regValueName) != null)
                    {
                        testKey.Dispose();
                        baseKey64.Dispose();
                        baseKey32.Dispose();
                        return true;
                    }
                    else if (testKey != null)
                    {
                        testKey.Dispose();
                    }

                    baseKey64.Dispose();
                    testKey = baseKey32.OpenSubKey(regKey, false);

                    if (testKey != null && testKey.GetValue(regValueName) != null)
                    {
                        testKey.Dispose();
                        baseKey32.Dispose();
                        return true;
                    }
                    else if (testKey != null)
                    {
                        testKey.Dispose();
                    }

                    baseKey32.Dispose();
                    return false;
                }
                else
                {
                    RegistryKey testKey = baseKey32.OpenSubKey(regKey, false);

                    if (testKey != null && testKey.GetValue(regValueName) != null)
                    {
                        testKey.Dispose();
                        baseKey32.Dispose();
                        return true;
                    }
                    else if (testKey != null)
                    {
                        testKey.Dispose();
                    }

                    baseKey32.Dispose();
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}