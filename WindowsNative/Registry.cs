using Microsoft.Win32;
using System;
using System.Linq;

namespace WindowsNative
{
    public static class Registry
    {
        public static bool DeleteRegistrySubKeysWithValue(RegistryHive regHive, string rootKey, string matchName, string matchValue)
        {
            try
            {
                // Open base registry
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry32);
                RegistryKey baseKey64 = null;

                // Is this 64-bit OS?
                if (Environment.Is64BitOperatingSystem)
                {
                    // Open base registry
                    baseKey64 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry64);
                }

                // Test the registry
                RegistryKey regTest = baseKey32.OpenSubKey(rootKey, false);

                // Does 32-bit subkey exist?
                if (regTest == null)
                {
                    // Is the 64-bit registry available?
                    if (baseKey64 != null)
                    {
                        // Test the registry
                        regTest = baseKey64.OpenSubKey(rootKey, false);

                        // Does 64-bit subkey exist?
                        if (regTest == null)
                        {
                            // Not found
                            return false;
                        }
                    }
                }

                // Iterate subkeys
                foreach (string subKey in regTest.GetSubKeyNames())
                {
                    // Open subkey
                    RegistryKey regSubKey = regTest.OpenSubKey(subKey, false);

                    // Did the subkey open OK?
                    if (regSubKey == null)
                    {
                        // Skip to next one
                        continue;
                    }

                    // Get value
                    string subKeyValue = (string)regSubKey.GetValue(matchName);

                    // Was a matching value found, and if so, does its data match the specified input?
                    if (subKeyValue != null && subKeyValue.ToString().ToLower().Equals(matchValue.ToLower()))
                    {
                        // Close the subkey
                        regSubKey.Dispose();

                        // Write debug
                        Logger.WriteDebug("Delete registry: " + regHive.ToString() + "\\" + rootKey + "\\" + matchName + "=" + matchValue);

                        // Delete the subkey tree
                        return DeleteRegistrySubKeyTree(regHive, rootKey + "\\" + subKey);
                    }
                    else if (subKeyValue == null && regSubKey.SubKeyCount > 0)
                    {
                        // Does the subkey of the subkey contain a matching value-data entry?
                        if (DeleteRegistrySubKeysWithValue(regHive, rootKey + "\\" + subKey, matchName, matchValue))
                        {
                            // Close the subkey
                            regSubKey.Dispose();

                            // Write debug
                            Logger.WriteDebug("Delete registry: " + regHive.ToString() + "\\" + rootKey + "\\" + matchName + "=" + matchValue);

                            // Delete the subkey tree
                            return DeleteRegistrySubKeyTree(regHive, rootKey + "\\" + subKey);
                        }
                    }
                    else
                    {
                        // Close registry
                        regSubKey.Dispose();

                        // Continue for
                        continue;
                    }
                }

                // Close registry
                regTest.Dispose();

                // No match
                return false;
            }
            catch (Exception)
            {
                // Return
                return false;
            }
        }

        public static bool DeleteRegistrySubKeyTree(RegistryHive regHive, string regKey)
        {
            try
            {
                // Open base registry
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry32);
                RegistryKey baseKey64 = null;
                bool isFound = false;

                // Is this 64-bit OS?
                if (Environment.Is64BitOperatingSystem)
                {
                    // Open 64-bit registry
                    baseKey64 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry64);
                }

                // Test registry
                RegistryKey regTest = baseKey32.OpenSubKey(regKey, false);

                // Does 32-bit subkey exist?
                if (regTest != null)
                {
                    // Close registry test key
                    regTest.Dispose();

                    // Write debug
                    Logger.WriteDebug("Delete registry (32-bit): " + regHive + "\\" + regKey);

                    // Delete the subkey
                    baseKey32.DeleteSubKeyTree(regKey, false);

                    // Set flag
                    isFound = true;
                }

                // Close key
                baseKey32.Dispose();

                // Is the 64-bit registry available?
                if (baseKey64 != null)
                {
                    // Test registry
                    regTest = baseKey64.OpenSubKey(regKey, false);

                    // Does 64-bit subkey exist?
                    if (regTest != null)
                    {
                        // Close registry test key
                        regTest.Dispose();

                        // Write debug
                        Logger.WriteDebug("Delete registry (64-bit): " + regHive + "\\" + regKey);

                        // Delete the subkey
                        baseKey64.DeleteSubKeyTree(regKey, false);

                        // Set flag
                        isFound = true;
                    }

                    // Close key.
                    baseKey64.Dispose();
                }

                // Return
                return isFound;
            }
            catch (Exception)
            {
                // Return
                return false;
            }
        }

        public static bool DeleteRegistryValue(RegistryHive regHive, string regKey, string regValue)
        {
            // Flag for value deletion.
            bool valueDeleted = false;

            try
            {
                // Open registry.
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry32);
                RegistryKey baseKey64 = null;
                RegistryKey regTest = null;

                // Is this 64-bit OS?
                if (Environment.Is64BitOperatingSystem)
                {
                    // Open 64-bit registry.
                    baseKey64 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry64);
                    regTest = baseKey64.OpenSubKey(regKey, true);

                    // Does 64-bit subkey exist?
                    if (regTest != null && regTest.GetValue(regValue) != null)
                    {
                        // Read regValue data.
                        object regData = regTest.GetValue(regValue);

                        // Write debug.
                        Logger.WriteDebug("Delete value: " + regHive.ToString() + "\\" + regKey + "\\" + regValue + $" [{regData}]");

                        // Delete the value.
                        regTest.DeleteValue(regValue);

                        // Set flag.
                        valueDeleted = true;

                        // Close registry.
                        baseKey64.Dispose();
                        regTest.Dispose();
                    }

                    // Close registry.
                    baseKey64.Dispose();
                }

                // Open 32-bit registry.
                regTest = baseKey32.OpenSubKey(regKey, true);

                // Close registry.
                baseKey32.Dispose();

                // Does 32-bit subkey exist?
                if (regTest != null && regTest.GetValue(regValue) != null)
                {
                    // Read regValue data.
                    object regData = regTest.GetValue(regValue);

                    // Write debug.
                    Logger.WriteDebug("Delete value: " + regHive.ToString() + "\\" + regKey + "\\" + regValue + $" [{regData}]");

                    // Delete the value.
                    regTest.DeleteValue(regValue);

                    // Set flag.
                    valueDeleted = true;

                    // Close registry.
                    regTest.Dispose();
                }

                // Not found
                return valueDeleted;
            }
            catch (Exception e)
            {
                // Write exception.
                Logger.WriteException(e, "Failed to delete registry value.");

                // Return
                return valueDeleted;
            }
        }

        public static RegistryKey OpenRegistryKey(string regKey, bool writable = false, RegistryHive regTree = RegistryHive.LocalMachine)
        {
            try
            {
                // Open registry
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regTree, RegistryView.Registry32);
                RegistryKey baseKey64 = null;
                RegistryKey regTest = null;

                // Is this 64-bit OS?
                if (Environment.Is64BitOperatingSystem)
                {
                    // Open 64-bit registry
                    baseKey64 = RegistryKey.OpenBaseKey(regTree, RegistryView.Registry64);
                    regTest = baseKey64.OpenSubKey(regKey, writable);

                    // Does 64-bit subkey exist?
                    if (regTest != null)
                    {
                        // Close registry
                        baseKey64.Dispose();
                        baseKey32.Dispose();

                        // Return
                        return regTest;
                    }

                    // Close registry
                    baseKey64.Dispose();
                }

                // Open 32-bit registry
                regTest = baseKey32.OpenSubKey(regKey, writable);

                // Close registry
                baseKey32.Dispose();

                // Does 32-bit subkey exist?
                if (regTest != null)
                {
                    // Return
                    return regTest;
                }

                // Not found
                return null;
            }
            catch (Exception)
            {
                // Return
                return null;
            }
        }

        public static void RegistryCopy(RegistryKey sourceKey, RegistryKey destKey)
        {
            try
            {
                // Iterate values in source key
                foreach (string regValue in sourceKey.GetValueNames())
                {
                    // Copy value to destination key
                    destKey.SetValue(regValue, sourceKey.GetValue(regValue, regValue, RegistryValueOptions.DoNotExpandEnvironmentNames), sourceKey.GetValueKind(regValue));
                }
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to copy registry values from [" + sourceKey.Name + "] to [" + destKey.Name + "].");
            }

            // Iterate subkeys in source key
            foreach (string strSubKey in sourceKey.GetSubKeyNames())
            {
                try
                {
                    // Recurse subkey
                    using (RegistryKey regSubKey = sourceKey.OpenSubKey(strSubKey, false))
                    {
                        // Create the subkey at the destination
                        RegistryKey dstSubKey = destKey.CreateSubKey(strSubKey);

                        // Recurse for any values/subkeys
                        RegistryCopy(regSubKey, dstSubKey);

                        // Close key.
                        dstSubKey.Dispose();
                    }
                }
                catch (Exception e)
                {
                    // Write debug
                    Logger.WriteDebug("EXCEPTION: " + e.Message);
                    Logger.WriteDebug("ERROR: Failed to copy registry subkey [" + strSubKey + "] to destination.");
                }
            }
        }

        public static RegistryKey RegistryGetParent(RegistryKey childKey, bool writable)
        {
            // Split chiild key into parts
            string[] regPath = childKey.Name.Split('\\');

            // First element is the registry hive
            string childHive = regPath.First();

            // Get the parent key
            string parentKeyName = String.Join("\\", regPath.Skip(1).Reverse().Skip(1).Reverse());

            // Local function for mapping hiveName(str) --> hiveName(registry)
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

            // Get parent hive
            RegistryHive parentHive = GetHive();

            // Return open parent key
            using (var baseKey = RegistryKey.OpenBaseKey(parentHive, childKey.View))
            {
                return baseKey.OpenSubKey(parentKeyName, writable);
            }
        }

        public static bool RegistryKeyExists(string regKey, RegistryHive regHive = RegistryHive.LocalMachine)
        {
            try
            {
                // Open base registry
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry32);

                // Is this 64-bit OS?
                if (Environment.Is64BitOperatingSystem)
                {
                    // Open base registry
                    RegistryKey baseKey64 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry64);
                    RegistryKey testKey = baseKey64.OpenSubKey(regKey, false);

                    // Does it exist?
                    if (testKey != null)
                    {
                        // Close registry
                        testKey.Dispose();
                        baseKey64.Dispose();
                        baseKey32.Dispose();

                        // Return
                        return true;
                    }

                    // Attmept to open 32-bit registry key
                    testKey = baseKey32.OpenSubKey(regKey, false);

                    // Does it exist?
                    if (testKey != null)
                    {
                        // Close registry
                        testKey.Dispose();
                        baseKey64.Dispose();
                        baseKey32.Dispose();

                        // Return
                        return true;
                    }

                    // Not found
                    return false;
                }
                else
                {
                    // Attmept to open 32-bit registry key
                    RegistryKey TestKey = baseKey32.OpenSubKey(regKey, false);

                    // Does it exist?
                    if (TestKey != null)
                    {
                        // Close registry
                        TestKey.Dispose();
                        baseKey32.Dispose();

                        // Return
                        return true;
                    }

                    // Close registry.
                    baseKey32.Dispose();

                    // Return -- not found
                    return false;
                }
            }
            catch (Exception)
            {
                // Return
                return false;
            }
        }

        public static bool RegistryValueExists(string regKey, string regValueName, RegistryHive regHive = RegistryHive.LocalMachine)
        {
            try
            {
                // Open base registry.
                RegistryKey baseKey32 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry32);

                // Is this 64-bit OS?
                if (Environment.Is64BitOperatingSystem)
                {
                    // Open base registry.
                    RegistryKey baseKey64 = RegistryKey.OpenBaseKey(regHive, RegistryView.Registry64);
                    RegistryKey testKey = baseKey64.OpenSubKey(regKey, false);

                    // Does the key and value exist?
                    if (testKey != null && testKey.GetValue(regValueName) != null)
                    {
                        // Close registry.
                        testKey.Dispose();
                        baseKey64.Dispose();
                        baseKey32.Dispose();

                        // Return.
                        return true;
                    }
                    else if (testKey != null)
                    {
                        // Close registry.
                        testKey.Dispose();
                    }

                    // Close key.
                    baseKey64.Dispose();

                    // Attmept to open 32-bit registry key.
                    testKey = baseKey32.OpenSubKey(regKey, false);

                    // Does the key and value exist?
                    if (testKey != null && testKey.GetValue(regValueName) != null)
                    {
                        // Close registry.
                        testKey.Dispose();
                        baseKey32.Dispose();

                        // Return.
                        return true;
                    }
                    else if (testKey != null)
                    {
                        // Close registry.
                        testKey.Dispose();
                    }

                    // Close registry.
                    baseKey32.Dispose();

                    // Not found.
                    return false;
                }
                else
                {
                    // Attmept to open 32-bit registry key.
                    RegistryKey testKey = baseKey32.OpenSubKey(regKey, false);

                    // Does the key and value exist?
                    if (testKey != null && testKey.GetValue(regValueName) != null)
                    {
                        // Close registry.
                        testKey.Dispose();
                        baseKey32.Dispose();

                        // Return.
                        return true;
                    }
                    else if (testKey != null)
                    {
                        // Close registry.
                        testKey.Dispose();
                    }

                    // Close registry.
                    baseKey32.Dispose();

                    // Not found.
                    return false;
                }
            }
            catch (Exception)
            {
                // Return.
                return false;
            }
        }

        public static void RegistryMove(RegistryKey sourceKey, RegistryKey destKey)
        {
            try
            {
                // Iterate values in source key
                foreach (string regValue in sourceKey.GetValueNames())
                {
                    // Copy value to destination
                    destKey.SetValue(regValue, sourceKey.GetValue(regValue, regValue, RegistryValueOptions.DoNotExpandEnvironmentNames), sourceKey.GetValueKind(regValue));

                    // Delete value at source
                    sourceKey.DeleteValue(regValue, false);
                }
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to move registry values from [" + sourceKey.Name + "] to [" + destKey.Name + "].");
            }

            // Iterate subkeys in source key
            foreach (string strSubKey in sourceKey.GetSubKeyNames())
            {
                try
                {
                    // Recurse and delete subkey
                    using (RegistryKey regSubKey = sourceKey.OpenSubKey(strSubKey, false))
                    {
                        // Create the subkey at the destination
                        RegistryKey dstSubKey = destKey.CreateSubKey(strSubKey);

                        // Recurse for any values/subkeys
                        RegistryMove(regSubKey, dstSubKey);

                        // Close key.
                        destKey.Dispose();

                        // Delete the subkey
                        using (RegistryKey parentKey = RegistryGetParent(regSubKey, true))
                        {
                            // Get the child key name
                            string strChildKey = regSubKey.Name.Split('\\').Last();

                            // Delete the key
                            parentKey.DeleteSubKeyTree(strChildKey);
                        }
                    }
                }
                catch (Exception e)
                {
                    // Write debug
                    Logger.WriteDebug("EXCEPTION: " + e.Message);
                    Logger.WriteDebug("ERROR: Failed to copy registry subkey [" + strSubKey + "] to destination.");
                }
            }
        }

        public static void RegistryMoveValue(RegistryKey sourceKey, RegistryKey destKey, string sourceValueName, string destValueName)
        {
            try
            {
                // Does the value name exist?
                if (sourceKey.GetValue(sourceValueName) == null)
                {
                    // Write debug
                    Logger.WriteDebug("ERROR: Source value [" + sourceValueName + "] does not exist in [" + sourceKey.Name + "].");
                }

                // Copy value to destination
                destKey.SetValue(destValueName, sourceKey.GetValue(sourceValueName, sourceValueName, RegistryValueOptions.DoNotExpandEnvironmentNames), sourceKey.GetValueKind(sourceValueName));

                // Delete value at source
                sourceKey.DeleteValue(sourceValueName, false);
            }
            catch (Exception e)
            {
                // Write debug
                Logger.WriteDebug("EXCEPTION: " + e.Message);
                Logger.WriteDebug("ERROR: Failed to move registry value [" + sourceValueName + "] from [" + sourceKey.Name + "] to [" + destKey.Name + "].");
            }
        }
    }
}