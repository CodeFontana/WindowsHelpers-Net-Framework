using System;
using System.Collections.Generic;
using System.Text;

namespace WindowsNative
{
    public static class DotNetHelpers
    {
        public static bool IsHexChar(char c)
        {
            if (int.TryParse(c.ToString(), out int result) && result >= 0 && result <= 9)
                return true;
            if (c.ToString().ToLower().Equals("a"))
                return true;
            if (c.ToString().ToLower().Equals("b"))
                return true;
            if (c.ToString().ToLower().Equals("c"))
                return true;
            if (c.ToString().ToLower().Equals("d"))
                return true;
            if (c.ToString().ToLower().Equals("e"))
                return true;
            if (c.ToString().ToLower().Equals("f"))
                return true;
            return false;
        }

        public static bool IsHexString(string s)
        {
            foreach (char c in s) 
            {
                if (!IsHexChar(c))
                {
                    return false;
                }
            }
            
            return true;
        }

        public static bool IsListStringEqual(
            List<string> list1,
            List<string> list2,
            List<string> matchExceptions = null)
        {
            // Unequal number of elements?
            if (list1.Count != list2.Count)
            {
                return false;
            }

            // Flag for skipping element check (based on exception)
            bool skipFlag = false;

            for (int i = 0; i < list1.Count; i++)
            {
                if (matchExceptions != null)
                {
                    foreach (string s in matchExceptions)
                    {
                        if (list1[i].ToLower().Contains(s.ToLower()) || list1[i].ToLower().Contains(s.ToLower()) ||
                            list2[i].ToLower().Contains(s.ToLower()) || list2[i].ToLower().Contains(s.ToLower()))
                        {
                            skipFlag = true;
                            break;
                        }
                    }
                }

                if (skipFlag)
                {
                    skipFlag = false;
                    continue;
                }

                if (!list1[i].Equals(list2[i]))
                {
                    return false;
                }
            }

            return true;
        }

        public static bool IsListStringTupleEqual(
            List<Tuple<string, string>> list1,
            List<Tuple<string, string>> list2,
            List<string> matchExceptions = null)
        {
            // Unequal number of elements?
            if (list1.Count != list2.Count)
            {
                return false;
            }

            // Flag for skipping element check (based on exception)
            bool skipFlag = false;

            for (int i = 0; i < list1.Count; i++)
            {
                if (matchExceptions != null)
                {
                    foreach (string s in matchExceptions)
                    {
                        if (list1[i].Item1.ToLower().Contains(s.ToLower()) ||
                            list1[i].Item2.ToLower().Contains(s.ToLower()) ||
                            list2[i].Item1.ToLower().Contains(s.ToLower()) ||
                            list2[i].Item2.ToLower().Contains(s.ToLower()))
                        {
                            skipFlag = true;
                            break;
                        }
                    }
                }

                if (skipFlag)
                {
                    skipFlag = false;
                    continue;
                }

                if (!list1[i].Item1.Equals(list2[i].Item1) ||
                    !list1[i].Item2.Equals(list2[i].Item2))
                {
                    return false;
                }
            }

            return true;
        }

        public static string PadListElements(List<string[]> inputList, int columnPadding = 1)
        {
            // Using the first element as the template, store a value indicating
            // the number of columns each string array has. As we are displaying
            // a chart of information, it is presumed that all elements have the
            // same number of columns.
            var numColumns = inputList[0].Length;

            // An array for storing the max length of each column, for all
            // elements in the chart. This way content+padding of each element
            // in the chart is equal to the max length, so all columns are
            // properly aligned.
            var maxValues = new int[numColumns];

            // Iterate each column.
            for (int i = 0; i < numColumns; i++)
            {
                // Initialize -- for storing the max column length amongst
                //               each element.
                int maxColLength = 0;

                // Iterate each element.
                inputList.ForEach(e =>
                {
                    // Does this element have an ith column?
                    if (i < e.Length)
                    {
                        // Record the length of the ith column.
                        int colLength = e[i].Length;

                        // Is this column length greater than the max?
                        if (colLength > maxColLength)
                        {
                            maxColLength = colLength; // Store new maximum.
                        }
                    }
                });

                // Store max value.
                maxValues[i] = maxColLength + columnPadding;
            }

            var outputString = new StringBuilder();
            bool isFirst = true;

            // Iterate list elements (each string array)
            foreach (var line in inputList)
            {
                if (!isFirst)
                {
                    outputString.AppendLine();
                }

                isFirst = false;

                for (int i = 0; i < line.Length; i++)
                {
                    var value = line[i];

                    // Append the value with padding of the maximum length of any value for this element
                    outputString.Append(value.PadRight(maxValues[i]));
                }
            }

            return outputString.ToString();
        }

        public static string StringListToCommaString(string[] inputArray, string delimeter = ",")
        {
            string returnString = "";

            foreach (string s in inputArray)
            {
                returnString += s + delimeter;
            }

            return returnString.TrimEnd(delimeter.ToCharArray());
        }
    }
}