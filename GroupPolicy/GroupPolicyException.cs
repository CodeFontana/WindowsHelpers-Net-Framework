using System;

namespace LocalPolicyLibrary
{
    public class GroupPolicyException : Exception
    {
        internal GroupPolicyException(string message)
            : base(message) { }
    }
}
