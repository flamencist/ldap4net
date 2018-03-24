using System;

namespace LdapForNet
{
    public class LdapException : Exception
    {
        public LdapException(string message):base(message)
        {
        }

        public LdapException(string message, int res) : base($"{message} . Result: {res}")
        {
        }

        public LdapException(string message, string method, int res) : base($"{message}. Result: {res}. Method: {method}")
        {
        }
    }
}
