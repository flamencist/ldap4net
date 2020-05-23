using System;

namespace LdapForNet
{
    [Serializable]
    public class LdapException : Exception
    {
        public LdapException(string message) : base(message)
        {
        }

        public LdapException(string message, int res) : base($"{message} . Result: {res}")
        {
        }

        public LdapException(string message, string method, int res) : base(
            $"{message}. Result: {res}. Method: {method}")
        {
        }

        public LdapException(string message, string method, int res, string details) : base(
            $"{message}. Result: {res}. Method: {method}. Details: {details}")
        {
        }
    }

    [Serializable]
    public class LdapOperationException : LdapException
    {
	    public LdapOperationException(DirectoryResponse response, string message) : base(message)
	    {
		    Response = response;
	    }

	    public LdapOperationException(DirectoryResponse response, string message, int res) : base(message, res)
	    {
		    Response = response;
        }

	    public LdapOperationException(DirectoryResponse response, string message, string method, int res) : base(message, method, res)
	    {
		    Response = response;
        }

	    public LdapOperationException(DirectoryResponse response, string message, string method, int res, string details) : base(message, method, res, details)
	    {
		    Response = response;
        }

	    public DirectoryResponse Response { get; internal set; }
    }
}