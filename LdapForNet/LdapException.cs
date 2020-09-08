using System;
using System.Text;

namespace LdapForNet
{
	[Serializable]
	public class LdapUnavailableException : LdapException
	{
		public LdapUnavailableException(LdapExceptionData data) : base(data)
		{
		}
	}
	
    [Serializable]
    public class LdapException : Exception
    {
        public Native.Native.ResultCode?  ResultCode { get; }
        
       public LdapException(LdapExceptionData data) : base(data.ToString())
       {
	        if (data.Result != null)
	        {
		        ResultCode = (Native.Native.ResultCode) data.Result;
	        }
	   }
    }

    [Serializable]
    public class LdapOperationException : LdapException
    {
	    public LdapOperationException(DirectoryResponse response, LdapExceptionData data) : base(data)
	    {
		    Response = response;
	    }

	    public DirectoryResponse Response { get; internal set; }
    }

    public class LdapExceptionData
    {
	    public LdapExceptionData(string message)
	    {
		    Message = message;
	    }
	    
	    public LdapExceptionData(string message, int res)
	    {
		    Message = message;
		    Result = res;
	    }
	    
	    public LdapExceptionData(string message, string method, int res)
	    {
		    Message = message;
		    Method = method;
		    Result = res;
	    }
	    
	    public LdapExceptionData(string message, string method, int res, string details)
	    {
		    Message = message;
		    Method = method;
		    Details = details;
		    Result = res;
	    }
	    
	    public string Message { get;  }
	    public int? Result { get; }
	    public string Method { get;  }
	    public string Details { get; }

	    public override string ToString()
	    {
		    var sb = new StringBuilder();
		    sb.Append(Message);
		    if(Result != null)
		    {
			    sb.AppendFormat(". Result: {0}", Result);
		    }
		    if(Method != null)
		    {
			    sb.AppendFormat(". Method: {0}", Method);
		    }
		    if(Details != null)
		    {
			    sb.AppendFormat(". Details: {0}", Details);
		    }
		    return base.ToString();
	    }
    }
}