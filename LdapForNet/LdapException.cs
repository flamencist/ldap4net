using System;
using System.Text;

namespace LdapForNet
{
    [Serializable]
    public class LdapException : Exception
    {
        public Native.Native.ResultCode?  ResultCode { get; }
        
        public DirectoryResponse Response { get; }
        
       public LdapException(LdapExceptionData data) : base(data.ToString())
       {
	        if (data.Result != null)
	        {
		        ResultCode = (Native.Native.ResultCode) data.Result;
	        }

	        if (data.Response != null)
	        {
		        Response = data.Response;
	        }
	   }
    }
    
    [Serializable]
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
	    
	    public DirectoryResponse Response { get; internal set; }

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
		    return sb.ToString();
	    }
    }
    
    [Serializable]
	public class LdapUnavailableException : LdapException
	{
		public LdapUnavailableException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapNotSupportedException : LdapException
	{
		public LdapNotSupportedException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapParamErrorException : LdapException
	{
		public LdapParamErrorException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapOperationsErrorException : LdapException
	{
		public LdapOperationsErrorException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapProtocolErrorException : LdapException
	{
		public LdapProtocolErrorException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapTimeLimitExceededException : LdapException
	{
		public LdapTimeLimitExceededException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapSizeLimitExceededException : LdapException
	{
		public LdapSizeLimitExceededException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapAuthMethodNotSupportedException : LdapException
	{
		public LdapAuthMethodNotSupportedException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapStrongAuthRequiredException : LdapException
	{
		public LdapStrongAuthRequiredException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapAdminLimitExceededException : LdapException
	{
		public LdapAdminLimitExceededException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapUnavailableCriticalExtensionException : LdapException
	{
		public LdapUnavailableCriticalExtensionException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapConfidentialityRequiredException : LdapException
	{
		public LdapConfidentialityRequiredException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapNoSuchAttributeException : LdapException
	{
		public LdapNoSuchAttributeException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapUndefinedAttributeTypeException : LdapException
	{
		public LdapUndefinedAttributeTypeException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapInappropriateMatchingException : LdapException
	{
		public LdapInappropriateMatchingException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapConstraintViolationException : LdapException
	{
		public LdapConstraintViolationException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapAttributeOrValueExistsException : LdapException
	{
		public LdapAttributeOrValueExistsException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapInvalidAttributeSyntaxException : LdapException
	{
		public LdapInvalidAttributeSyntaxException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapNoSuchObjectException : LdapException
	{
		public LdapNoSuchObjectException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapAliasProblemException : LdapException
	{
		public LdapAliasProblemException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapInvalidDnSyntaxException : LdapException
	{
		public LdapInvalidDnSyntaxException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapAliasDereferencingProblemException : LdapException
	{
		public LdapAliasDereferencingProblemException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapInappropriateAuthenticationException : LdapException
	{
		public LdapInappropriateAuthenticationException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapInvalidCredentialsException : LdapException
	{
		public LdapInvalidCredentialsException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapInsufficientAccessRightsException : LdapException
	{
		public LdapInsufficientAccessRightsException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapBusyException : LdapException
	{
		public LdapBusyException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapUnwillingToPerformException : LdapException
	{
		public LdapUnwillingToPerformException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapLoopDetectException : LdapException
	{
		public LdapLoopDetectException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapSortControlMissingException : LdapException
	{
		public LdapSortControlMissingException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapOffsetRangeErrorException : LdapException
	{
		public LdapOffsetRangeErrorException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapNamingViolationException : LdapException
	{
		public LdapNamingViolationException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapObjectClassViolationException : LdapException
	{
		public LdapObjectClassViolationException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapNotAllowedOnNonLeafException : LdapException
	{
		public LdapNotAllowedOnNonLeafException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapNotAllowedOnRdnException : LdapException
	{
		public LdapNotAllowedOnRdnException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapEntryAlreadyExistsException : LdapException
	{
		public LdapEntryAlreadyExistsException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapObjectClassModificationsProhibitedException : LdapException
	{
		public LdapObjectClassModificationsProhibitedException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapResultsTooLargeException : LdapException
	{
		public LdapResultsTooLargeException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapAffectsMultipleDsasException : LdapException
	{
		public LdapAffectsMultipleDsasException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapVirtualListViewErrorException : LdapException
	{
		public LdapVirtualListViewErrorException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapOtherException : LdapException
	{
		public LdapOtherException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapTimeoutException : LdapException
	{
		public LdapTimeoutException(LdapExceptionData data) : base(data)
		{
		}
	}
	
	[Serializable]
	public class LdapBerConversionException : LdapException
	{
		public LdapBerConversionException(LdapExceptionData data) : base(data)
		{
		}
	}

    [Serializable]
    public class LdapServerDownException : LdapException
    {
        public LdapServerDownException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapLocalErrorException : LdapException
    {
        public LdapLocalErrorException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapEncodingErrorException : LdapException
    {
        public LdapEncodingErrorException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapDecodingErrorException : LdapException
    {
        public LdapDecodingErrorException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapAuthUnknownException : LdapException
    {
        public LdapAuthUnknownException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapFilterErrorException : LdapException
    {
        public LdapFilterErrorException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapUserCanceledException : LdapException
    {
        public LdapUserCanceledException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapNoMemoryException : LdapException
    {
        public LdapNoMemoryException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapConnectErrorException : LdapException
    {
        public LdapConnectErrorException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapControlNotFoundException : LdapException
    {
        public LdapControlNotFoundException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapNoResultsReturnedException : LdapException
    {
        public LdapNoResultsReturnedException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapMoreResultsToReturnException : LdapException
    {
        public LdapMoreResultsToReturnException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapClientLoopException : LdapException
    {
        public LdapClientLoopException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapReferralLimitExceededException : LdapException
    {
        public LdapReferralLimitExceededException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapInvalidResponseException : LdapException
    {
        public LdapInvalidResponseException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapAmbiguousResponseException : LdapException
    {
        public LdapAmbiguousResponseException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapTlsNotSupportedException : LdapException
    {
        public LdapTlsNotSupportedException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapIntermediateResponseException : LdapException
    {
        public LdapIntermediateResponseException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapUnknownTypeException : LdapException
    {
        public LdapUnknownTypeException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapCanceledException : LdapException
    {
        public LdapCanceledException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapNoSuchOperationException : LdapException
    {
        public LdapNoSuchOperationException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapTooLateException : LdapException
    {
        public LdapTooLateException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapCannotCancelException : LdapException
    {
        public LdapCannotCancelException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapAssertionFailedException : LdapException
    {
        public LdapAssertionFailedException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapAuthorizationDeniedException : LdapException
    {
        public LdapAuthorizationDeniedException(LdapExceptionData data) : base(data)
        {
        }
    }

    [Serializable]
    public class LdapNoOperationException : LdapException
    {
        public LdapNoOperationException(LdapExceptionData data) : base(data)
        {
        }
    }
}