using System;
using System.Collections.Generic;

namespace LdapForNet
{
    public abstract class DirectoryResponse
    {
        public virtual Native.Native.ResultCode ResultCode { get; internal set; }

        public virtual string ErrorMessage { get; internal set; }
    }
    
    public class SearchResponse : DirectoryResponse
    {
        public List<DirectoryEntry> Entries { get; internal set; } = new List<DirectoryEntry>();
    }

    public class AddResponse : DirectoryResponse
    {
        
    }
    
    public class ModifyResponse : DirectoryResponse
    {
        
    }
    
    public class ModifyDNResponse : DirectoryResponse
    {
        
    }
    
    public class DeleteResponse : DirectoryResponse
    {
        
    }
    
    public class ExtendedResponse : DirectoryResponse
    {
        private byte[] _value;

        public string ResponseName { get; internal set; }

        public byte[] ResponseValue
        {
            get
            {
                if (_value == null)
                {
                    return Array.Empty<byte>();
                }

                byte[] tmpValue = new byte[_value.Length];
                for (int i = 0; i < _value.Length; i++)
                {
                    tmpValue[i] = _value[i];
                }

                return tmpValue;
            }
            internal set => _value = value;
        }
    }

    public class CompareResponse : DirectoryResponse
    {
        
    }
}