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
        public List<LdapEntry> Entries { get; internal set; } = new List<LdapEntry>();
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
}