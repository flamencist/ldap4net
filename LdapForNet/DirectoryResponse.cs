using System.Collections.Generic;

namespace LdapForNet
{
    public class DirectoryResponse
    {
    }
    
    public class SearchResponse : DirectoryResponse
    {
        public List<LdapEntry> Entries { get; internal set; } = new List<LdapEntry>();
    }
}