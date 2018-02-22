using System.Collections.Generic;

namespace LdapForNet
{
    public class LdapEntry
    {
        public string Dn { get; set; }
        public Dictionary<string,List<string>> Attributes { get; set; }
    }
}