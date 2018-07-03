using System.Collections.Generic;
using LdapForNet.Native;

namespace LdapForNet
{
    public class LdapEntry
    {
        public string Dn { get; set; }
        public Dictionary<string,List<string>> Attributes { get; set; }
    }

    public class LdapModifyEntry
    {
        public string Dn { get; set; }
        public List<LdapModifyAttribute> Attributes { get; set; }
    }

    public class LdapModifyAttribute
    {
        public string Type { get; set; }
        public List<string> Values { get; set; }
        public Native.Native.LdapModOperation LdapModOperation { get; set; } = Native.Native.LdapModOperation.LDAP_MOD_REPLACE;
    }
}