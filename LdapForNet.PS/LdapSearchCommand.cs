using System;
using System.Management.Automation;

namespace LdapForNet.PS
{
    [Cmdlet(VerbsLdap.Ldap, VerbsCommon.Search)]
    [OutputType(typeof(LdapEntry))]
    public class LdapSearchCommand : LdapBaseCommand
    {
        [Parameter(
            Position = 8)]
        public string Filter { get; set; } = "(objectClass=*)";

        [Parameter(
            Position = 9)]
        public string Base { get; set; }

        [Parameter(
            Position = 10)]
        [ValidateSet("base", "one", "sub")]
        public string Scope { get; set; } = "base";

        protected override void OnLdapBind(LdapConnection cn)
        {
            
            var entries = cn.Search(Base, Filter, ToSearchScope(Scope));
            foreach (var entry in entries)
            {
                WriteObject(entry, true);
            }
        }
        
        private Native.Native.LdapSearchScope ToSearchScope(string type)
        {
            switch (type)
            {
                case "base":
                    return Native.Native.LdapSearchScope.LDAP_SCOPE_BASE;
                case "one":
                    return Native.Native.LdapSearchScope.LDAP_SCOPE_ONE;
                case "sub":
                    return Native.Native.LdapSearchScope.LDAP_SCOPE_SUB;
                default:
                    throw new ArgumentException($"Unknown {nameof(Scope)}");
            }
        }
    }
}