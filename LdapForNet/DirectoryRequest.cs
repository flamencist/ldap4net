using System.Collections.Specialized;
using System.ComponentModel;

namespace LdapForNet
{
    public abstract class DirectoryRequest
    {
        internal DirectoryRequest(){}
    }
    
    public class DeleteRequest : DirectoryRequest
    {
        public DeleteRequest(string distinguishedName)
        {
            DistinguishedName = distinguishedName;
        }

        public string DistinguishedName { get; set; }
    }

    public class AddRequest : DirectoryRequest
    {
        public AddRequest(LdapEntry ldapEntry)
        {
            LdapEntry = ldapEntry;
        }

        public LdapEntry LdapEntry { get; set; }
    }

    public class ModifyRequest : DirectoryRequest
    {
        public ModifyRequest(LdapModifyEntry ldapModifyEntry)
        {
            LdapEntry = ldapModifyEntry;
        }
        public LdapModifyEntry LdapEntry { get; set; }
    }


    public class ModifyDNRequest : DirectoryRequest
    {
        public ModifyDNRequest(string distinguishedName, string newParentDistinguishedName, string newName)
        {
            DistinguishedName = distinguishedName;
            NewParentDistinguishedName = newParentDistinguishedName;
            NewName = newName;
        }

        public string DistinguishedName { get; set; }

        public string NewParentDistinguishedName { get; set; }

        public string NewName { get; set; }

        public bool DeleteOldRdn { get; set; } = true;
    }

    public class SearchRequest : DirectoryRequest
    {

        public SearchRequest(string distinguishedName, string ldapFilter, Native.Native.LdapSearchScope searchScope)
        {
            DistinguishedName = distinguishedName;
            Scope = searchScope;
            Filter = ldapFilter;
        }

        public string DistinguishedName { get; set; }


        public string Filter
        {
            get => _directoryFilter;
            set => _directoryFilter = value;
        }

        public Native.Native.LdapSearchScope Scope
        {
            get => _directoryScope;
            set
            {
                if (value < Native.Native.LdapSearchScope.LDAP_SCOPE_BASE || value > Native.Native.LdapSearchScope.LDAP_SCOPE_SUBTREE)
                {
                    throw new InvalidEnumArgumentException(nameof(value), (int)value, typeof(Native.Native.LdapSearchScope));
                }

                _directoryScope = value;
            }
        }

        private string _directoryFilter = null;
        private Native.Native.LdapSearchScope _directoryScope = Native.Native.LdapSearchScope.LDAP_SCOPE_SUBTREE;
    }
}