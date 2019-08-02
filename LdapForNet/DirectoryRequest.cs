using System;
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
    
    public class ExtendedRequest : DirectoryRequest
    {
        private byte[] _requestValue = null;

        public ExtendedRequest() { }

        public ExtendedRequest(string requestName)
        {
            RequestName = requestName;
        }

        public ExtendedRequest(string requestName, byte[] requestValue) : this(requestName)
        {
            _requestValue = requestValue;
        }

        public string RequestName { get; set; }

        public byte[] RequestValue
        {
            get
            {
                if (_requestValue == null)
                {
                    return Array.Empty<byte>();
                }

                byte[] tempValue = new byte[_requestValue.Length];
                for (int i = 0; i < _requestValue.Length; i++)
                {
                    tempValue[i] = _requestValue[i];
                }
                return tempValue;
            }
            set => _requestValue = value;
        }
    }
}