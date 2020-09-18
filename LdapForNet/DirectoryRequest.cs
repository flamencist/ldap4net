using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;

namespace LdapForNet
{
    public abstract class DirectoryRequest
    {
        internal DirectoryRequest(){}
        
        public List<DirectoryControl> Controls { get; } = new List<DirectoryControl>();       
        public int MessageId { get; internal set; }
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

        public AddRequest(string distinguishedName, params DirectoryAttribute[] attributes)
        {
            DistinguishedName = distinguishedName;
            foreach (var attribute in attributes)
            {
                Attributes.Add(attribute);
            }
        }

        public string DistinguishedName { get; set; }
        public SearchResultAttributeCollection Attributes { get; } = new SearchResultAttributeCollection();

        public LdapEntry LdapEntry
        {
            get =>
	            new LdapEntry
	            {
		            Dn = DistinguishedName,
		            DirectoryAttributes = Attributes
	            };
            set
            {
                DistinguishedName = value.Dn;
                Attributes.Clear();
                
                foreach (var attribute in value.DirectoryAttributes)
                {
	                Attributes.Add(attribute);
                }
            }
        }
    }

    public class ModifyRequest : DirectoryRequest
    {
        public ModifyRequest(LdapModifyEntry ldapModifyEntry)
        {
            LdapEntry = ldapModifyEntry;
        }

        public ModifyRequest(string distinguishedName, params DirectoryModificationAttribute[] attributes)
        {
            DistinguishedName = distinguishedName;
            foreach (var attribute in attributes)
            {
                Attributes.Add(attribute);
            }
        }

        public string DistinguishedName { get; set; }

        public LdapModifyEntry LdapEntry
        {
            get
            {
                return new LdapModifyEntry
                {
                    Dn = DistinguishedName,
                    Attributes = Attributes.Select(_ => new LdapModifyAttribute
                        {
                            Type = _.Name, Values = _.GetValues<string>().ToList(),
                            LdapModOperation = _.LdapModOperation
                        })
                        .ToList()
                };
            }
            set
            {
                DistinguishedName = value.Dn;
                Attributes.Clear();
                foreach (var attribute in value.Attributes)
                {
                    var item = new DirectoryModificationAttribute
                    {
                        Name = attribute.Type,
                        LdapModOperation = attribute.LdapModOperation
                    };
                    item.AddValues(attribute.Values);
                    Attributes.Add(item);
                }
            }
        }

        public ModifyAttributeCollection Attributes { get; } = new ModifyAttributeCollection();
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
        private string _directoryFilter = null;
        private Native.Native.LdapSearchScope _directoryScope = Native.Native.LdapSearchScope.LDAP_SCOPE_SUBTREE;
        private int _directorySizeLimit = 0;
        private TimeSpan _directoryTimeLimit = new TimeSpan(0);


        public SearchRequest(string distinguishedName, string ldapFilter, Native.Native.LdapSearchScope searchScope,
            params string[] attributeList)
        {
            DistinguishedName = distinguishedName;
            Scope = searchScope;
            Filter = ldapFilter;
            if (attributeList != null)
            {
                Attributes.AddRange(attributeList);
            }
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
                if (value < Native.Native.LdapSearchScope.LDAP_SCOPE_BASE ||
                    value > Native.Native.LdapSearchScope.LDAP_SCOPE_SUBTREE)
                {
                    throw new InvalidEnumArgumentException(nameof(value), (int) value,
                        typeof(Native.Native.LdapSearchScope));
                }

                _directoryScope = value;
            }
        }

        public List<string> Attributes { get; } = new List<string>();


        public int SizeLimit
        {
            get => _directorySizeLimit;
            set
            {
                if (value < 0)
                {
                    throw new ArgumentException(nameof(SizeLimit) + " could not negative number", nameof(value));
                }

                _directorySizeLimit = value;
            }
        }

        public TimeSpan TimeLimit
        {
            get => _directoryTimeLimit;
            set
            {
                if (value < TimeSpan.Zero)
                {
                    throw new ArgumentException(nameof(TimeLimit) + " could not negative number", nameof(value));
                }

                // Prevent integer overflow.
                if (value.TotalSeconds > int.MaxValue)
                {
                    throw new ArgumentException("Time span overflow", nameof(value));
                }

                _directoryTimeLimit = value;
            }
        }

        public bool AttributesOnly { get; set; }

        public Action<SearchResponse> OnPartialResult { get; set; }

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

    public class CompareRequest : DirectoryRequest
    {
        public CompareRequest(LdapEntry ldapEntry)
        {
            if (ldapEntry.DirectoryAttributes.Count != 1)
            {
                throw new ArgumentException("Wrong number of attributes");
            }

            var attribute = ldapEntry.DirectoryAttributes.Single();
            if (attribute.GetRawValues().Count != 1)
            {
                throw new ArgumentException("Wrong number of attribute values");
            }

            DistinguishedName = ldapEntry.Dn;
            Assertion.Name = attribute.Name;
            Assertion.Add(attribute.GetValues<string>().Single());
        }

        public CompareRequest(string distinguishedName, string attributeName, byte[] value)
        {
            DistinguishedName = distinguishedName;
            Assertion.Name = attributeName;
            Assertion.Add(value);
        }

        public CompareRequest(string distinguishedName, string attributeName, string value)
        {
            DistinguishedName = distinguishedName;
            Assertion.Name = attributeName;
            Assertion.Add(value);
        }

        public string DistinguishedName { get; set; }

        public DirectoryAttribute Assertion { get; } = new DirectoryAttribute();
    }

    public class TransportLayerSecurityRequest : DirectoryRequest
    {
    }

    public class AbandonRequest : DirectoryRequest
    {
        public AbandonRequest(int messageId)
        {
            MessageId = messageId;
        }

    }
}