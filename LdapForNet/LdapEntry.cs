using LdapForNet.Utils;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;

namespace LdapForNet
{
    public class LdapEntry
    {
        public string Dn { get; set; }

        [Obsolete]
        public Dictionary<string, List<string>> Attributes
        {
            get { return DirectoryAttributes.ToDictionary(_ => _.Name, _ => _.GetValues<string>().ToList()); }
            set
            {
                DirectoryAttributes = new SearchResultAttributeCollection();
                foreach (var attribute in value)
                {
                    var directoryAttribute = new DirectoryAttribute
                    {
                        Name = attribute.Key
                    };
                    directoryAttribute.AddValues(attribute.Value);
                    DirectoryAttributes.Add(directoryAttribute);
                }
            }
        }

        public SearchResultAttributeCollection DirectoryAttributes { get; set; }

        public DirectoryEntry ToDirectoryEntry()
        {
            return new DirectoryEntry { Dn = Dn, Attributes = DirectoryAttributes };
        }
    }

    public class DirectoryEntry
    {
        public string Dn { get; set; }
        public SearchResultAttributeCollection Attributes { get; set; }

        public LdapEntry ToLdapEntry()
        {
            return new LdapEntry
            {
                Dn = Dn,
                DirectoryAttributes = Attributes
            };
        }

        public DirectoryAttribute GetAttribute(string attribute) => Attributes.FirstOrDefault(x => string.Equals(x.Name, attribute, StringComparison.OrdinalIgnoreCase));

        private static Guid? GetGuid(byte[] bytes) => bytes != null && bytes.Length == 16 ? (Guid?)new Guid(bytes) : null;

        public string GetObjectSid() => LdapSidConverter.ParseFromBytes(GetBytes("objectSid"));

        public IEnumerable<string> GetObjectClass() => GetStrings(LdapAttributes.ObjectClass);

        public IEnumerable<string> GetSubRefs() => GetStrings(LdapAttributes.SubRefs);

        public Guid? GetObjectGuid()
        {
            var objectGuid = GetAttribute(LdapAttributes.ObjectGuid);
            return objectGuid != null ? GetGuid(objectGuid.GetValue<byte[]>()) : null;
        }

        public DateTime? GetWhenChanged()
        {
            var whenChanged = GetString(LdapAttributes.WhenChanged);
            if (whenChanged != null)
            {
                var date = DateTime.ParseExact(whenChanged, "yyyyMMddHHmmss.f'Z'", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal);
                return DateTime.SpecifyKind(date, DateTimeKind.Utc);
            }

            return null;
        }

        public DateTime? GetModifyTimestamp()
        {
            var modifyTimestamp = GetString(LdapAttributes.ModifyTimestamp);
            if (modifyTimestamp != null)
            {
                var date = DateTime.ParseExact(modifyTimestamp, "yyyyMMddHHmmss'Z'", CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeLocal);
                return DateTime.SpecifyKind(date, DateTimeKind.Utc);
            }

            return null;
        }

        public IEnumerable<string> GetMemberOf() => GetStrings(LdapAttributes.MemberOf);

        public UserAccountControl GetUserAccountControl()
        {
            var attribute = GetString(LdapAttributes.UserAccountControl);
            return attribute == null ? UserAccountControl.NONE : (UserAccountControl)int.Parse(attribute);
        }

        public int GetPrimaryGroupID()
        {
            var attribute = GetString(LdapAttributes.PrimaryGroupID);
            return attribute == null ? 0 : int.Parse(attribute);
        }

        public int GetUserPrimaryID()
        {
            var objectSid = GetAttribute(LdapAttributes.ObjectSid)?.GetValue<byte[]>();
            if (objectSid != null)
                return BitConverter.ToInt32(objectSid, objectSid.Length - 4); //last 4 bytes are primary group id

            return -1;
        }

        public string GetString(string attributeName) => GetAttribute(attributeName)?.GetValue<string>();

        public byte[] GetBytes(string attributeName) => GetAttribute(attributeName)?.GetValue<byte[]>();

        public IEnumerable<string> GetStrings(string attributeName) => GetAttribute(attributeName)?.GetValues<string>() ?? Enumerable.Empty<string>();

        public IEnumerable<byte[]> GetByteArrays(string attributeName) => GetAttribute(attributeName)?.GetValues<byte[]>() ?? Enumerable.Empty<byte[]>();
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

        public Native.Native.LdapModOperation LdapModOperation { get; set; } =
            Native.Native.LdapModOperation.LDAP_MOD_REPLACE;
    }

    public class DirectoryAttribute
    {
        private List<byte[]> _byteValues;
        private List<string> _stringValues;

        public string Name { get; set; }

        public T GetValue<T>()
            where T : class, IEnumerable
        {
            var items = GetValues<T>();
            var item = items.FirstOrDefault();
            return item == default(T) ? default : item;
        }

        public IReadOnlyList<T> GetValues<T>() where T : class, IEnumerable
        {
            var type = typeof(T);

            if (type == typeof(string))
            {
                if (_stringValues == null)
                {
                    if (_byteValues == null)
                    {
                        _stringValues = new List<string>(0);
                    }
                    else
                    {
                        _stringValues = new List<string>(_byteValues.Count);
                        for (int i = 0; i < _byteValues.Count; i++)
                        {
                            _stringValues.Add(Encoder.Instance.GetString(_byteValues[i]));
                        }
                    }
                }

                return (IReadOnlyList<T>)_stringValues;
            }

            if (type == typeof(byte[]))
            {
                if (_byteValues == null)
                {
                    if (_stringValues == null)
                    {
                        _byteValues = new List<byte[]>(0);
                    }
                    else
                    {
                        _byteValues = new List<byte[]>(_stringValues.Count);
                        for (int i = 0; i < _stringValues.Count; i++)
                        {
                            _byteValues.Add(Encoder.Instance.GetBytes(_stringValues[i]));
                        }
                    }
                }

                return (IReadOnlyList<T>)_byteValues;
            }

            throw new NotSupportedException(
                $"Not supported type. You could specify 'string' or 'byte[]' of generic methods. Your type is {type.Name}");
        }

        internal IList GetRawValues()
        {
            return _stringValues ?? (IList)_byteValues;
        }

        public void Add<T>(T value) where T : class, IEnumerable
        {
            ThrowIfWrongType<T>();
            if (value is string svalue)
            {
                _stringValues ??= new List<string>();

                _stringValues.Add(svalue);
            }
            else if (value is byte[] bvalue)
            {
                _byteValues ??= new List<byte[]>();

                _byteValues.Add(bvalue);
            }
            else if (value is sbyte[] sbvalue)
            {
                var targetValue = new byte[sbvalue.Length];
                for (int i = 0; i < sbvalue.Length; i++)
                {
                    targetValue[i] = (byte)sbvalue[i];
                }

                _byteValues ??= new List<byte[]>();

                _byteValues.Add(targetValue);
            }
        }

        public void AddValues<T>(IEnumerable<T> values) where T : class, IEnumerable
        {
            ThrowIfWrongType<T>();
            foreach (var value in values)
            {
                Add<T>(value);
            }
        }

        private void ThrowIfWrongType<T>() where T : class, IEnumerable
        {
            var type = typeof(T);
            if (type != typeof(string) && type != typeof(byte[]) && type != typeof(sbyte[]))
                throw new NotSupportedException(
                    $"Not supported type. You could specify 'string' or 'byte[]' of generic methods. Your type is {type.Name}");

            if ((_stringValues != null && typeof(T) != typeof(string)) || (_byteValues != null && typeof(T) != typeof(byte[]) && typeof(T) != typeof(sbyte[])))
                throw new NotSupportedException($"Not supported type. Type of values is {(_stringValues != null ? typeof(string) : typeof(byte[]))}");
        }
    }

    public class DirectoryModificationAttribute : DirectoryAttribute
    {
        public Native.Native.LdapModOperation LdapModOperation { get; set; } =
            Native.Native.LdapModOperation.LDAP_MOD_REPLACE;
    }

    public abstract class DirectoryAttributeCollectionBase<T> : List<T>
        where T : DirectoryAttribute
    {
        public IEnumerable<string> AttributeNames =>
            this.Select(x => x.Name);

        public bool Contains(string attribute)
        {
            return this.Any(x => string.Equals(x.Name, attribute, StringComparison.OrdinalIgnoreCase));
        }

        public DirectoryAttribute this[string attribute]
        {
            get
            {
                var item = this.FirstOrDefault(
                    x => string.Equals(x.Name, attribute, StringComparison.OrdinalIgnoreCase));

                if (item == null) throw new KeyNotFoundException();

                return item;
            }
        }

        public bool TryGetValue(string attribute, out DirectoryAttribute item)
        {
            item = this.FirstOrDefault(x => string.Equals(x.Name, attribute, StringComparison.OrdinalIgnoreCase));

            if (item == null) return false;

            return true;
        }

        public bool Remove(string attribute)
        {
            var found = false;

            for (var i = 0; i < Count; i++)
                if (string.Equals(this[i].Name, attribute, StringComparison.OrdinalIgnoreCase))
                {
                    RemoveAt(i);
                    --i;

                    found = true;
                }

            return found;
        }
    }

    public class SearchResultAttributeCollection : KeyedCollection<string, DirectoryAttribute>
    {
        public SearchResultAttributeCollection()
            : base(StringComparer.OrdinalIgnoreCase)
        {
        }

        public ICollection<string> AttributeNames => Dictionary.Keys;

        protected override string GetKeyForItem(DirectoryAttribute item)
        {
            return item.Name;
        }
    }

    public class ModifyAttributeCollection : DirectoryAttributeCollectionBase<DirectoryModificationAttribute>
    {
        internal ModifyAttributeCollection()
        {
        }
    }
}