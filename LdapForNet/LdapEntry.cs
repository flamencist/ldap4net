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
        public Dictionary<string, List<string>> Attributes { get; set; }

        public DirectoryEntry ToDirectoryEntry()
        {
            var directoryEntry = new DirectoryEntry {Dn = Dn, Attributes = new SearchResultAttributeCollection()};
            foreach (var attr in Attributes)
            {
                var item = new DirectoryAttribute
                {
                    Name = attr.Key
                };
                item.AddValues(attr.Value);
                directoryEntry.Attributes.Add(item);
            }

            return directoryEntry;
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
                Attributes = Attributes.ToDictionary(_ => _.Name, _ => _.GetValues<string>().ToList())
            };
        }
        
        public DirectoryAttribute GetAttribute(string attribute) 
            => this.Attributes.Contains(attribute) ? this.Attributes[attribute] : null;

        private static Guid? GetGuid(byte[] bytes) 
            => bytes != null && bytes.Length == 16 ? (Guid?) new Guid(bytes) : null;

        public IEnumerable<string> GetObjectClass() => this.GetStrings(LdapAttributes.ObjectClass);

        public IEnumerable<string> GetSubRefs() => this.GetStrings(LdapAttributes.SubRefs);

        public Guid? GetObjectGuid()
        {
            var objectGuid = this.GetAttribute(LdapAttributes.ObjectGuid);
            return objectGuid != null ? GetGuid(objectGuid.GetValue<byte[]>()) : null;
        }

        public DateTime? GetWhenChanged()
        {
            var whenChanged = this.GetString(LdapAttributes.WhenChanged);
            if (whenChanged != null)
            {
                DateTime date = DateTime.ParseExact(whenChanged, "yyyyMMddHHmmss.f'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal);
                return DateTime.SpecifyKind(date, DateTimeKind.Utc);
            }
            return null;
        }
        
        public DateTime? GetModifyTimestamp()
        {
            var modifyTimestamp = this.GetString(LdapAttributes.ModifyTimestamp);
            if (modifyTimestamp != null)
            {
                DateTime date = DateTime.ParseExact(modifyTimestamp, "yyyyMMddHHmmss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal);
                return DateTime.SpecifyKind(date, DateTimeKind.Utc);
            }
            return null;
        }

        public IEnumerable<string> GetMemberOf() => this.GetStrings(LdapAttributes.MemberOf);

        public UserAccountControl GetUserAccountControl()
        {
            var attribute = this.GetString(LdapAttributes.UserAccountControl);
            return attribute == null ? UserAccountControl.NONE : (UserAccountControl) int.Parse(attribute);
        }

        public int GetPrimaryGroupID()
        {
            var attribute = this.GetString(LdapAttributes.PrimaryGroupID);
            return attribute == null ? 0 : int.Parse(attribute);
        }

        public int GetUserPrimaryID()
        {
            var objectSid = this.GetAttribute(LdapAttributes.ObjectSid)?.GetValue<byte[]>();
            if (objectSid != null)
            {
                return BitConverter.ToInt32(objectSid, objectSid.Length - 4); //last 4 bytes are primary group id
            }

            return -1;
        }

        public string GetString(string attributeName) => this.GetAttribute(attributeName)?.GetValue<string>();
        
        public byte[] GetBytes(string attributeName) => this.GetAttribute(attributeName)?.GetValue<byte[]>();
        
        public IEnumerable<string> GetStrings(string attributeName) => this.GetAttribute(attributeName)?.GetValues<string>()?? Enumerable.Empty<string>();

        public IEnumerable<byte[]> GetByteArrays(string attributeName) => this.GetAttribute(attributeName)?.GetValues<byte[]>() ?? Enumerable.Empty<byte[]>();
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
        private readonly List<object> _values = new List<object>();

        public string Name { get; set; }
        
        public T GetValue<T>()
            where T : class, IEnumerable
        {
            var items = this.GetValues<T>();
            var item = items.FirstOrDefault();
            return item == default(T) ? default : item;
        }

        public IEnumerable<T> GetValues<T>() where T : class, IEnumerable
        {
            if (!_values.Any())
            {
                return Enumerable.Empty<T>();
            }

            var type = typeof(T);
            var valuesType = _values.First().GetType();
            if (type == valuesType)
            {
                return _values.Select(_ => _ as T);
            }

            if (type == typeof(byte[]) && valuesType == typeof(sbyte[]))
            {
                return _values.Select(_ => _ as T);
            }

            if (type == typeof(string))
            {
                return _values.Select(_ => Utils.Encoder.Instance.GetString((byte[]) _))
                    .Select(_ => _ as T);
            }

            if (type == typeof(byte[]))
            {
                return _values.Select(_ => Utils.Encoder.Instance.GetBytes((string) _))
                    .Select(_ => _ as T);
            }

            throw new NotSupportedException(
                $"Not supported type. You could specify 'string' or 'byte[]' of generic methods. Your type is {type.Name}");
        }

        internal List<object> GetRawValues() => _values;

        public void Add<T>(T value) where T : class, IEnumerable
        {
            ThrowIfWrongType<T>();
            _values.Add(value);
        }

        public void AddValues<T>(IEnumerable<T> values) where T : class, IEnumerable
        {
            ThrowIfWrongType<T>();
            _values.AddRange(values);
        }

        private void ThrowIfWrongType<T>() where T : class, IEnumerable
        {
            var type = typeof(T);
            if (type != typeof(string) && type != typeof(byte[]) && type != typeof(sbyte[]))
            {
                throw new NotSupportedException(
                    $"Not supported type. You could specify 'string' or 'byte[]' of generic methods. Your type is {type.Name}");
            }

            if (_values.Any() && _values.First().GetType() != type)
            {
                throw new NotSupportedException($"Not supported type. Type of values is {_values.First().GetType()}");
            }
        }
    }

    public class DirectoryModificationAttribute : DirectoryAttribute
    {
        public Native.Native.LdapModOperation LdapModOperation { get; set; } =
            Native.Native.LdapModOperation.LDAP_MOD_REPLACE;
    }

    public class SearchResultAttributeCollection : KeyedCollection<string, DirectoryAttribute>
    {
        internal SearchResultAttributeCollection()
        {
        }

        public ICollection<string> AttributeNames => Dictionary.Keys;

        protected override string GetKeyForItem(DirectoryAttribute item)
        {
            return item.Name;
        }
    }

    public class ModifyAttributeCollection : KeyedCollection<string, DirectoryModificationAttribute>
    {
        internal ModifyAttributeCollection()
        {
        }

        public ICollection<string> AttributeNames => Dictionary.Keys;

        protected override string GetKeyForItem(DirectoryModificationAttribute item)
        {
            return item.Name + item.LdapModOperation.ToString();
        }
    }
}
