using LdapForNet;
using LdapForNet.Native;
using Xunit;

namespace LdapForNetTests
{
    public sealed class AttributeCollectionTests
    {
        [Fact]
        public void AttributeCollection_CaseInsensitivity()
        {
            var searchCollection = new SearchResultAttributeCollection();
            var modifyCollection = new ModifyAttributeCollection();
            var gnAttr = new DirectoryAttribute { Name = LdapAttributes.GivenName.ToLowerInvariant() };
            var modifAttr = new DirectoryModificationAttribute { Name = LdapAttributes.GivenName.ToLowerInvariant() };
            searchCollection.Add(gnAttr);
            modifyCollection.Add(modifAttr);

            Assert.True(searchCollection.Contains(LdapAttributes.GivenName.ToUpperInvariant()));
            Assert.True(modifyCollection.Contains(LdapAttributes.GivenName.ToUpperInvariant()));

        }

        [Fact]
        public void ModifyAttributeCollection_Should_Allow_Attributes_With_Same_Name()
        {
	        var attributeCollection = new ModifyAttributeCollection
	        {
		        new DirectoryModificationAttribute {Name = "name", LdapModOperation = Native.LdapModOperation.LDAP_MOD_ADD},
		        new DirectoryModificationAttribute {Name = "name", LdapModOperation = Native.LdapModOperation.LDAP_MOD_REPLACE}
	        };

	        var attribute = attributeCollection["name"];

	        Assert.Equal(2, attributeCollection.Count);
	        Assert.Equal("name", attribute.Name);
        }
	}
}
