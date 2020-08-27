using LdapForNet;
using LdapForNet.Native;
using Xunit;

namespace LdapForNetTests
{
	public class LdapEntryTests
	{
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

		[Fact]
		public void ModifyAttributeCollection_Should_Ignore_Key_Name_Case()
		{
			var attributeCollection = new ModifyAttributeCollection
			{
				new DirectoryModificationAttribute {Name = "name", LdapModOperation = Native.LdapModOperation.LDAP_MOD_ADD},
			};

			var attribute = attributeCollection["NAME"];

			Assert.Equal("name", attribute.Name);
		}

		[Fact]
		public void SearchResultAttributeCollection_Should_Ignore_Key_Name_Case()
		{
			var attributeCollection = new SearchResultAttributeCollection
			{
				new DirectoryAttribute {Name = "name"}
			};

			var attribute = attributeCollection["NAME"];

			Assert.Equal("name", attribute.Name);
		}
	}
}
