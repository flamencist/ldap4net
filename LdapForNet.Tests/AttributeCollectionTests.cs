using LdapForNet;
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
    }
}
