using System.Linq;
using System.Threading.Tasks;
using LdapForNet;
using LdapForNet.Native;
using Xunit;

namespace LdapForNetTests
{
    public class LdapSearchExtensionsTests
    {
        [Fact]
        public void LdapConnection_SearchByCn_Returns_LdapEntries()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost,Config.LdapPort);
                connection.Bind(Native.LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var entries = connection.SearchByCn(Config.RootDn, "admin");
                Assert.True(entries.Count == 1);
                Assert.Equal(Config.LdapUserDn, entries[0].Dn);
                Assert.Equal("admin", entries[0].Attributes["cn"][0]);
                Assert.True(entries[0].Attributes["objectClass"].Any());
            }
        }
        
        [Fact]
        public async Task LdapConnection_SearchByCnAsync_Returns_LdapEntries()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost,Config.LdapPort);
                await connection.BindAsync(Native.LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var entries = await connection.SearchByCnAsync(Config.RootDn, "admin");
                Assert.True(entries.Count == 1);
                Assert.Equal(Config.LdapUserDn, entries[0].Dn);
                Assert.Equal("admin", entries[0].Attributes["cn"][0]);
                Assert.True(entries[0].Attributes["objectClass"].Any());
            }
        }

        [Fact]
        public async Task LdapConnection_GetRootDse_Returns_Server_Information()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                await connection.BindAsync(Native.LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                var entry = connection.GetRootDse();
                Assert.NotEmpty(entry.Attributes);
            }
        }
    }
}