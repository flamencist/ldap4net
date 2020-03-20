using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using LdapForNet;
using LdapForNet.Native;
using Xunit;

namespace LdapForNetTests
{
    public class LdapExtendedExtensionsTests
    {
        [Fact]
        public async Task LdapConnection_GetRootDse_Returns_Server_Information()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                await connection.BindAsync(Native.LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                var authorizationId = await connection.WhoAmI();
                Assert.Contains(new List<string>
                {
                    "u:admin",
                    $"dn:{Config.LdapUserDn}"
                }, _=> _.Equals(authorizationId, StringComparison.OrdinalIgnoreCase) );
            }
        }
    }
}
