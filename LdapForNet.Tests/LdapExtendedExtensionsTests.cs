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
        /// <summary>
        /// https://github.com/delphij/openldap/blob/master/clients/tools/ldapwhoami.c
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task LdapConnection_Extended_Operation_WhoAmI_Async()
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
                }, _ => _.Equals(authorizationId, StringComparison.OrdinalIgnoreCase));
            }
        }
    }
}