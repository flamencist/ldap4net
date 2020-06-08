using System.Linq;
using System.Threading.Tasks;
using LdapForNet;
using LdapForNet.Adsddl;
using LdapForNet.Native;
using LdapForNet.Utils;
using Xunit;

namespace LdapForNetTests
{
    public class AdsddlTest
    {
        [Fact]
        public async Task LdapConnection_GetNtSecurityDescriptor()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                await connection.BindAsync(Native.LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                var directoryRequest = new SearchRequest(LdapUtils.GetDnFromHostname(), "(objectclass=top)",
                    Native.LdapSearchScope.LDAP_SCOPE_BASE){ Attributes = {LdapAttributes.NtSecurityDescriptor}};
                directoryRequest.Controls.Add(new SecurityDescriptorFlagControl(SecurityMasks.Owner | SecurityMasks.Group | SecurityMasks.Dacl | SecurityMasks.Sacl));
                var response = (SearchResponse)await connection.SendRequestAsync(directoryRequest);
                var entry = response.Entries.First();
                byte[] descbytes = entry.GetBytes(LdapAttributes.NtSecurityDescriptor);
                SDDL sddl = new SDDL(descbytes);
                var dacl = sddl.getDacl();
                var revision = sddl.getRevision();
                Assert.Equal(0x01, revision);
            }
        }
    }
}