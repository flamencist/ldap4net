using LdapForNet.Utils;
using Xunit;

namespace LdapForNetTests.Utils
{
    public class LdapUtilsTests
    {
        [Fact]
        public void LdapUtils_GetDnFromHostname_Return_Base_Dn()
        {
            var actual = LdapUtils.GetDnFromHostname("uvda01.v04.example.com");
            Assert.Equal("dc=v04,dc=example,dc=com", actual);
        }

        [Fact]
        public void LdapUtils_GetDnFromHostname_Return_Hostname_When_Machine_Not_Joined_To_Domain()
        {
            var actual = LdapUtils.GetDnFromHostname("uvda01");
            Assert.Equal("dc=uvda01", actual);
        }
    }
}