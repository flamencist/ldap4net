using LdapForNet.Utils;
using Xunit;

namespace LdapForNetTests.Utils
{
    public class DomainUtilsTests
    {
        [Fact]
        public void DomainUtils_GetDomainFromHostname()
        {
            var actual = DomainUtils.GetDomainFromHostname("mycomp.v123.example.com");
            Assert.Equal("v123.example.com", actual);
        }
        
        [Fact]
        public void DomainUtils_GetDomainFromHostname_Return_Hostname_If_Not_Found_Domain()
        {
            var actual = DomainUtils.GetDomainFromHostname("mycomp");
            Assert.Equal("mycomp", actual);
        }
    }
}