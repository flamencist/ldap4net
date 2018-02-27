using LdapForNet.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LdapForNetTests.Utils
{
    [TestClass]
    public class DomainUtilsTests
    {
        [TestMethod]
        public void DomainUtils_GetDomainFromHostname()
        {
            var actual = DomainUtils.GetDomainFromHostname("mycomp.v123.example.com");
            Assert.AreEqual("v123.example.com", actual);
        }
        
        [TestMethod]
        public void DomainUtils_GetDomainFromHostname_Return_Hostname_If_Not_Found_Domain()
        {
            var actual = DomainUtils.GetDomainFromHostname("mycomp");
            Assert.AreEqual("mycomp", actual);
        }
    }
}