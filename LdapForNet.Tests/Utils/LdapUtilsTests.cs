using LdapForNet.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LdapForNetTests.Utils
{
    [TestClass]
    public class LdapUtilsTests
    {
        [TestMethod]
        public void LdapUtils_GetDnFromHostname_Return_Base_Dn()
        {
            var actual = LdapUtils.GetDnFromHostname("uvda01.v04.example.com");
            Assert.AreEqual("dc=v04,dc=example,dc=com", actual);
        }
        
        [TestMethod]
        public void LdapUtils_GetDnFromHostname_Return_Hostname_When_Machine_Not_Joined_To_Domain()
        {
            var actual = LdapUtils.GetDnFromHostname("uvda01");
            Assert.AreEqual("dc=uvda01", actual);
        }
    }
}