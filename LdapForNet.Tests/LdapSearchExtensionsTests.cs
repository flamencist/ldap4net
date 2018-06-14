using System.Linq;
using LdapForNet;
using LdapForNet.Native;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LdapForNetTests
{
    [TestClass]
    public class LdapSearchExtensionsTests
    {
        [TestMethod]
        public void LdapConnection_SearchByCn_Returns_LdapEntries()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost,Config.LdapPort);
                connection.Bind(Native.LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var entries = connection.SearchByCn(Config.RootDn, "admin");
                Assert.IsTrue(entries.Count == 1);
                Assert.AreEqual(Config.LdapUserDn, entries[0].Dn);
                Assert.AreEqual("admin", entries[0].Attributes["cn"][0]);
                Assert.IsTrue(entries[0].Attributes["objectClass"].Any());
            }
        }
    }
}