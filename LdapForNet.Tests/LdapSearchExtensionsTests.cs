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
                connection.Connect(Config.LdapHost);
                connection.Bind(Native.LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var entries = connection.SearchByCn("dc=example,dc=com", "read-only-admin");
                Assert.IsTrue(entries.Count == 1);
                Assert.AreEqual("cn=read-only-admin,dc=example,dc=com", entries[0].Dn);
                Assert.AreEqual("Read Only Admin", entries[0].Attributes["sn"][0]);
                Assert.AreEqual("read-only-admin", entries[0].Attributes["cn"][0]);
                Assert.IsTrue(entries[0].Attributes["objectClass"].Any());
                Assert.IsTrue(entries[0].Attributes["objectClass"].Any());
            }
        }
    }
}