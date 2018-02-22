using System.Linq;
using LdapForNet;
using LdapForNet.Native;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LdapForNetTests
{
    [TestClass]
    public class LdapConnectionTests
    {
        [TestMethod]
        public void LdapConnection_Search_Return_LdapEntries_List()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost);
                connection.Bind(Native.LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var entries = connection.Search("dc=example,dc=com", "(&(objectclass=top)(cn=read-only-admin))");
                Assert.IsTrue(entries.Count == 1);
                Assert.AreEqual("cn=read-only-admin,dc=example,dc=com", entries[0].Dn);
                Assert.AreEqual("Read Only Admin", entries[0].Attributes["sn"][0]);
                Assert.AreEqual("read-only-admin", entries[0].Attributes["cn"][0]);
                Assert.IsTrue(entries[0].Attributes["objectClass"].Any());
                Assert.IsTrue(entries[0].Attributes["objectClass"].Any());
            }
        }
        
        [TestMethod]
        [ExpectedException(typeof(LdapException))]
        public void LdapConnection_Search_Throw_LdapExcepton_If_Server_Unavailable()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect("someunknown.host");
                connection.Bind(Native.LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
            }
        }
        
        [TestMethod]
        [ExpectedException(typeof(LdapException))]
        public void LdapConnection_Search_Throw_LdapExcepton_If_Search_Syntax_Wrong()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost);
                connection.Bind(Native.LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                connection.Search("dc=example,dc=com", "(&(objectclass=top)...wrong...)");
            }
        }
        
        [TestMethod]
        [ExpectedException(typeof(LdapException))]
        public void LdapConnection_Search_Throw_LdapExcepton_If_Not_Called_Connect_Method()
        {
            using (var connection = new LdapConnection())
            {
                connection.Bind(Native.LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                connection.Search("dc=example,dc=com", "(objectclass=top)");
            }
        }
        
        [TestMethod]
        [ExpectedException(typeof(LdapException))]
        public void LdapConnection_Search_Throw_LdapExcepton_If_Not_Called_Bind_Method()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost);
                connection.Search("dc=example,dc=com", "(&(objectclass=top)...wrong...)");
            }
        }
    }
}