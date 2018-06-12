using System.Collections.Generic;
using System.Linq;
using LdapForNet;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using static LdapForNet.Native.Native;

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
                connection.Bind(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var entries = connection.Search("dc=example,dc=com", "(&(objectclass=top)(cn=read-only-admin))");
                Assert.IsTrue(entries.Count == 1);
                Assert.AreEqual("cn=read-only-admin,dc=example,dc=com", entries[0].Dn);
                Assert.AreEqual("Read Only Admin", entries[0].Attributes["sn"][0]);
                Assert.AreEqual("read-only-admin", entries[0].Attributes["cn"][0]);
                Assert.IsTrue(entries[0].Attributes["objectClass"].Any());
            }
        }
        
        [TestMethod]
        public void LdapConnection_Search_Return_LdapEntries_List2()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost2,Config.LdapPort2);
                connection.Bind(LdapAuthMechanism.SIMPLE,Config.LdapUserDn2, Config.LdapPassword2);
                var entries = connection.Search(Config.RootDn2, "(&(objectclass=top)(cn=admin))");
                Assert.IsTrue(entries.Count == 1);
                Assert.AreEqual(Config.LdapUserDn2, entries[0].Dn);
                Assert.AreEqual("admin", entries[0].Attributes["cn"][0]);
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
                connection.Bind(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
            }
        }
        
        [TestMethod]
        [ExpectedException(typeof(LdapException))]
        public void LdapConnection_Search_Throw_LdapExcepton_If_Search_Syntax_Wrong()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost);
                connection.Bind(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                connection.Search("dc=example,dc=com", "(&(objectclass=top)...wrong...)");
            }
        }
        
        [TestMethod]
        [ExpectedException(typeof(LdapException))]
        public void LdapConnection_Search_Throw_LdapExcepton_If_Not_Called_Connect_Method()
        {
            using (var connection = new LdapConnection())
            {
                connection.Bind(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
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


        [TestMethod]
        public void LdapConnection_Add_Delete()
        {
            try
            {
                AddLdapEntry();
            }
            finally
            {
                DeleteLdapEntry();                
            }
        }

        private static void AddLdapEntry()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost2, Config.LdapPort2);
                connection.Bind(LdapAuthMechanism.SIMPLE, Config.LdapUserDn2, Config.LdapPassword2);
                connection.Add(new LdapEntry
                {
                    Dn = $"cn=test,{Config.RootDn2}",
                    Attributes = new Dictionary<string, List<string>>
                    {
                        {"sn", new List<string> {"Winston"}},
                        {"objectclass", new List<string> {"inetOrgPerson"}},
                        {"givenName", new List<string> {"test_value"}}
                    }
                });
                var entries = connection.Search(Config.RootDn2, "(&(objectclass=top)(cn=test))");
                Assert.IsTrue(entries.Count == 1);
                Assert.AreEqual($"cn=test,{Config.RootDn2}", entries[0].Dn);
                Assert.AreEqual("test_value", entries[0].Attributes["givenName"][0]);
                Assert.IsTrue(entries[0].Attributes["objectClass"].Any());
            }
        }

        private static void DeleteLdapEntry()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost2, Config.LdapPort2);
                connection.Bind(LdapAuthMechanism.SIMPLE, Config.LdapUserDn2, Config.LdapPassword2);
                connection.Delete($"cn=test,{Config.RootDn2}");
                var entries = connection.Search(Config.RootDn2, "(&(objectclass=top)(cn=test))");
                Assert.IsTrue(entries.Count == 0);
            }
        }
    }
}