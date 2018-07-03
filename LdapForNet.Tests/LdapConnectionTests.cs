using System;
using System.Collections.Generic;
using System.Linq;
using LdapForNet;
using LdapForNet.Native;
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
                connection.Connect(Config.LdapHost,Config.LdapPort);
                connection.Bind(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var entries = connection.Search(Config.RootDn, "(&(objectclass=top)(cn=admin))");
                Assert.IsTrue(entries.Count == 1);
                Assert.AreEqual(Config.LdapUserDn, entries[0].Dn);
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
        public void LdapConnection_Add_Modify_Delete()
        {
            try
            {
                DeleteLdapEntry();
            }
            catch
            {
                //no catch
            }
            AddLdapEntry();
            ModifyLdapEntry();
            DeleteLdapEntry();                
        }

        [TestMethod]
        public void LdapConnection_Rename_Entry_Dn()
        {
            var cn = Guid.NewGuid().ToString();
            var dn = $"cn={cn},{Config.RootDn}";
            var newRdn = $"cn={Guid.NewGuid().ToString()}";
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                connection.Bind(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                connection.Add(new LdapEntry
                {
                    Dn = dn,
                    Attributes = new Dictionary<string, List<string>>
                    {
                        {"sn", new List<string> {"Winston"}},
                        {"objectclass", new List<string> {"inetOrgPerson"}},
                        {"givenName", new List<string> {"test_value"}},
                        {"description", new List<string> {"test_value"}}
                    }
                });
                connection.Rename(dn, newRdn, null, true);
                var entries = connection.Search(Config.RootDn, $"(&(objectclass=top)(cn={cn}))");
                Assert.IsTrue(entries.Count == 0);
                
                var actual = connection.Search(Config.RootDn, $"(&(objectclass=top)({newRdn}))");
                Assert.IsTrue(actual.Count == 1);
                
                Assert.AreEqual($"{newRdn},{Config.RootDn}", actual[0].Dn);
                
                connection.Delete($"{newRdn},{Config.RootDn}");
            }
        }
        
        private static void AddLdapEntry()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                connection.Bind(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                connection.Add(new LdapEntry
                {
                    Dn = $"cn=test,{Config.RootDn}",
                    Attributes = new Dictionary<string, List<string>>
                    {
                        {"sn", new List<string> {"Winston"}},
                        {"objectclass", new List<string> {"inetOrgPerson"}},
                        {"givenName", new List<string> {"test_value"}},
                        {"description", new List<string> {"test_value"}}
                    }
                });
                var entries = connection.Search(Config.RootDn, "(&(objectclass=top)(cn=test))");
                Assert.IsTrue(entries.Count == 1);
                Assert.AreEqual($"cn=test,{Config.RootDn}", entries[0].Dn);
                Assert.AreEqual("test_value", entries[0].Attributes["givenName"][0]);
                Assert.IsTrue(entries[0].Attributes["objectClass"].Any());
            }
        }
        
        private static void ModifyLdapEntry()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                connection.Bind(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                connection.Modify(new LdapModifyEntry
                {
                    Dn = $"cn=test,{Config.RootDn}",
                    Attributes = new List<LdapModifyAttribute>
                    {
                        new LdapModifyAttribute
                        {
                            LdapModOperation = LdapModOperation.LDAP_MOD_REPLACE,
                            Type = "givenName",
                            Values = new List<string> {"test_value_2"}
                        },
                        new LdapModifyAttribute
                        {
                            LdapModOperation = LdapModOperation.LDAP_MOD_ADD,
                            Type = "displayName",
                            Values = new List<string> {"test_display_name"}
                        },
                        new LdapModifyAttribute
                        {
                            LdapModOperation = LdapModOperation.LDAP_MOD_ADD,
                            Type = "sn",
                            Values = new List<string> {"test"}
                        },
                        new LdapModifyAttribute
                        {
                            LdapModOperation = LdapModOperation.LDAP_MOD_DELETE,
                            Type = "description",
                            Values = new List<string> {"test_value"}
                        }
                    }
                });
                var entries = connection.Search(Config.RootDn, "(&(objectclass=top)(cn=test))");
                Assert.IsTrue(entries.Count == 1);
                Assert.AreEqual($"cn=test,{Config.RootDn}", entries[0].Dn);
                Assert.AreEqual("test_value_2", entries[0].Attributes["givenName"][0]);
                Assert.AreEqual("test_display_name", entries[0].Attributes["displayName"][0]);
                Assert.AreEqual("Winston", entries[0].Attributes["sn"][0]);
                Assert.AreEqual("test", entries[0].Attributes["sn"][1]);
                Assert.IsFalse(entries[0].Attributes.ContainsKey("description"));
            }
        }

        private static void DeleteLdapEntry()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                connection.Bind(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                connection.Delete($"cn=test,{Config.RootDn}");
                var entries = connection.Search(Config.RootDn, "(&(objectclass=top)(cn=test))");
                Assert.IsTrue(entries.Count == 0);
            }
        }
    }
}