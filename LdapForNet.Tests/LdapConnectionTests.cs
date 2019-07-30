using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using LdapForNet;
using Xunit;
using Xunit.Abstractions;
using static LdapForNet.Native.Native;

namespace LdapForNetTests
{
    public class LdapConnectionTests
    {
        private readonly ITestOutputHelper _testOutputHelper;

        public LdapConnectionTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }
        [Fact]
        public void LdapConnection_Search_Return_LdapEntries_List()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost,Config.LdapPort);
                connection.Bind(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var entries = connection.Search(Config.RootDn, "(&(objectclass=top)(cn=admin))");
                Assert.True(entries.Count == 1);
                Assert.Equal(Config.LdapUserDn, entries[0].Dn);
                Assert.Equal("admin", entries[0].Attributes["cn"][0]);
                Assert.True(entries[0].Attributes["objectClass"].Any());
            }
        }
        
        [Fact]
        public async Task LdapConnection_SearchAsync_Return_LdapEntries_List()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost,Config.LdapPort);
                await connection.BindAsync(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var entries = await connection.SearchAsync(Config.RootDn, "(&(objectclass=top)(cn=admin))");
                Assert.True(entries.Count == 1);
                Assert.Equal(Config.LdapUserDn, entries[0].Dn);
                Assert.Equal("admin", entries[0].Attributes["cn"][0]);
                Assert.True(entries[0].Attributes["objectClass"].Any());
            }
        }
        
        [Fact]
        public void LdapConnection_Search_Throw_LdapException_If_Server_Unavailable()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect("someunknown.host");
                Assert.Throws<LdapException>(() =>
                    connection.Bind(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword));
            }
        }
        
        [Fact]
        public void LdapConnection_Search_Throw_LdapException_If_Search_Syntax_Wrong()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost,Config.LdapPort);
                connection.Bind(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                Assert.Throws<LdapException>(()=>connection.Search("dc=example,dc=com", "(&(objectclass=top)...wrong...)"));
            }
        }
        
        [Fact]
        public void LdapConnection_Search_Throw_LdapException_If_Not_Called_Connect_Method()
        {
            using (var connection = new LdapConnection())
            {
                Assert.Throws<LdapException>(()=>
                    {
                        connection.Bind(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                        return connection.Search("dc=example,dc=com", "(objectclass=top)");
                    })
                ;
            }
        }
        
        [Fact]
        public void LdapConnection_Search_Throw_LdapException_If_Not_Called_Bind_Method()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost);
                Assert.Throws<LdapException>(()=>
                connection.Search("dc=example,dc=com", "(&(objectclass=top)...wrong...)"));
            }
        }


        [Fact]
        public void LdapConnection_Add_Modify_Delete()
        {
            try
            {
                DeleteLdapEntry();
            }
            catch(Exception e)
            {
                _testOutputHelper.WriteLine(e.ToString());
            }
            AddLdapEntry();
            ModifyLdapEntry();
            DeleteLdapEntry();                
        }
        
        
        [Fact]
        public async Task LdapConnection_Add_Modify_Delete_Async()
        {
            try
            {
               await DeleteLdapEntryAsync();
            }
            catch(Exception e)
            {
                _testOutputHelper.WriteLine(e.ToString());
            }
            await AddLdapEntryAsync();
            await ModifyLdapEntryAsync();
            await DeleteLdapEntryAsync();                    
        }

        private async Task ModifyLdapEntryAsync()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                await connection.BindAsync(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                await connection.ModifyAsync(new LdapModifyEntry
                {
                    Dn = $"cn=asyncTest,{Config.RootDn}",
                    Attributes = new List<LdapModifyAttribute>
                    {
                        new LdapModifyAttribute
                        {
                            LdapModOperation = LdapModOperation.LDAP_MOD_REPLACE,
                            Type = "givenname",
                            Values = new List<string> {"test_value_2"}
                        },
                        new LdapModifyAttribute
                        {
                            LdapModOperation = LdapModOperation.LDAP_MOD_ADD,
                            Type = "displayname",
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
                var entries = await connection.SearchAsync(Config.RootDn, "(&(objectclass=top)(cn=asyncTest))");
                Assert.True(entries.Count == 1);
                Assert.Equal($"cn=asyncTest,{Config.RootDn}", entries[0].Dn);
                Assert.Equal("test_value_2", GetAttributeValue(entries[0].Attributes,"givenName")[0]);
                Assert.Equal("test_display_name", GetAttributeValue(entries[0].Attributes,"displayName")[0]);
                Assert.Equal("Winston", entries[0].Attributes["sn"][0]);
                Assert.Equal("test", entries[0].Attributes["sn"][1]);
                Assert.False(entries[0].Attributes.ContainsKey("description"));
            }
        }

        private async Task AddLdapEntryAsync()
        {
            using (var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15)))
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                await connection.BindAsync(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                await connection.AddAsync(new LdapEntry
                {
                    Dn = $"cn=asyncTest,{Config.RootDn}",
                    Attributes = new Dictionary<string, List<string>>
                    {
                        {"sn", new List<string> {"Winston"}},
                        {"objectclass", new List<string> {"inetOrgPerson","top"}},
                        {"givenname", new List<string> {"test_value"}},
                        {"description", new List<string> {"test_value"}}
                    }
                },cts.Token);
                var entries = await connection.SearchAsync(Config.RootDn, "(&(objectclass=top)(cn=asyncTest))",token: cts.Token);
                Assert.True(entries.Count == 1);
                Assert.Equal($"cn=asyncTest,{Config.RootDn}", entries[0].Dn);
                Assert.Equal("test_value", GetAttributeValue(entries[0].Attributes,"givenName")[0]);
                Assert.True(GetAttributeValue(entries[0].Attributes,"objectClass").Any());
            }
        }

        private async Task DeleteLdapEntryAsync()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                await connection.BindAsync(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                await connection.DeleteAsync($"cn=asyncTest,{Config.RootDn}");
                var entries = await connection.SearchAsync(Config.RootDn, "(&(objectclass=top)(cn=asyncTest))");
                Assert.True(entries.Count == 0);
            }
        }


        [Fact]
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
                        {"objectclass", new List<string> {"inetOrgPerson","top"}},
                        {"givenname", new List<string> {"test_value"}},
                        {"description", new List<string> {"test_value"}}
                    }
                });
                connection.Rename(dn, newRdn, null, true);
                var entries = connection.Search(Config.RootDn, $"(&(objectclass=top)(cn={cn}))");
                Assert.True(entries.Count == 0);
                
                var actual = connection.Search(Config.RootDn, $"(&(objectclass=top)({newRdn}))");
                Assert.True(actual.Count == 1);
                
                Assert.Equal($"{newRdn},{Config.RootDn}", actual[0].Dn);
                
                connection.Delete($"{newRdn},{Config.RootDn}");
            }
        }
        
        private void AddLdapEntry()
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
                        {"cn",new List<string>{"test"}},
                        {"sn", new List<string> {"Winston"}},
                        {"objectclass", new List<string> {"inetOrgPerson","top"}},
                        {"givenname", new List<string> {"test_value"}},
                        {"description", new List<string> {"test_value"}}
                    }
                });
                var entries = connection.Search(Config.RootDn, "(&(objectclass=top)(cn=test))");
                Assert.True(entries.Count == 1);
                _testOutputHelper.WriteLine(entries[0].Dn);

                Assert.Equal($"cn=test,{Config.RootDn}", entries[0].Dn);
                Assert.Equal("test_value", GetAttributeValue(entries[0].Attributes,"givenName")[0]);
                Assert.True(GetAttributeValue(entries[0].Attributes,"objectClass").Any());
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
                            Type = "givenname",
                            Values = new List<string> {"test_value_2"}
                        },
                        new LdapModifyAttribute
                        {
                            LdapModOperation = LdapModOperation.LDAP_MOD_ADD,
                            Type = "displayname",
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
                Assert.True(entries.Count == 1);
                Assert.Equal($"cn=test,{Config.RootDn}", entries[0].Dn);
                Assert.Equal("test_value_2", GetAttributeValue(entries[0].Attributes,"givenName")[0]);
                Assert.Equal("test_display_name", GetAttributeValue(entries[0].Attributes,"displayName")[0]);
                Assert.Equal("Winston", entries[0].Attributes["sn"][0]);
                Assert.Equal("test", entries[0].Attributes["sn"][1]);
                Assert.False(entries[0].Attributes.ContainsKey("description"));
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
                Assert.True(entries.Count == 0);
            }
        }
        
        private static List<string> GetAttributeValue(Dictionary<string,List<string>> attributes, string name)
        {
            if (!attributes.TryGetValue(name, out var result))
            {
                if (!attributes.TryGetValue(name.ToLower(), out result))
                {
                    throw new KeyNotFoundException(name);
                }
            }

            return result;
        }

    }
}