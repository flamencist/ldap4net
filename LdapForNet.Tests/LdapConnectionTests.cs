using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Castle.Core.Internal;
using LdapForNet;
using LdapForNet.Utils;
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
        
        //[Fact(Skip = "Example of controls with gssapi enabled")]
        [Fact]
        public void LdapConnection_With_Directory_Control_Search_Return_LdapEntries_List()
        {
            using (var connection = new LdapConnection())
            {
                var results = new List<DirectoryEntry>();
                connection.Connect("");
                connection.BindAsync().Wait();
                //var directoryRequest = new SearchRequest(LdapUtils.GetDnFromHostname(), "(&(objectclass=top)(cn=Adam Bäck))",
                var directoryRequest = new SearchRequest("OU=Servers," + LdapUtils.GetDnFromHostname(), "(objectclass=top)",
                    LdapSearchScope.LDAP_SCOPE_SUB){ Attributes = { "cn"}, SizeLimit =  1001};
                var resultRequestControl = new PageResultRequestControl(3);
                directoryRequest.Controls.Add(resultRequestControl);

                var response = (SearchResponse)connection.SendRequest(directoryRequest);
                results.AddRange(response.Entries);

                PageResultResponseControl pageResultResponseControl;
                while (true)
                {
                    pageResultResponseControl = (PageResultResponseControl)response.Controls.FirstOrDefault(_ => _ is PageResultResponseControl);
                    if (pageResultResponseControl == null || pageResultResponseControl.Cookie.Length == 0)
                    {
                        break;
                    }
                    directoryRequest = new SearchRequest("OU=Servers,"+LdapUtils.GetDnFromHostname(), "(objectclass=top)",
                            LdapSearchScope.LDAP_SCOPE_SUB)
                        { Attributes = { "cn" }, SizeLimit = 1001 };
                    resultRequestControl = new PageResultRequestControl(pageResultResponseControl.Cookie){PageSize = 3};
                    directoryRequest.Controls.Add(resultRequestControl);
                    response = (SearchResponse)connection.SendRequest(directoryRequest);
                    results.AddRange(response.Entries);
                    if (response.ResultCode == ResultCode.UnavailableCriticalExtension)
                    {
                        break;
                    }
                }
                var entries = results.Select(_=>_.ToLdapEntry()).ToList();
                Assert.Single(entries);
                Assert.Equal(Config.LdapUserDn, entries[0].Dn);
                Assert.Equal("admin", entries[0].Attributes["cn"][0]);
                Assert.True(entries[0].Attributes["objectClass"].Any());
            }
        }

        [Fact]
        public void LdapConnection_Search_Return_LdapEntries_With_Concrete_Attributes()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                connection.Bind(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                var response = (SearchResponse)connection.SendRequest(new SearchRequest(Config.RootDn, "(&(objectclass=top)(cn=admin))",LdapSearchScope.LDAP_SCOPE_SUBTREE,"cn","objectClass"));
                var entries = response.Entries;
                Assert.Single(entries);
                Assert.Equal(2, entries[0].Attributes.AttributeNames.Count);
                Assert.Equal(Config.LdapUserDn, entries[0].Dn);
                Assert.Equal("admin", entries[0].Attributes["cn"].GetValues<string>().First());
                Assert.True(entries[0].Attributes["objectClass"].GetValues<string>().Any());
            }
        }

        [Fact]
        public async Task LdapConnection_SearchAsync_Retrieve_Binary_Values()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(new Uri($"LDAP://{Config.LdapHost}:{Config.LdapPort}"));
                await connection.BindAsync(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                var response = (SearchResponse)await connection.SendRequestAsync(new SearchRequest(Config.LdapUserDn, "(&(objectclass=top)(cn=admin))", LdapSearchScope.LDAP_SCOPE_SUBTREE), CancellationToken.None);
                _testOutputHelper.WriteLine("ResultCode {0}. ErrorMessage: {1}", response.ResultCode, response.ErrorMessage);
                Assert.Equal(ResultCode.Success, response.ResultCode);
                Assert.NotEmpty(response.Entries);
                var directoryAttribute = response.Entries.First().Attributes["cn"];
                var cnBinary = directoryAttribute.GetValues<byte[]>().First();
                Assert.NotEmpty(cnBinary);
                var actual = new ASCIIEncoding().GetString(cnBinary);
                Assert.Equal("admin", actual);

                var cn = directoryAttribute.GetValues<string>().First();
                Assert.Equal("admin", cn);
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

        /// <summary>
        /// https://github.com/delphij/openldap/blob/master/clients/tools/ldapwhoami.c
        /// </summary>
        /// <returns></returns>
        [Fact]
        public async Task LdapConnection_Extended_Operation_WhoAmI_Async()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost,Config.LdapPort);
                await connection.BindAsync(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var result = await connection.SendRequestAsync(new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3"));
                var extendedResponse = (ExtendedResponse) result;
                Assert.True(result.ResultCode==ResultCode.Success);
                var name = LdapForNet.Utils.Encoder.Instance.GetString(extendedResponse.ResponseValue);
                Assert.Equal($"dn:{Config.LdapUserDn}",name);
            }
        }

        [Fact]
        public async Task LdapConnection_Compare_Operation_Async_Returns_True_If_Attribute_Exists()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost,Config.LdapPort);
                await connection.BindAsync(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var result = await connection.SendRequestAsync(new CompareRequest(new LdapEntry
                {
                    Dn = Config.LdapUserDn,
                    Attributes = new Dictionary<string,List<string>>
                    {
                        ["objectClass"]=new List<string>{"top"}
                    }
                }));
                Assert.True(result.ResultCode==ResultCode.CompareTrue,result.ResultCode.ToString());
            }
        }

        [Fact]
        public async Task LdapConnection_Compare_Operation_Binary_Async_Returns_True_If_Attribute_Exists()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                await connection.BindAsync(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                var result = await connection.SendRequestAsync(new CompareRequest(Config.LdapUserDn,"objectClass",LdapForNet.Utils.Encoder.Instance.GetBytes("top")));
                Assert.True(result.ResultCode == ResultCode.CompareTrue, result.ResultCode.ToString());
            }
        }

        [Fact]
        public async Task LdapConnection_Compare_Operation_String_Async_Returns_True_If_Attribute_Exists()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost, Config.LdapPort);
                await connection.BindAsync(LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
                var result = await connection.SendRequestAsync(new CompareRequest(Config.LdapUserDn, "objectClass", "top"));
                Assert.True(result.ResultCode == ResultCode.CompareTrue, result.ResultCode.ToString());
            }
        }

        [Fact]
        public async Task LdapConnection_Compare_Operation_Async_Returns_False_If_Attribute_Not_Exist()
        {
            using (var connection = new LdapConnection())
            {
                connection.Connect(Config.LdapHost,Config.LdapPort);
                await connection.BindAsync(LdapAuthMechanism.SIMPLE,Config.LdapUserDn, Config.LdapPassword);
                var result = await connection.SendRequestAsync(new CompareRequest(new LdapEntry
                {
                    Dn = Config.LdapUserDn,
                    Attributes = new Dictionary<string,List<string>>
                    {
                        ["objectClass"]=new List<string>{"organizationalUnit"}
                    }
                }));
                Assert.True(result.ResultCode==ResultCode.CompareFalse,result.ResultCode.ToString());
            }
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
                            Values = new List<string> { "имя" }
                        },
                        new LdapModifyAttribute
                        {
                            LdapModOperation = LdapModOperation.LDAP_MOD_ADD,
                            Type = "sn",
                            Values = new List<string> { "數字" }
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
                Assert.Equal("имя", GetAttributeValue(entries[0].Attributes,"displayName")[0]);
                Assert.Equal("Winston", entries[0].Attributes["sn"][0]);
                Assert.Equal("數字", entries[0].Attributes["sn"][1]);
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
                        {"givenname", new List<string> {"винстон"}},
                        {"description", new List<string> {"test_value"}}
                    }
                },cts.Token);
                var entries = await connection.SearchAsync(Config.RootDn, "(&(objectclass=top)(cn=asyncTest))",token: cts.Token);
                Assert.True(entries.Count == 1);
                Assert.Equal($"cn=asyncTest,{Config.RootDn}", entries[0].Dn);
                Assert.Equal("винстон", GetAttributeValue(entries[0].Attributes,"givenName")[0]);
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
                        {"givenname", new List<string> {"винстон"}},
                        {"description", new List<string> {"test_value"}}
                    }
                });
                var entries = connection.Search(Config.RootDn, "(&(objectclass=top)(cn=test))");
                Assert.True(entries.Count == 1);
                _testOutputHelper.WriteLine(entries[0].Dn);

                Assert.Equal($"cn=test,{Config.RootDn}", entries[0].Dn);
                Assert.Equal("винстон", GetAttributeValue(entries[0].Attributes,"givenName")[0]);
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
                            Values = new List<string> { "имя" }
                        },
                        new LdapModifyAttribute
                        {
                            LdapModOperation = LdapModOperation.LDAP_MOD_ADD,
                            Type = "sn",
                            Values = new List<string> { "數字" }
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
                Assert.Equal("имя", GetAttributeValue(entries[0].Attributes,"displayName")[0]);
                Assert.Equal("Winston", entries[0].Attributes["sn"][0]);
                Assert.Equal("數字", entries[0].Attributes["sn"][1]);
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