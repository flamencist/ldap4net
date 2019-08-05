using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using LdapForNet;
using LdapForNet.Native;
using LdapForNet.RequestHandlers;
using LdapForNet.Utils;
using Moq;
using Xunit;

namespace LdapForNetTests.RequestHandlers
{
    public class SearchRequestHandlerTests
    {
        [Fact]
        public void SendRequest_Should_Send_SearchRequest()
        {
            var native = new Mock<LdapNative>();
            var requestHandler = CreateRequestHandler(native);
            var messageId = 0;
            var dn = "cn=admin,dc=example,dc=com";
            var ldapSearchScope = Native.LdapSearchScope.LDAP_SCOPE_SUBTREE;
            var ldapFilter = "(objectclass=*)";

            native.Setup(_ => _.Search(It.IsAny<LdapHandle>(), dn, (int)ldapSearchScope, ldapFilter,
                    It.IsAny<IntPtr>(), It.IsAny<int>(),
                    It.IsAny<IntPtr>(), It.IsAny<IntPtr>(), It.IsAny<int>(), It.IsAny<int>(), ref messageId))
                .Returns(20);

            
            var res = requestHandler.SendRequest(new LdapHandle(IntPtr.Zero), 
                new SearchRequest(dn, ldapFilter, ldapSearchScope), ref messageId);
            Assert.Equal(20,res);
            native.Verify(_=>_.Search(It.IsAny<LdapHandle>(), dn, (int)ldapSearchScope, ldapFilter,
                IntPtr.Zero, (int)Native.LdapSearchAttributesOnly.False,
                IntPtr.Zero, IntPtr.Zero, 0, (int)Native.LdapSizeLimit.LDAP_NO_LIMIT, ref messageId), Times.Once);
            
        }

        [Fact]
        public void Handle_Should_Returns_SearchResponse()
        {
            var native = new Mock<LdapNative>();
            var requestHandler = CreateRequestHandler(native);
            var msg = IntPtr.Zero;
            var ldapHandle = new LdapHandle(IntPtr.Zero);
            var entry = new IntPtr(1);
            var dn = "cn=admin,dc=example,dc=com";
            var attribute = new KeyValuePair<string, List<string>>("cn",new List<string>(2){"admin",null});
            var attributeNamePtr = Marshal.StringToHGlobalAnsi(attribute.Key);
            var dnPtr = Marshal.StringToHGlobalAnsi(dn);
            var valuesPtr = Marshal.AllocHGlobal(IntPtr.Size*attribute.Value.Count);
            MarshalUtils.StringArrayToPtr(attribute.Value, valuesPtr);
            
            native.Setup(_ => _.ldap_first_entry(ldapHandle, msg))
                .Returns(entry);
            native.Setup(_ => _.ldap_next_entry(ldapHandle, msg))
                .Returns(IntPtr.Zero);
            native.Setup(_ => _.ldap_get_dn(ldapHandle, entry))
                .Returns(dnPtr);
            native.Setup(_ => _.ldap_memfree(It.IsAny<IntPtr>()))
                .Callback((IntPtr ptr) => Marshal.FreeHGlobal(ptr));
            native.Setup(_ => _.ldap_first_attribute(ldapHandle, entry, ref It.Ref<IntPtr>.IsAny))
                .Returns(attributeNamePtr);
            native.Setup(_ => _.ldap_next_attribute(ldapHandle, entry, It.IsAny<IntPtr>()))
                .Returns(IntPtr.Zero);
            native.Setup(_ => _.ldap_get_values(ldapHandle, entry, attributeNamePtr))
                .Returns(valuesPtr);
            native.Setup(_ => _.ldap_value_free(It.IsAny<IntPtr>()))
                .Callback((IntPtr ptr) => Marshal.FreeHGlobal(ptr));
            
            var status = requestHandler.Handle(ldapHandle,
                Native.LdapResultType.LDAP_RES_SEARCH_ENTRY, msg, out _);
            Assert.Equal(LdapResultCompleteStatus.Partial,status);
            
            status =  requestHandler.Handle(ldapHandle,
                Native.LdapResultType.LDAP_RES_SEARCH_RESULT, msg, out var actual);
            Assert.Equal(LdapResultCompleteStatus.Complete,status);
            Assert.IsType<SearchResponse>(actual);
            var searchResult = actual as SearchResponse;
            Assert.NotNull(searchResult);
            Assert.Single(searchResult.Entries);
            Assert.Equal(dn,searchResult.Entries[0].Dn);
            Assert.Single(searchResult.Entries[0].Attributes);
            Assert.True(searchResult.Entries[0].Attributes.ContainsKey(attribute.Key));
            Assert.Equal(attribute.Value[0], searchResult.Entries[0].Attributes[attribute.Key][0]);
        }

        private static SearchRequestHandler CreateRequestHandler(IMock<LdapNative> native)
        {
            var searchRequestHandler = new SearchRequestHandler();
            searchRequestHandler.SetNative(native.Object);
            return searchRequestHandler;
        }
    }
}