using System;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using LdapForNet;
using LdapForNet.Native;
using LdapForNet.RequestHandlers;
using Moq;
using Xunit;

namespace LdapForNetTests
{
    public class LdapConnectionAbandonTests
    {
	    delegate void InitCallback(ref IntPtr handle, string url );
	    delegate void ParseResultCallback(SafeHandle handle, int mess, int free, LDAP_TIMEVAL timeval, ref IntPtr res);
	    
	    [Fact]
		public async Task LdapConnection_Should_Not_Try_Abandon_Request_After_Request_Complete()
		{
			//arrange
			var requestHandlerResolver = new Mock<IRequestHandlerResolver>();
			var abandonHandler = new Mock<RequestHandler>();
			
			requestHandlerResolver.Setup(_ => _.Resolve(It.IsAny<SearchRequest>())).Returns(new SearchRequestHandler());
			requestHandlerResolver.Setup(_ => _.Resolve(It.IsAny<AbandonRequest>())).Returns(abandonHandler.Object);
			
			using (var connection = new LdapConnection(LdapNative.Instance, requestHandlerResolver.Object ))
			{
				connection.Connect(Config.LdapHost, Config.LdapPort);
				await connection.BindAsync(Native.LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
				var cts = new CancellationTokenSource();
				
				//act
				var entries =  await connection.SearchAsync(Config.RootDn, "(&(objectclass=top)(cn=admin))", token: cts.Token);
				cts.Cancel();
				
			}
			
			//assert
			abandonHandler.Verify(_=>_.SendRequest(It.IsAny<SafeHandle>(), It.IsAny<DirectoryRequest>(), ref It.Ref<int>.IsAny), Times.Never);
		}
		
		[Fact]
		public async Task LdapConnection_Should_Abandon_Request_On_Cancel()
		{
			//arrange
			var requestHandlerResolver = new Mock<IRequestHandlerResolver>();
			var abandonHandler = new Mock<RequestHandler>();
			var searchHandler = new Mock<RequestHandler>();
			var native = new Mock<LdapNative>();
			var ld = Marshal.AllocHGlobal(IntPtr.Size);
			var cts = new CancellationTokenSource();
			
			native.Setup(_ => _.Init(ref It.Ref<IntPtr>.IsAny, It.IsAny<string>()))
				.Callback(new InitCallback((ref IntPtr handle, string url) => handle = ld))
				.Returns(0);
			native.Setup(_ => _.ldap_parse_result(It.IsAny<SafeHandle>(),
					It.IsAny<IntPtr>(), ref It.Ref<int>.IsAny, ref It.Ref<IntPtr>.IsAny,
					ref It.Ref<IntPtr>.IsAny, ref It.Ref<IntPtr>.IsAny, ref It.Ref<IntPtr>.IsAny, It.IsAny<int>()))
				.Returns(0);
			
			native.Setup(_ => _.ldap_result(It.IsAny<SafeHandle>(),
					It.IsAny<int>(),It.IsAny<int>(),It.IsAny<LDAP_TIMEVAL>(),
					ref It.Ref<IntPtr>.IsAny))
				.Callback(new ParseResultCallback((SafeHandle handle, int mess, int free, LDAP_TIMEVAL timeval, ref IntPtr res) =>
				{
					handle.SetHandleAsInvalid();
					Marshal.FreeHGlobal(ld);
					cts.Cancel();
				}))
				.Returns(Native.LdapResultType.LDAP_RES_SEARCH_RESULT);
			
			DirectoryResponse searchResponse = new SearchResponse();
			searchHandler.Setup(_ => _.Handle(It.IsAny<SafeHandle>(), It.IsAny<Native.LdapResultType>(),
					It.IsAny<IntPtr>(), out searchResponse))
				.Returns(LdapResultCompleteStatus.Complete);
			requestHandlerResolver.Setup(_ => _.Resolve(It.IsAny<SearchRequest>())).Returns(searchHandler.Object);
			requestHandlerResolver.Setup(_ => _.Resolve(It.IsAny<AbandonRequest>())).Returns(abandonHandler.Object);
			
			using (var connection = new LdapConnection(native.Object, requestHandlerResolver.Object ))
			{
				connection.Connect(Config.LdapHost, Config.LdapPort);
				await connection.BindAsync(Native.LdapAuthMechanism.SIMPLE, Config.LdapUserDn, Config.LdapPassword);
				
				//act
				var entries = await connection.SearchAsync(Config.RootDn, "(&(objectclass=top)(cn=admin))", token: cts.Token);
				//assert
				abandonHandler.Verify(_=>_.SendRequest(It.IsAny<SafeHandle>(), It.IsAny<DirectoryRequest>(), ref It.Ref<int>.IsAny), Times.Once);
			}
		}
    }
}