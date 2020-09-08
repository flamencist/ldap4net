namespace LdapForNet.RequestHandlers
{
    internal class RequestHandlerResolver : IRequestHandlerResolver
    {
        public RequestHandler Resolve(DirectoryRequest request)
        {
            switch (request)
            {
                case AddRequest _:
                    return new AddRequestHandler();
                case ModifyRequest _:
                    return new ModifyRequestHandler();
                case SearchRequest _:
                    return new SearchRequestHandler();
                case DeleteRequest _:
                    return new DeleteRequestHandler();
                case ModifyDNRequest _:
                    return new ModifyDnRequestHandler();
                case CompareRequest _:
                    return new CompareRequestHandler();
                case ExtendedRequest _:
                    return new ExtendedRequestHandler();
                case TransportLayerSecurityRequest _:
                    return new TransportLayerSecurityRequestHandler();
                case AbandonRequest _:
                    return new AbandonRequestHandler();
                default:
                    throw new LdapException(new LdapExceptionData("Not supported operation of request: " + request?.GetType()));
            }
        }
    }
}