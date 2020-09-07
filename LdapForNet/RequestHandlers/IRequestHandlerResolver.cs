namespace LdapForNet.RequestHandlers
{
    internal interface IRequestHandlerResolver
    {
        RequestHandler Resolve(DirectoryRequest request);
    }
}