using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace LdapForNet
{
    public static class LdapExtendedExtensions
    {
        public static async Task<string> WhoAmI(this ILdapConnection connection, CancellationToken ct = default)
        {
            var response =
                (ExtendedResponse) await connection.SendRequestAsync(new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3"),
                    ct);
            return Utils.Encoder.Instance.GetString(response.ResponseValue);
        }
    }
}