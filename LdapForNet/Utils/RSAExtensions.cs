using System.Security.Cryptography;
using LdapForNet.Asn1;

namespace LdapForNet.Utils
{
    internal static  class RSAExtensions
    {
        public static byte[] ToRsaPrivateKey(this RSA rsa)
        {
#if NETSTANDARD2_1
            return rsa.ExportRSAPrivateKey();
#else
            var rsaParameters = rsa.ExportParameters(true);
            
            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();

            writer.WriteInteger(0);
            writer.WriteKeyParameterInteger(rsaParameters.Modulus);
            writer.WriteKeyParameterInteger(rsaParameters.Exponent);
            writer.WriteKeyParameterInteger(rsaParameters.D);
            writer.WriteKeyParameterInteger(rsaParameters.P);
            writer.WriteKeyParameterInteger(rsaParameters.Q);
            writer.WriteKeyParameterInteger(rsaParameters.DP);
            writer.WriteKeyParameterInteger(rsaParameters.DQ);
            writer.WriteKeyParameterInteger(rsaParameters.InverseQ);

            writer.PopSequence();
            return writer.Encode();
#endif
        }
    }
}