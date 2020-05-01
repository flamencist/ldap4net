using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace LdapForNetTests.TestUtils
{
    public static class RsaUtils
    {
        public enum PemStringType
        {
            Certificate = 1,
            RsaPrivateKey = 2,
            Pkcs8PrivateKey = 3
        }
        
        public static byte[] GetBytesFromPem(string pemString, PemStringType type)
        {
            string header; string footer;
            switch (type)
            {
                case PemStringType.Certificate:
                    header = "-----BEGIN CERTIFICATE-----";
                    footer = "-----END CERTIFICATE-----";
                    break;
                case PemStringType.RsaPrivateKey:
                    header = "-----BEGIN RSA PRIVATE KEY-----";
                    footer = "-----END RSA PRIVATE KEY-----";
                    break;
                case PemStringType.Pkcs8PrivateKey:
                    header = "-----BEGIN PRIVATE KEY-----";
                    footer = "-----END PRIVATE KEY-----";
                    break;
                default:
                    return null;
            }

            var start = pemString.IndexOf(header, StringComparison.Ordinal) + header.Length;
            var end = pemString.IndexOf(footer, start, StringComparison.Ordinal) - start;
            return Convert.FromBase64String(pemString.Substring(start, end));
        }

        public static X509Certificate2 ImportPkcs8PrivateKey(X509Certificate2 cert, byte[] keyBytes )
        {
#if NETCOREAPP3_1
            using (var rsa = RSA.Create())
            {
                rsa.ImportPkcs8PrivateKey(keyBytes, out _);
                return cert.CopyWithPrivateKey(rsa);
            }
#else
            var pkcs8Reader = new AsnReader(keyBytes, AsnEncodingRules.BER);
            Decode(pkcs8Reader,  Asn1Tag.Sequence, out var privateKey);
            var reader = new AsnReader(privateKey.Span.ToArray(), AsnEncodingRules.BER);
            var rsaPrivateKey = reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            return ImportRsaPrivateKey(cert, rsaPrivateKey);
#endif
        }

        private static X509Certificate2 ImportRsaPrivateKey(X509Certificate2 cert, AsnReader rsaPrivateKey)
        {
            if (!rsaPrivateKey.TryReadInt32(out var version) || version != 0)
            {
                throw new InvalidOperationException();
            }

            var modulus = rsaPrivateKey.ReadInteger().ToByteArray(true, true);
            var halfModulusLen = (modulus.Length + 1) / 2;

            var rsaParameters = new RSAParameters
            {
                Modulus = modulus,
                Exponent = rsaPrivateKey.ReadInteger().ToByteArray(true, true),
                D = ReadNormalizedInteger(rsaPrivateKey, modulus.Length),
                P = ReadNormalizedInteger(rsaPrivateKey, halfModulusLen),
                Q = ReadNormalizedInteger(rsaPrivateKey, halfModulusLen),
                DP = ReadNormalizedInteger(rsaPrivateKey, halfModulusLen),
                DQ = ReadNormalizedInteger(rsaPrivateKey, halfModulusLen),
                InverseQ = ReadNormalizedInteger(rsaPrivateKey, halfModulusLen),
            };

            rsaPrivateKey.ThrowIfNotEmpty();

            using (var rsa = RSA.Create())
            {
                rsa.ImportParameters(rsaParameters);
                return cert.CopyWithPrivateKey(rsa);
            }
        }

        private static void Decode(AsnReader reader, Asn1Tag expectedTag, out ReadOnlyMemory<byte> privateKey)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            var sequenceReader = reader.ReadSequence(expectedTag);
            

            if (!sequenceReader.TryReadUInt8(out _))
            {
                sequenceReader.ThrowIfNotEmpty();
            }

            Decode(sequenceReader, Asn1Tag.Sequence);

            privateKey = sequenceReader.TryReadPrimitiveOctetStringBytes(out var tmpPrivateKey) ? tmpPrivateKey : sequenceReader.ReadOctetString();

            sequenceReader.ThrowIfNotEmpty();
        }
        
        private static void Decode(AsnReader reader, Asn1Tag expectedTag)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            var sequenceReader = reader.ReadSequence(expectedTag);
            
            sequenceReader.ReadObjectIdentifier();

            if (sequenceReader.HasData)
            {
                sequenceReader.ReadEncodedValue();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
        
        private static byte[] ReadNormalizedInteger(AsnReader reader, int length)
        {
            var memory = reader.ReadIntegerBytes();
            var span = memory.Span;

            if (span[0] == 0)
            {
                span = span.Slice(1);
            }

            var buf = new byte[length];
            var skipSize = length - span.Length;
            span.CopyTo(buf.AsSpan(skipSize));
            return buf;
        }
    }
}