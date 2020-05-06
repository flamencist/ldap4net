// ReSharper disable InconsistentNaming

namespace LdapForNet.Asn1
{
    internal static class SR
    {
        public const string Argument_EncodeDestinationTooSmall =
            "The destination is too small to hold the encoded value.";

        public const string Cryptography_Der_Invalid_Encoding = "ASN1 corrupted data.";

        public const string Cryptography_Asn_UniversalValueIsFixed =
            "Tags with TagClass Universal must have the appropriate TagValue value for the data type being read or written.";

        public const string Cryptography_AsnWriter_EncodeUnbalancedStack =
            "Encode cannot be called while a Sequence or SetOf is still open.";

        public const string Cryptography_AsnWriter_PopWrongTag =
            "Cannot pop the requested tag as it is not currently in progress.";
    }
}