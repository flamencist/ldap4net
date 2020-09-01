using System;
using System.Text;

namespace LdapForNet.Utils
{
    internal class LdapSidConverter
    {
        private const int SidVersionLength = 2;
        private const int SubAuthorityCountLength = 2;
        private const int AuthorityIdentifierLength = 12;
        private const int SubAuthorityLength = 8;

        internal static string ConvertToHex(string sid)
        {
            var parts = sid.Split('-');
            if (parts.Length < 4 || parts[0] != "S")
            {
                throw new ArgumentException($"Sid is wrong format. Sid: {sid}");
            }

            //"S-1-5-21-2127521184-1604012920-1887927527-72713"
            var sidVersion = byte.Parse(parts[1]).ToString("X"); //01
            var subAuthoirityCount = ((byte) (parts.GetUpperBound(0) - 2)).ToString("X"); //05
            var securityNtAuthority = parts[2]; // 0x00 00 00 00 00 05

            var builder = new StringBuilder();
            builder.Append(sidVersion.PadLeft(SidVersionLength, '0'));
            builder.Append(subAuthoirityCount.PadLeft(SubAuthorityCountLength, '0'));
            builder.Append(securityNtAuthority.PadLeft(AuthorityIdentifierLength, '0'));

            for (var i = 3; i < parts.Length; i++)
            {
                var temp = Convert.ToInt64(parts[i]).ToString("X");
                builder.Append(EndianReverse(temp.PadLeft(SubAuthorityLength, '0')));
            }

            return builder.ToString();
        }

        internal static string ParseFromBytes(byte[] objectSid)
        {
	        var sid = new StringBuilder("S-");

	        // get byte(0) - revision level
	        sid.AppendFormat("{0}", objectSid[0]);

	        // byte(1) - count of sub-authorities
	        var countSubAuths = objectSid[1] & 0xFF;

	        // byte(2-7) - 48 bit authority ([Big-Endian])
	        long authority = 0;

	        for (var i = 2; i <= 7; i++)
	        {
		        authority |= (long)objectSid[i] << (8 * (5 - (i - 2)));
	        }

	        sid.AppendFormat("-{0:X}", authority);

	        // iterate all the sub-auths and then countSubAuths x 32 bit sub authorities ([Little-Endian])
	        var offset = 8;
	        var size = 4; //4 bytes for each sub auth

	        for (var j = 0; j < countSubAuths; j++)
	        {
		        long subAuthority = 0;
		        for (var k = 0; k < size; k++)
		        {
			        subAuthority |= (long)(objectSid[offset + k] & 0xFF) << (8 * k);
		        }

		        // format it
		        sid.AppendFormat("-{0}", subAuthority);

		        offset += size;
	        }

	        return sid.ToString();
        }

        private static string EndianReverse(string hex)
        {
            var reversed = new char[hex.Length];
            for (var i = hex.Length - 1; i > 0; i = i - 2)
            {
                reversed[hex.Length - i - 1] = hex[i - 1];
                reversed[hex.Length - i] = hex[i];
            }

            return new string(reversed);
        }
    }
}