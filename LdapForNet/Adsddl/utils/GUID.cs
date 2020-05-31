/*
 * Copyright (C) 2015 Tirasa (info@tirasa.net)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.Text;

namespace LdapForNet.Adsddl.utils
{
    /// <summary>
    ///     Utility class to manage GUID.
    ///     A GUID, also known as a UUID, is a 16-byte structure, intended to serve as a unique identifier for an object. There
    ///     are three representations of a GUID, as described in the following sections.
    ///     <see href="https://msdn.microsoft.com/en-us/library/cc230326.aspx">cc230326</see>
    /// </summary>
    public class GUID
    {
        /// <summary>
        ///     Gets GUID as string.
        ///     @param GUID GUID.
        ///     @return GUID as string.
        /// </summary>
        public static string getGuidAsString(byte[] GUID)
        {
            StringBuilder res = new StringBuilder();

            res.Append(AddLeadingZero(GUID[3] & 0xFF));
            res.Append(AddLeadingZero(GUID[2] & 0xFF));
            res.Append(AddLeadingZero(GUID[1] & 0xFF));
            res.Append(AddLeadingZero(GUID[0] & 0xFF));
            res.Append("-");
            res.Append(AddLeadingZero(GUID[5] & 0xFF));
            res.Append(AddLeadingZero(GUID[4] & 0xFF));
            res.Append("-");
            res.Append(AddLeadingZero(GUID[7] & 0xFF));
            res.Append(AddLeadingZero(GUID[6] & 0xFF));
            res.Append("-");
            res.Append(AddLeadingZero(GUID[8] & 0xFF));
            res.Append(AddLeadingZero(GUID[9] & 0xFF));
            res.Append("-");
            res.Append(AddLeadingZero(GUID[10] & 0xFF));
            res.Append(AddLeadingZero(GUID[11] & 0xFF));
            res.Append(AddLeadingZero(GUID[12] & 0xFF));
            res.Append(AddLeadingZero(GUID[13] & 0xFF));
            res.Append(AddLeadingZero(GUID[14] & 0xFF));
            res.Append(AddLeadingZero(GUID[15] & 0xFF));

            return res.ToString();
        }

        /// <summary>
        ///     Gets GUID as byte array.
        ///     @param GUID GUID.
        ///     @return GUID as byte array.
        /// </summary>
        public static byte[] getGuidAsByteArray(string GUID)
        {
            UUID uuid = UUID.fromString(GUID);

            ByteBuffer buff = ByteBuffer.wrap(new byte[16]);
            buff.putLong(uuid.getMostSignificantBits());
            buff.putLong(uuid.getLeastSignificantBits());

            byte[] res =
            {
                buff.get(3),
                buff.get(2),
                buff.get(1),
                buff.get(0),
                buff.get(5),
                buff.get(4),
                buff.get(7),
                buff.get(6),
                buff.get(8),
                buff.get(9),
                buff.get(10),
                buff.get(11),
                buff.get(12),
                buff.get(13),
                buff.get(14),
                buff.get(15)
            };

            return res;
        }

        private static string AddLeadingZero(int k) => k <= 0xF ? "0" + Integer.toHexString(k) : Integer.toHexString(k);
    }
}