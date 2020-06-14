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
    ///     Utility class to be used to convert byte arrays into hexadecimal strings.
    /// </summary>
    public class Hex
    {
        /// <summary>
        ///     Gets hex string corresponding to the given byte array from "<tt>from</tt>" position to "<tt>to's</tt>"
        ///     @param bytes bytes.
        ///     @param from from position.
        ///     @param to to position.
        ///     @return hex string.
        /// </summary>
        public static string Get(byte[] bytes, int from, int to)
        {
            StringBuilder bld = new StringBuilder();
            for (int i = from; i < to; i++)
            {
                bld.Append(Get(bytes[i]));
            }

            return bld.ToString();
        }

        /// <summary>
        ///     Gets hex string corresponding to the given bytes.
        ///     @param bytes bytes.
        ///     @return hex string.
        /// </summary>
        public static string Get(byte[] bytes)
        {
            StringBuilder bld = new StringBuilder();
            foreach (byte b in bytes)
            {
                bld.Append(Get(b));
            }

            return bld.ToString();
        }

        /// <summary>
        ///     Gets escaped hex string corresponding to the given bytes.
        ///     @param bytes bytes.
        ///     @return escaped hex string
        /// </summary>
        public static string GetEscaped(byte[] bytes)
        {
            StringBuilder bld = new StringBuilder();
            foreach (byte b in bytes)
            {
                bld.Append("\\").Append(Get(b));
            }

            return bld.ToString();
        }

        /// <summary>
        ///     Gets hex string corresponding to the given byte.
        ///     @param b byte.
        ///     @return hex string.
        /// </summary>
        public static string Get(byte b) => string.Format("%02X", b);

        /// <summary>
        ///     Reverses bytes.
        ///     @param bytes bytes.
        ///     @return reversed byte array.
        /// </summary>
        public static byte[] Reverse(byte[] bytes)
        {
            var res = new byte[bytes.Length];
            var j = 0;
            for (int i = bytes.Length - 1; i >= 0; i--)
            {
                res[j] = bytes[i];
                j++;
            }

            return res;
        }
    }
}