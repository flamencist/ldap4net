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

using System;

namespace LdapForNet.Adsddl.utils
{
    /// <summary>
    ///     Utility class to be used to manipulate byte arrays and numbers.
    /// </summary>
    public class NumberFacility
    {
        /// <summary>
        ///     Gets byte array corresponding to a given unsigned integer.
        ///     @param value unsigned integer.
        ///     @return byte array.
        /// </summary>
        public static byte[] getUIntBytes(long value) => copyOfRange(BitConverter.GetBytes(value), 4, 8);

        /// <summary>
        ///     Gets byte array from integer.
        ///     @param value integer.
        ///     @return byte array.
        /// </summary>
        public static byte[] getBytes(int value) => BitConverter.GetBytes(value);

        /// <summary>
        ///     Gets byte array from integer.
        ///     @param value integer.
        ///     @param length array size.
        ///     @return byte array.
        /// </summary>
        public static byte[] getBytes(int value, int length)
        {
            var arr = new byte[length];
            var bytes = BitConverter.GetBytes(value);
            for (int i = length-bytes.Length; i < length; i++)
            {
                arr[i] = bytes[i];
            }
            return arr;
        }

        /// <summary>
        ///     Remove 0x00 bytes from left side.
        ///     @param bytes source array.
        ///     @return trimmed array.
        /// </summary>
        public static byte[] leftTrim(byte[] bytes)
        {
            var pos = 0;
            for (; pos < bytes.Length && bytes[pos] == 0x00; pos++) ;

            if (pos < bytes.Length)
            {
                return copyOfRange(bytes, pos, bytes.Length);
            }

            return new byte[] { 0x00 };
        }

        /// <summary>
        ///     Remove 0x00 bytes from right side.
        ///     @param bytes source array.
        ///     @return trimmed array.
        /// </summary>
        public static byte[] rightTrim(byte[] bytes) => Hex.reverse(leftTrim(Hex.reverse(bytes)));

        /// <summary>
        ///     Gets bits as bool array from a given byte array.
        ///     @param bytes bytes.
        ///     @return bits.
        /// </summary>
        public static bool[] getBits(byte[] bytes)
        {
            if (bytes.Length > 4)
            {
                throw new ArgumentOutOfRangeException("Invalid number of bytes");
            }

            var res = new bool[bytes.Length * 8];

            var pos = 0;

            foreach (byte b in bytes)
            {
                foreach (bool boolean in getBits(b))
                {
                    res[pos] = boolean;
                    pos++;
                }
            }

            return res;
        }

        /// <summary>
        ///     Gets bits as bool array from a given byte.
        ///     @param b byte.
        ///     @return bits.
        /// </summary>
        public static bool[] getBits(byte b)
        {
            var res = new bool[8];
            for (var i = 0; i < 8; i++)
            {
                res[7 - i] = (b & (1 << i)) != 0;
            }

            return res;
        }

        /// <summary>
        ///     Reverts bytes and retrieves the corresponding integer value.
        ///     @param bytes bytes.
        ///     @return integer.
        /// </summary>
        public static int getReverseInt(byte[] bytes) => (int) getReverseUInt(bytes);

        /// <summary>
        ///     Reverses bytes and retrieves the corresponding unsigned integer value.
        ///     @param bytes bytes.
        ///     @return unsigned integer.
        /// </summary>
        public static long getReverseUInt(byte[] bytes) => getUInt(Hex.reverse(bytes));

        /// <summary>
        ///     Gets byte array corresponding to the given integer value, reverses obtained byte array and retrieves the new
        ///     integer value.
        ///     @param value integer value.
        ///     @return reversed integer value.
        /// </summary>
        public static int getReverseInt(int value) => (int) getReverseUInt(value);

        /// <summary>
        ///     Gets byte array corresponding to the given integer value, reverses obtained byte array and retrieves the new
        ///     unsigned integer value.
        ///     @param value integer value.
        ///     @return reversed unsigned integer value.
        /// </summary>
        public static long getReverseUInt(int value) => getReverseUInt(getBytes(value));

        /// <summary>
        ///     Gets integer value corresponding to the given bytes.
        ///     @param bytes bytes.
        ///     @return integer.
        /// </summary>
        public static int getInt(params byte[] bytes) => (int) getUInt(bytes);

        /// <summary>
        ///     Gets unsigned integer value corresponding to the given bytes.
        ///     @param bytes bytes.
        ///     @return unsigned integer.
        /// </summary>
        public static long getUInt(params byte[] bytes)
        {
            if (bytes.Length > 4)
            {
                throw new ArgumentOutOfRangeException("Invalid number of bytes");
            }

            long res = 0;
            for (var i = 0; i < bytes.Length; i++)
            {
                res |= bytes[i] & 0xFF;
                if (i < bytes.Length - 1)
                {
                    res <<= 8;
                }
            }

            return res;
        }
        
        private static T[] copyOfRange<T>(T[] src, int start, int end)
        {
            int len = end - start;
            var dest = new T[len];
            for (int i = 0; i < len; i++)
            {
                dest[i] = src[start + i]; // so 0..n = 0+x..n+x
            }
            return dest;
        }
    }
}