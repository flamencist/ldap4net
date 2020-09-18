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
        public static byte[] GetUIntBytes(long value) => CopyOfRange(BitConverter.GetBytes(value), 4, 8);

        /// <summary>
        ///     Gets byte array from integer.
        ///     @param value integer.
        ///     @return byte array.
        /// </summary>
        public static byte[] GetBytes(int value) => BitConverter.GetBytes(value);

        /// <summary>
        ///     Gets byte array from integer.
        ///     @param value integer.
        ///     @param length array size.
        ///     @return byte array.
        /// </summary>
        public static byte[] GetBytes(int value, int length)
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
        ///     Gets bits as bool array from a given byte array.
        ///     @param bytes bytes.
        ///     @return bits.
        /// </summary>
        public static bool[] GetBits(byte[] bytes)
        {
            if (bytes.Length > 4)
            {
                throw new ArgumentOutOfRangeException("Invalid number of bytes");
            }

            var res = new bool[bytes.Length * 8];

            var pos = 0;

            foreach (byte b in bytes)
            {
                foreach (bool boolean in GetBits(b))
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
        public static bool[] GetBits(byte b)
        {
            var res = new bool[8];
            for (var i = 0; i < 8; i++)
            {
                res[7 - i] = (b & (1 << i)) != 0;
            }

            return res;
        }

        /// <summary>
        ///     Reverses bytes and retrieves the corresponding unsigned integer value.
        ///     @param bytes bytes.
        ///     @return unsigned integer.
        /// </summary>
        public static long GetReverseUInt(byte[] bytes) => GetUInt(Hex.Reverse(bytes));

        /// <summary>
        ///     Gets byte array corresponding to the given integer value, reverses obtained byte array and retrieves the new
        ///     integer value.
        ///     @param value integer value.
        ///     @return reversed integer value.
        /// </summary>
        public static int GetReverseInt(int value) => (int) GetReverseUInt(value);

        /// <summary>
        ///     Gets byte array corresponding to the given integer value, reverses obtained byte array and retrieves the new
        ///     unsigned integer value.
        ///     @param value integer value.
        ///     @return reversed unsigned integer value.
        /// </summary>
        public static long GetReverseUInt(int value) => GetReverseUInt(GetBytes(value));

        /// <summary>
        ///     Gets integer value corresponding to the given bytes.
        ///     @param bytes bytes.
        ///     @return integer.
        /// </summary>
        public static int GetInt(params byte[] bytes) => (int) GetUInt(bytes);

        /// <summary>
        ///     Gets unsigned integer value corresponding to the given bytes.
        ///     @param bytes bytes.
        ///     @return unsigned integer.
        /// </summary>
        public static long GetUInt(params byte[] bytes)
        {
            if (bytes.Length > sizeof(uint))
            {
                throw new ArgumentOutOfRangeException("Invalid number of bytes");
            }

            uint res = 0;
            for (var i = 0; i < bytes.Length; i++)
            {
                res |= bytes[i];
                if (i < bytes.Length - 1)
                {
                    res <<= 8;
                }
            }

            return (long)res;
        }
        
        private static T[] CopyOfRange<T>(T[] src, int start, int end)
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