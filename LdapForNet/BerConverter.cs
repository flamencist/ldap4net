using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using LdapForNet.Native;
using LdapForNet.Utils;

namespace LdapForNet
{
    internal delegate TResult Func<in T, in T2, T3, out TResult>(T obj, T2 obj2, out T3 obj3);
    internal class BerEncodeAction
    {
        public BerEncodeAction(Func<BerSafeHandle, char, object[], int, int> action, char format) : this(action, true, format)
        {
        }
        public BerEncodeAction(Func<BerSafeHandle, char, object[], int, int> action, bool next) : this(action, next, char.MinValue)
        {
        }
        public BerEncodeAction(Func<BerSafeHandle, char, object[], int, int> action) : this(action, true, char.MinValue)
        {
        }
        public BerEncodeAction(Func<BerSafeHandle, char, object[], int, int> action, bool next, char format)
        {
            Action = action;
            Next = next;
            UseFormat = format;
        }
        public bool Next { get; }
        public Func<BerSafeHandle, char, object[], int, int> Action { get; }
        public char UseFormat { get; } 
    }

    internal class BerDecodeAction
    {
        public BerDecodeAction(Func<BerSafeHandle, char, object, int> action) : this(action, false, Char.MinValue)
        {
        }
        public BerDecodeAction(Func<BerSafeHandle, char, object, int> action, char format) : this(action, false, format)
        {
        }
        public BerDecodeAction(Func<BerSafeHandle, char, object, int> action, bool empty) : this(action, empty, Char.MinValue)
        {
        }
        public BerDecodeAction(Func<BerSafeHandle, char, object, int> action, bool empty, char format)
        {
            Action = action;
            Empty = empty;
            UseFormat = format;
        }
        public bool Empty { get; }
        public Func<BerSafeHandle, char, object, int> Action { get; }
        public char UseFormat { get; }
    }

    /// <summary>
    /// supported formats
    /// ber_printf
    /// win	(winber.h)	t b e i n o s v V { } [ ] X 
    /// unix (lber.h)  	t b e i n o s v V { } [ ] B O W	
    /// 
    /// ber_scanf
    /// win	(winber.h)	a O b e i B n t v V x { } [ ]
    /// unix (lber.h)	a O b e i B n t v V x { } [ ] A s o m W M l T 
    /// </summary>
    public static class BerConverter
    {
        private static readonly IDictionary<char, BerEncodeAction> EncodeActions = new Dictionary<char, BerEncodeAction>
        {

            ['t'] = new BerEncodeAction(BerPrintInt),
            ['b'] = new BerEncodeAction(BerPrintBool),
            ['e'] = new BerEncodeAction(BerPrintInt),
            ['i'] = new BerEncodeAction(BerPrintInt),
            ['n'] = new BerEncodeAction(BerPrintEmptyArg, false),
            ['o'] = new BerEncodeAction(BerPrintOctetStringFromBytes),
            ['s'] = new BerEncodeAction(BerPrintOctetString),
            ['v'] = new BerEncodeAction(BerPrintMultiByteStrings),
            ['V'] = new BerEncodeAction(BerPrintBerValMultiBytes),
            ['{'] = new BerEncodeAction(BerPrintEmptyArg, false),
            ['}'] = new BerEncodeAction(BerPrintEmptyArg, false),
            ['['] = new BerEncodeAction(BerPrintEmptyArg, false),
            [']'] = new BerEncodeAction(BerPrintEmptyArg, false),
            ['X'] = new BerEncodeAction(BerPrintBitStringFromBytes),
            ['B'] = new BerEncodeAction(BerPrintBitStringFromBytes, 'X'),
            ['O'] = new BerEncodeAction(BerPrintOctetStringFromBytes, true, 'o'),
            ['W'] = new BerEncodeAction(BerPrintBerValMultiBytesW),

        };

        private static readonly IDictionary<char, BerDecodeAction> DecodeActions = new Dictionary<char, BerDecodeAction>
        {
            ['a'] = new BerDecodeAction(BerScanfStringFromByteArray),
            ['A'] = new BerDecodeAction(BerScanfStringFromByteArray,'a'),
            ['O'] = new BerDecodeAction(BerScanfByteArray),
            ['b'] = new BerDecodeAction(BerScanfInt),
            ['e'] = new BerDecodeAction(BerScanfInt),
            ['i'] = new BerDecodeAction(BerScanfInt),
            ['B'] = new BerDecodeAction(BerScanfBitString),
            ['n'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['t'] = new BerDecodeAction(BerScanfTag),
            ['v'] = new BerDecodeAction(BerScanfStringArray),
            ['V'] = new BerDecodeAction(BerScanfBerValMultiByteArray),
            ['x'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['{'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['}'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['['] = new BerDecodeAction(BerScanfEmptyTag, true),
            [']'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['s'] = new BerDecodeAction(BerScanfStringFromByteArray, 'a'),
            ['o'] = new BerDecodeAction(BerScanfByteArray,  'O'),
            ['m'] = new BerDecodeAction(BerScanfByteArray,  'O'),
            ['W'] = new BerDecodeAction(BerScanfBerValMultiByteArrayW),
            ['l'] = new BerDecodeAction(BerScanfInt),
            ['T'] = new BerDecodeAction(BerScanfInt),
        };

        private static readonly UTF8Encoding Utf8Encoder = new UTF8Encoding();
        private static readonly UTF8Encoding Utf8EncoderWithChecks = new UTF8Encoding(false, true);

        public static byte[] Encode(string format, params object[] value)
        {
            if (format == null)
                throw new ArgumentNullException(nameof(format));

            // no need to turn on invalid encoding detection as we just do string->byte[] conversion.
            byte[] encodingResult;
            // value is allowed to be null in certain scenario, so if it is null, just set it to empty array.
            if (value == null)
            {
                value = Array.Empty<object>();
            }

            Debug.WriteLine("Begin encoding");

            // allocate the berelement
            var berElement = new BerSafeHandle();

            var valueCount = 0;
            for (var i = 0; i < format.Length; i++)
            {
                var fmt = format[i];
                if (!EncodeActions.TryGetValue(fmt, out var encodeAction))
                {
                    throw new ArgumentException("Format string contains undefined character: " + new string(fmt, 1));
                }

                fmt = encodeAction.UseFormat == char.MinValue ? fmt : encodeAction.UseFormat;
                if (encodeAction.Action(berElement, fmt, value, valueCount) == -1)
                {
                    Debug.WriteLine("ber_printf failed\n");
                    throw new LdapBerConversionException(new LdapExceptionData($"ber_printf failed. Format: {format}. Current char: {fmt} with index {i}"));
                }

                if (encodeAction.Next)
                {
                    valueCount++;
                }
            }

            // get the binary value back
            var berVal = new Native.Native.berval();
            var flattenPtr = IntPtr.Zero;

            try
            {
                // can't use SafeBerval here as CLR creates a SafeBerval which points to a different memory location, but when doing memory
                // deallocation, wldap has special check. So have to use IntPtr directly here.
                var rc = LdapNative.Instance.ber_flatten(berElement, ref flattenPtr);

                if (rc == -1)
                {
                    throw new LdapBerConversionException(new LdapExceptionData("ber_flatten failed"));
                }

                if (flattenPtr != IntPtr.Zero)
                {
                    Marshal.PtrToStructure(flattenPtr, berVal);
                }

                if (berVal.bv_len == 0)
                {
                    encodingResult = Array.Empty<byte>();
                }
                else
                {
                    encodingResult = new byte[berVal.bv_len];

                    Marshal.Copy(berVal.bv_val, encodingResult, 0, berVal.bv_len);
                }
            }
            finally
            {
                if (flattenPtr != IntPtr.Zero)
                {
                    LdapNative.Instance.ber_bvfree(flattenPtr);
                }
            }

            return encodingResult;
        }

        public static object[] Decode(string format, byte[] value)
        {
            var decodeResult = TryDecode(format, value, out var decodeSucceeded);
            return decodeSucceeded ? decodeResult : throw new LdapBerConversionException(new LdapExceptionData("BerConversionException"));
        }

        internal static object[] TryDecode(string format, byte[] value, out bool decodeSucceeded)
        {
            if (format == null)
            {
                throw new ArgumentNullException(nameof(format));
            }

            Debug.WriteLine("Begin decoding");

            if (!format.All(LdapNative.Instance.BerScanfSupports))
            {
                throw new ArgumentException($"{nameof(format)} has unsupported format characters");
            }

            var berValue = new Native.Native.berval();
            var resultList = new ArrayList();
            BerSafeHandle berElement;

            decodeSucceeded = false;

            if (value == null)
            {
                berValue.bv_len = 0;
                berValue.bv_val = IntPtr.Zero;
            }
            else
            {
                berValue.bv_len = value.Length;
                berValue.bv_val = Marshal.AllocHGlobal(value.Length);
                Marshal.Copy(value, 0, berValue.bv_val, value.Length);
            }

            try
            {
                berElement = new BerSafeHandle(berValue);
            }
            finally
            {
                if (berValue.bv_val != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(berValue.bv_val);
                }
            }

            foreach (var fmt in format)
            {
                if (!DecodeActions.TryGetValue(fmt, out var decodeAction))
                {
                    throw new ArgumentException($"Format string contains unrecognized format character {fmt}");
                }

                var decodeFormat = decodeAction.UseFormat == char.MinValue ? fmt : decodeAction.UseFormat;

                if (decodeAction.Action(berElement, decodeFormat, out var result) == -1)
                {
                    Debug.WriteLine($"ber_scanf for {fmt} failed");

                    return resultList.ToArray();
                }

                if (!decodeAction.Empty)
                {
                    resultList.Add(result);
                }
            }

            decodeSucceeded = true;
            return resultList.ToArray();
        }

        private static int BerPrintBerValMultiBytes(BerSafeHandle berElement, char fmt, object[] value, int valueIndex)
        {
            // we need to have one arguments
            if (valueIndex >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length");
            }

            if (value[valueIndex] != null && !(value[valueIndex] is byte[][]))
            {
                // argument is wrong
                throw new ArgumentException("type should be byte[][], but receiving value has type of " +
                                            value[valueIndex].GetType());
            }

            return EncodingBerValMultiByteArrayHelper(berElement, fmt, (byte[][])value[valueIndex]);
        }

        private static int BerPrintBerValMultiBytesW(BerSafeHandle berElement, char fmt, object[] value, int valueIndex)
        {
            // we need to have one arguments
            if (valueIndex >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length");
            }

            if (value[valueIndex] != null && !(value[valueIndex] is byte[][]))
            {
                // argument is wrong
                throw new ArgumentException("type should be byte[][], but receiving value has type of " +
                                            value[valueIndex].GetType());
            }

            return EncodingBerValMultiByteArrayHelperW(berElement, fmt, (byte[][])value[valueIndex]);
        }

        private static int BerPrintEmptyArg(BerSafeHandle berElement, char format, object[] value, int index) => LdapNative.Instance.ber_printf_emptyarg(berElement, new string(format, 1));

        private static int BerPrintMultiByteStrings(BerSafeHandle berElement, char fmt, object[] value, int valueIndex)
        {
            // we need to have one arguments
            if (valueIndex >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length\n");
            }

            if (value[valueIndex] != null && !(value[valueIndex] is string[]))
            {
                // argument is wrong
                throw new ArgumentException("type should be string[], but receiving value has type of " +
                                            value[valueIndex].GetType());
            }

            var stringValues = (string[])value[valueIndex];
            var values = stringValues?.Select(_ => _ == null ? null : Utf8Encoder.GetBytes(_))
                .ToArray();

            return EncodingMultiByteArrayHelper(berElement, values, fmt);
        }

        private static int BerPrintBerValOctetString(BerSafeHandle berElement, char fmt, object[] value, int valueIndex)
        {
            // we need to have one arguments
            if (valueIndex >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length");
            }

            if (value[valueIndex] != null && !(value[valueIndex] is byte[]))
            {
                // argument is wrong
                throw new ArgumentException(
                    $"type should be byte[], but receiving value has type of {value[valueIndex].GetType()}");
            }

            var tempValue = (byte[])value[valueIndex] ?? new byte[0];
            return EncodingBerValHelper(berElement, tempValue, fmt);
        }

        private static int BerPrintBitStringFromBytes(BerSafeHandle berElement, char fmt, object[] value, int valueIndex)
        {
            // we need to have one arguments
            if (valueIndex >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length");
            }

            if (value[valueIndex] != null && !(value[valueIndex] is byte[]))
            {
                // argument is wrong
                throw new ArgumentException(
                    $"type should be byte[], but receiving value has type of {value[valueIndex].GetType()}");
            }

            var byteArray = (byte[])value[valueIndex] ?? new byte[0];
            var bitArray = new BitArray(byteArray.Select(_ => _ > 0).ToArray());
            return EncodingBitArrayHelper(berElement, bitArray, fmt);
        }

        private static int BerPrintOctetStringFromBytes(BerSafeHandle berElement, char fmt, object[] value, int valueIndex)
        {
            // we need to have one arguments
            if (valueIndex >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length");
            }

            if (value[valueIndex] != null && !(value[valueIndex] is byte[]))
            {
                // argument is wrong
                throw new ArgumentException(
                    $"type should be byte[], but receiving value has type of {value[valueIndex].GetType()}");
            }

            var byteArray = (byte[])value[valueIndex] ?? new byte[0];
            return EncodingByteArrayHelper(berElement, byteArray, fmt);
        }

        private static int BerPrintOctetString(BerSafeHandle berElement, char fmt, object[] value, int valueIndex)
        {
            if (valueIndex >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length");
            }

            if (value[valueIndex] != null && !(value[valueIndex] is string))
            {
                // argument is wrong
                throw new ArgumentException(
                    $"type should be string, but receiving value has type of {value[valueIndex].GetType()}");
            }

            // one string argument       
            // value[valueCount] = value[valueCount] ?? string.Empty;
            var tempValue = Utf8Encoder.GetBytes((string)value[valueIndex] ?? string.Empty);

            return EncodingByteArrayHelper(berElement, tempValue, 'o');
        }

        private static int BerPrintBool(BerSafeHandle berElement, char fmt, object[] value, int valueIndex)
        {
            if (valueIndex >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length");
            }

            if (!(value[valueIndex] is bool))
            {
                // argument is wrong
                throw new ArgumentException("type should be boolean\n");
            }

            // one int argument                    
            return LdapNative.Instance.ber_printf_int(berElement, new string(fmt, 1), (bool)value[valueIndex] ? 1 : 0);
        }

        private static int BerPrintInt(BerSafeHandle berElement, char fmt, object[] value, int valueCount)
        {
            if (valueCount >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length\n");
            }

            if (!(value[valueCount] is int))
            {
                // argument is wrong                                                                        
                Debug.WriteLine("type should be int\n");
                throw new ArgumentException("type should be int");
            }

            // one int argument
            return LdapNative.Instance.ber_printf_int(berElement, new string(fmt, 1), (int)value[valueCount]);
        }



        private static int BerScanfBerValMultiByteArray(BerSafeHandle berElement, char fmt, out object result)
        {
            var error = DecodingBerValMultiByteArrayHelper(berElement, fmt, out var array);
            result = array;
            return error;
        }
        
        private static int BerScanfBerValMultiByteArrayW(BerSafeHandle berElement, char fmt, out object result)
        {
            var error = DecodingBerValMultiByteArrayHelperW(berElement, fmt, out var array);
            result = array;
            return error;
        }

        private static int BerScanfStringArray(BerSafeHandle berElement, char fmt, out object result)
        {
            //null terminate strings
            string[] stringArray = null;

            var error = DecodingMultiByteArrayHelper(berElement, fmt, out var byteArrayResult);
            if (error != -1 && byteArrayResult != null)
            {
                stringArray = byteArrayResult.Select(_ => _ == null ? null : Utf8EncoderWithChecks.GetString(_))
                    .ToArray();
            }

            result = stringArray;

            return error;
        }

        private static int BerScanfBitString(BerSafeHandle berElement, char fmt, out object result)
        {
            // return a bitstring and its length
            var ptrResult = IntPtr.Zero;
            var length = 0;
            result = null;
            byte[] byteArray = null;
            var rc = LdapNative.Instance.ber_scanf_bitstring(berElement, new string(fmt, 1), ref ptrResult, ref length);

            // try
            // {
                if (rc != -1)
                {
                    if (ptrResult != IntPtr.Zero)
                    {
                        var bytesLength = length / 8 + 1;
                        var bytes = new byte[bytesLength];
                        for (var i = 0; i < bytes.Length; i++)
                        {
                            bytes[i] = Marshal.ReadByte(ptrResult, i);
                        }
                        var bitArray = new BitArray(bytes);
                        bitArray.Length = length;
                        bool[] boolArray = new bool[length];
                        bitArray.CopyTo(boolArray,0);
                        byteArray = boolArray.Select(_ => _ ? (byte) 1 : (byte)0).ToArray();
                    }



                result = byteArray;
                }
            // }
            // finally
            // {
            //     if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows) && ptrResult != IntPtr.Zero)
            //     {
            //         LdapNative.Instance.ber_memfree(ptrResult);
            //     }
            // }

            return rc;
        }

        private static int BerScanfBerValOstring(BerSafeHandle berElement, char fmt, out object result)
        {
            var rc = DecodingBerValOstringHelper(berElement, fmt, out var byteArray);
            result = byteArray;
            return rc;
        }

        private static int BerScanfStringFromByteArray(BerSafeHandle berElement, char fmt, out object result)
        {
            result = null;
            var error = BerScanfaString(berElement, fmt, out var byteArray);
            if (error != -1 && byteArray != null)
            {
                result = Utf8EncoderWithChecks.GetString((byte[])byteArray);
            }

            return error;
        }


        private static int BerScanfByteArray(BerSafeHandle berElement, char fmt, out object result)
        {
            var rc = DecodingBerValByteArrayHelper(berElement, fmt, out var byteArray);
            result = byteArray;
            return rc;
        }

        private static int BerScanfaString(BerSafeHandle berElement, char fmt, out object byteArray)
        {
            var result = IntPtr.Zero;
            byteArray = null;

            var rc = LdapNative.Instance.ber_scanf_ptr(berElement, new string(fmt, 1), ref result);

            try
            {
                if (rc != -1 && result != IntPtr.Zero)
                {
                    byteArray = MarshalUtils.GetBytes(result).ToArray();
                }
            }
            finally
            {
                if (result != IntPtr.Zero)
                {
                    LdapNative.Instance.ber_memfree(result);
                }
            }

            return rc;
        }
        private static int BerScanfString(BerSafeHandle berElement, char fmt, out object result)
        {
            int rc;
            var ptr = Marshal.AllocHGlobal(IntPtr.Size);
            var length = -1;
            result = null;
            try
            {
                rc = LdapNative.Instance.ber_scanf_string(berElement, new string(fmt, 1), ptr, ref length);
                if (rc != -1)
                {
                    var byteArray = new byte[length];
                    Marshal.Copy(ptr, byteArray, 0, length);
                    result = Utf8EncoderWithChecks.GetString(byteArray);
                }
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }

            return rc;
        }

        private static int BerScanfTag(BerSafeHandle berElement, char fmt, out object result)
        {
            var length = 0;
            result = LdapNative.Instance.ber_peek_tag(berElement, ref length);
            return (int)result;
        }

        private static int BerScanfInt(BerSafeHandle berElement, char fmt, out object result)
        {
            var intResult = 0;
            result = 0;
            var rc = LdapNative.Instance.ber_scanf_int(berElement, new string(fmt, 1), ref intResult);

            if (rc != -1)
            {
                result = fmt == 'b' ? (object)(intResult != 0) : intResult;
            }

            return rc;
        }

        private static int BerScanfEmptyTag(BerSafeHandle berElement, char fmt, out object result)
        {
            result = null;
            return LdapNative.Instance.ber_scanf(berElement, new string(fmt, 1));
        }

        private static int EncodingBitArrayHelper(BerSafeHandle berElement, BitArray value, char fmt)
        {
            int tag;

            // one byte array, one int arguments
            if (value != null)
            {
                var arr = new byte[value.Length/8 + 1];
                value.CopyTo(arr,0);
                var tmp = Marshal.AllocHGlobal(arr.Length);
                Marshal.Copy(arr, 0, tmp, arr.Length);
                var memHandle = new HGlobalMemHandle(tmp);

                tag = LdapNative.Instance.ber_printf_bytearray(berElement, new string(fmt, 1), memHandle, value.Length);
            }
            else
            {
                tag = LdapNative.Instance.ber_printf_bytearray(berElement, new string(fmt, 1), new HGlobalMemHandle(IntPtr.Zero), 0);
            }

            return tag;
        }

        private static int EncodingByteArrayHelper(BerSafeHandle berElement, byte[] value, char fmt)
        {
            int tag;

            // one byte array, one int arguments
            if (value != null)
            {
                var tmp = Marshal.AllocHGlobal(value.Length);
                Marshal.Copy(value, 0, tmp, value.Length);
                var memHandle = new HGlobalMemHandle(tmp);

                tag = LdapNative.Instance.ber_printf_bytearray(berElement, new string(fmt, 1), memHandle, value.Length);
            }
            else
            {
                tag = LdapNative.Instance.ber_printf_bytearray(berElement, new string(fmt, 1), new HGlobalMemHandle(IntPtr.Zero), 0);
            }

            return tag;
        }

        private static int DecodingBerValOstringHelper(BerSafeHandle berElement, char fmt, out byte[] byteArray)
        {
            var result = Marshal.AllocHGlobal(IntPtr.Size);
            var binaryValue = new Native.Native.berval();
            byteArray = null;

            var error = LdapNative.Instance.ber_scanf_ostring(berElement, new string(fmt, 1), result);

            try
            {
                if (error != -1 && result != IntPtr.Zero)
                {
                    Marshal.PtrToStructure(result, binaryValue);

                    byteArray = new byte[binaryValue.bv_len];
                    Marshal.Copy(binaryValue.bv_val, byteArray, 0, binaryValue.bv_len);
                }
            }
            finally
            {
                if (result != IntPtr.Zero)
                {
                    LdapNative.Instance.ber_memfree(result);
                }
            }

            return error;
        }

        private static int DecodingBerValByteArrayHelper(BerSafeHandle berElement, char fmt, out byte[] byteArray)
        {
            var result = IntPtr.Zero;
            var binaryValue = new Native.Native.berval();
            byteArray = null;

            // can't use SafeBerval here as CLR creates a SafeBerval which points to a different memory location, but when doing memory
            // deallocation, wldap has special check. So have to use IntPtr directly here.
            var rc = LdapNative.Instance.ber_scanf_ptr(berElement, new string(fmt, 1), ref result);

            try
            {
                if (rc != -1 && result != IntPtr.Zero)
                {
                    Marshal.PtrToStructure(result, binaryValue);

                    byteArray = new byte[binaryValue.bv_len];
                    if (binaryValue.bv_val != IntPtr.Zero)
                    {
                        Marshal.Copy(binaryValue.bv_val, byteArray, 0, binaryValue.bv_len);
                    }
                }
            }
            finally
            {
                if (result != IntPtr.Zero)
                {
                    LdapNative.Instance.ber_bvfree(result);
                }
            }

            return rc;
        }

        private static int EncodingBerValHelper(BerSafeHandle berElement, byte[] value, char fmt)
        {
            int rc;
            var valPtr = IntPtr.Zero;
            try
            {
                if (value == null)
                {
                    value = new byte[0];
                }
                valPtr = MarshalUtils.ByteArrayToBerValue(value);
                rc = LdapNative.Instance.ber_printf_berarray(berElement, new string(fmt, 1), valPtr);
            }
            finally
            {
                if (valPtr != IntPtr.Zero)
                {
                    MarshalUtils.BerValFree(valPtr);
                }
            }
            return rc;
        }
        private static int EncodingMultiByteArrayHelper(BerSafeHandle berElement, byte[][] value, char fmt)
        {
            var stringArray = IntPtr.Zero;
            int rc;

            try
            {
                if (value != null)
                {
                    var intPtrArray = value.Select(_ =>
                    {
                        var byteArray = _ ?? new byte[0];
                        var valPtr = Marshal.AllocHGlobal(byteArray.Length + 1);
                        Marshal.Copy(byteArray, 0, valPtr, byteArray.Length);
                        Marshal.WriteByte(valPtr, byteArray.Length, 0);
                        return valPtr;
                    }).Concat(new[] { IntPtr.Zero }).ToArray();

                    stringArray = MarshalUtils.WriteIntPtrArray(intPtrArray);
                }

                rc = LdapNative.Instance.ber_printf_berarray(berElement, new string(fmt, 1), stringArray);

            }
            finally
            {
                MarshalUtils.FreeIntPtrArray(stringArray);
            }

            return rc;
        }


        private static int EncodingBerValMultiByteArrayHelper(BerSafeHandle berElement, char fmt, byte[][] value)
        {
            var berValArray = IntPtr.Zero;
            Native.Native.SafeBerval[] managedBerVal = null;
            int rc;

            try
            {
                if (value != null)
                {
                    berValArray = MarshalUtils.AllocHGlobalIntPtrArray(value.Length + 1);
                    var structSize = Marshal.SizeOf(typeof(Native.Native.SafeBerval));
                    managedBerVal = new Native.Native.SafeBerval[value.Length];

                    for (var i = 0; i < value.Length; i++)
                    {
                        var byteArray = value[i];

                        // construct the managed berval
                        managedBerVal[i] = new Native.Native.SafeBerval();

                        if (byteArray == null)
                        {
                            managedBerVal[i].bv_len = 0;
                            managedBerVal[i].bv_val = IntPtr.Zero;
                        }
                        else
                        {
                            managedBerVal[i].bv_len = byteArray.Length;
                            managedBerVal[i].bv_val = Marshal.AllocHGlobal(byteArray.Length);
                            if (managedBerVal[i].bv_val != IntPtr.Zero)
                            {
                                Marshal.Copy(byteArray, 0, managedBerVal[i].bv_val, byteArray.Length);
                            }
                        }

                        // allocate memory for the unmanaged structure
                        var valPtr = Marshal.AllocHGlobal(structSize);
                        Marshal.StructureToPtr(managedBerVal[i], valPtr, false);

                        Marshal.WriteIntPtr(berValArray, IntPtr.Size * i, valPtr);
                    }

                    Marshal.WriteIntPtr(berValArray, IntPtr.Size * value.Length, IntPtr.Zero);
                }

                rc = LdapNative.Instance.ber_printf_berarray(berElement, new string(fmt, 1), berValArray);

                GC.KeepAlive(managedBerVal);
            }
            finally
            {
                if (berValArray != IntPtr.Zero)
                {
                    foreach (var ptr in MarshalUtils.GetPointerArray(berValArray))
                    {
                        Marshal.FreeHGlobal(ptr);
                    }
                    Marshal.FreeHGlobal(berValArray);
                }
            }

            return rc;
        }

        private static int EncodingBerValMultiByteArrayHelperW(BerSafeHandle berElement, char fmt, byte[][] value)
        {
            var berValArray = IntPtr.Zero;
            Native.Native.SafeBerval[] managedBerVal = null;
            int rc;

            try
            {
                if (value != null)
                {
                    var structSize = Marshal.SizeOf(typeof(Native.Native.SafeBerval));

                    berValArray = Marshal.AllocHGlobal((value.Length + 1) * structSize);
                    managedBerVal = new Native.Native.SafeBerval[value.Length];

                    for (var i = 0; i < value.Length; i++)
                    {
                        var byteArray = value[i];

                        // construct the managed berval
                        managedBerVal[i] = new Native.Native.SafeBerval();

                        if (byteArray == null)
                        {
                            managedBerVal[i].bv_len = 0;
                            managedBerVal[i].bv_val = IntPtr.Zero;
                        }
                        else
                        {
                            managedBerVal[i].bv_len = byteArray.Length;
                            managedBerVal[i].bv_val = Marshal.AllocHGlobal(byteArray.Length);
                            if (managedBerVal[i].bv_val != IntPtr.Zero)
                            {
                                Marshal.Copy(byteArray, 0, managedBerVal[i].bv_val, byteArray.Length);
                            }
                        }

                        var valPtr = new IntPtr((long)berValArray+i*structSize);
                        Marshal.StructureToPtr(managedBerVal[i], valPtr, false);
                    }

                    Marshal.StructureToPtr(new Native.Native.SafeBerval{ bv_len = 0, bv_val = IntPtr.Zero}, new IntPtr((long)berValArray+value.Length*structSize), false);
                }

                rc = LdapNative.Instance.ber_printf_berarray(berElement, $"{{{fmt}}}", berValArray);

                GC.KeepAlive(managedBerVal);
            }
            finally
            {
                if (berValArray != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(berValArray);
                }
            }

            return rc;
        }

        private static int DecodingBerValMultiByteArrayHelper(BerSafeHandle berElement, char fmt, out byte[][] result)
        {
            int rc;
            var ptrResult = IntPtr.Zero;
            result = null;

            try
            {
                rc = LdapNative.Instance.ber_scanf_ptr(berElement, new string(fmt, 1), ref ptrResult);

                if (rc != -1 && ptrResult != IntPtr.Zero)
                {
                    result = MarshalUtils.BerValArrayToByteArrays(ptrResult).ToArray();
                }
            }
            finally
            {
                if (ptrResult != IntPtr.Zero)
                {
                    LdapNative.Instance.ber_bvecfree(ptrResult);
                }
            }

            return rc;
        }
        
        private static int DecodingBerValMultiByteArrayHelperW(BerSafeHandle berElement, char fmt, out byte[][] result)
        {
            int rc;
            var ptrResult = IntPtr.Zero;
            result = null;

            try
            {
                rc = LdapNative.Instance.ber_scanf_ptr(berElement, new string(fmt, 1), ref ptrResult);

                if (rc != -1 && ptrResult != IntPtr.Zero)
                {
                    var count = 0;
                    var size = Marshal.SizeOf<Native.Native.berval>();
                    var bytes  = new List<byte[]>();
                    var bervalue = Marshal.PtrToStructure<Native.Native.berval>(ptrResult);
                    while (bervalue.bv_val != IntPtr.Zero)
                    {
                        if (bervalue.bv_len > 0)
                        {
                            var byteArray = new byte[bervalue.bv_len];
                            Marshal.Copy(bervalue.bv_val, byteArray, 0, bervalue.bv_len);
                            bytes.Add(byteArray);
                        }
                        count++;
                        var tempPtr = new IntPtr((long)ptrResult + size*count);
                        bervalue = Marshal.PtrToStructure<Native.Native.berval>(tempPtr);
                    }
                    result = bytes.ToArray();
                }
            }
            finally
            {
                if (ptrResult != IntPtr.Zero)
                {
                    //LdapNative.Instance.ber_bvarrayfree(ptrResult);
                }
            }

            return rc;
        }

        private static int DecodingMultiByteArrayHelper(BerSafeHandle berElement, char fmt, out byte[][] result)
        {
            int rc;
            var ptrResult = IntPtr.Zero;
            result = null;

            try
            {
                rc = LdapNative.Instance.ber_scanf_ptr(berElement, new string(fmt, 1), ref ptrResult);

                if (rc != -1 && ptrResult != IntPtr.Zero)
                {
                    result = MarshalUtils.GetPointerArray(ptrResult)
                        .Select(MarshalUtils.GetBytes)
                        .Select(_ => _.ToArray())
                        .ToArray();
                }

            }
            finally
            {
                if (ptrResult != IntPtr.Zero)
                {
                    LdapNative.Instance.ber_memfree(ptrResult);
                }
            }

            return rc;
        }
    }
}