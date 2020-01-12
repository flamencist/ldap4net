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
        public BerEncodeAction(Func<BerSafeHandle, char, object[], int, int> action) :this(action,true)
        {
        }
        public BerEncodeAction(Func<BerSafeHandle, char, object[], int, int> action, bool next)
        {
            Action = action;
            Next = next;
        }
        public bool Next { get; }
        public Func<BerSafeHandle, char, object[], int, int> Action { get;  }
    }

    internal class BerDecodeAction
    {
        public BerDecodeAction(Func<BerSafeHandle, char, object, int> action) : this(action, false)
        {
        }
        public BerDecodeAction(Func<BerSafeHandle, char, object, int> action, bool empty)
        {
            Action = action;
            Empty = empty;
        }
        public bool Empty { get; }
        public Func<BerSafeHandle, char, object, int> Action { get; }
    }

    /// <summary>
    /// supported formats
    /// ber_printf
    /// win	(wldap.h)	t b e i n o s v V { } [ ] X 
    /// unix (lber.h)  	t b e i n o s v V { } [ ] B O W	
    /// 
    /// ber_scanf
    /// win	(wldap.h)	a O b e i B n t v V x { } [ ]
    /// unix (lber.h)	a O b e i B n t v V x { } [ ] A s o m W M l T 
    /// </summary>
    public static class BerConverter
    {
        private static readonly IDictionary<char, BerEncodeAction> EncodeActions = new Dictionary<char, BerEncodeAction>
        {
            ['{']=new BerEncodeAction(BerPrintfEmptyArg,false),
            ['}']=new BerEncodeAction(BerPrintfEmptyArg,false),
            ['[']=new BerEncodeAction(BerPrintfEmptyArg,false),
            [']']=new BerEncodeAction(BerPrintfEmptyArg,false),
            ['n']=new BerEncodeAction(BerPrintfEmptyArg,false),
            ['t']=new BerEncodeAction(BerPrintInt),
            ['i']=new BerEncodeAction(BerPrintInt),
            ['e']=new BerEncodeAction(BerPrintInt),
            ['b']=new BerEncodeAction(BerPrintBool),
            ['s']=new BerEncodeAction(BerPrintOctetString),
            ['o']=new BerEncodeAction(BerPrintOctetStringFromBytes),
            ['X']=new BerEncodeAction(BerPrintOctetStringFromBytes),
            ['B']=new BerEncodeAction(BerPrintOctetStringFromBytes),
            ['O']=new BerEncodeAction(BerPrintBerValOctetString),
            ['v']=new BerEncodeAction(BerPrintMultiByteStrings),
            ['V'] =new BerEncodeAction(BerPrintBerValMultiBytes),
        };

        private static readonly IDictionary<char, BerDecodeAction> DecodeActions = new Dictionary<char, BerDecodeAction>
        {
            ['{'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['}'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['['] = new BerDecodeAction(BerScanfEmptyTag, true),
            [']'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['n'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['x'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['t'] = new BerDecodeAction(BerScanfEmptyTag, true),
            ['i'] = new BerDecodeAction(BerScanfInt),
            ['e'] = new BerDecodeAction(BerScanfInt),
            ['b'] = new BerDecodeAction(BerScanfInt),
            ['a'] = new BerDecodeAction(BerScanfStringFromByteArray),
            ['O'] = new BerDecodeAction(BerScanfByteArray),
            ['o'] = new BerDecodeAction(BerScanfBerValOstring),
            ['s'] = new BerDecodeAction(BerScanfString),
            ['B'] = new BerDecodeAction(BerScanfBitString),
            ['v'] = new BerDecodeAction(BerScanfStringArray),
            ['V'] = new BerDecodeAction(BerScanfBerValMultiByteArray),
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

            Debug.WriteLine("Begin encoding\n");

            // allocate the berelement
            var berElement = new BerSafeHandle();

            var valueCount = 0;
            for (var index = 0; index < format.Length; index++)
            {
                var fmt = format[index];
                if (!EncodeActions.TryGetValue(fmt, out var encodeAction))
                {
                    throw new ArgumentException("Format string contains undefined character: " + new string(fmt, 1));
                }

                if (encodeAction.Action(berElement, fmt, value, valueCount) == -1)
                {
                    Debug.WriteLine("ber_printf failed\n");
                    throw new LdapException($"ber_printf failed. Format: {format}. Current char: {fmt} with index {index}");
                }

                if (encodeAction.Next)
                {
                    valueCount++;
                }
            }

            // get the binary value back
            var binaryValue = new Native.Native.berval();
            var flattenptr = IntPtr.Zero;

            try
            {
                // can't use SafeBerval here as CLR creates a SafeBerval which points to a different memory location, but when doing memory
                // deallocation, wldap has special check. So have to use IntPtr directly here.
                var error = LdapNative.Instance.ber_flatten(berElement, ref flattenptr);

                if (error == -1)
                {
                    throw new LdapException("ber_flatten failed\n");
                }

                if (flattenptr != IntPtr.Zero)
                {
                    Marshal.PtrToStructure(flattenptr, binaryValue);
                }

                if (binaryValue.bv_len == 0)
                {
                    encodingResult = Array.Empty<byte>();
                }
                else
                {
                    encodingResult = new byte[binaryValue.bv_len];

                    Marshal.Copy(binaryValue.bv_val, encodingResult, 0, binaryValue.bv_len);
                }
            }
            finally
            {
                if (flattenptr != IntPtr.Zero)
                {
                    LdapNative.Instance.ber_bvfree(flattenptr);
                }
            }

            return encodingResult;
        }

        public static object[] Decode(string format, byte[] value)
        {
            var decodeResult = TryDecode(format, value, out var decodeSucceeded);
            return decodeSucceeded ? decodeResult : throw new LdapException("BerConversionException");
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

                if (decodeAction.Action(berElement, fmt, out var result) == -1)
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

        private static int BerPrintBerValMultiBytes(BerSafeHandle berElement, char fmt, object[] value, int valueCount)
        {
            // we need to have one arguments
            if (valueCount >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length");
            }

            if (value[valueCount] != null && !(value[valueCount] is byte[][]))
            {
                // argument is wrong
                throw new ArgumentException("type should be byte[][], but receiving value has type of " +
                                            value[valueCount].GetType());
            }

            var tempValue = (byte[][]) value[valueCount];

            return EncodingBerValMultiByteArrayHelper(berElement, fmt, tempValue);
        }

        private static int BerPrintfEmptyArg(BerSafeHandle berElement, char format, object[] value, int index) => LdapNative.Instance.ber_printf_emptyarg(berElement, new string(format, 1));


        private static int BerPrintMultiByteStrings(BerSafeHandle berElement, char fmt, object[] value, int valueCount)
        {
            int error;
            // we need to have one arguments
            if (valueCount >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length\n");
            }

            if (value[valueCount] != null && !(value[valueCount] is string[]))
            {
                // argument is wrong
                throw new ArgumentException("type should be string[], but receiving value has type of " +
                                            value[valueCount].GetType());
            }

            var stringValues = (string[]) value[valueCount];
            byte[][] tempValues = null;
            if (stringValues != null)
            {
                tempValues = new byte[stringValues.Length][];
                for (var i = 0; i < stringValues.Length; i++)
                {
                    var s = stringValues[i];
                    if (s == null)
                        tempValues[i] = null;
                    else
                    {
                        tempValues[i] = Utf8Encoder.GetBytes(s);
                    }
                }
            }

            error = EncodingMultiByteArrayHelper(berElement, tempValues, fmt);
            return error;
        }

        private static int BerPrintBerValOctetString(BerSafeHandle berElement, char fmt, object[] value, int valueCount)
        {
            int error;
            // we need to have one arguments
            if (valueCount >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length\n");
            }

            if (value[valueCount] != null && !(value[valueCount] is byte[]))
            {
                // argument is wrong
                throw new ArgumentException("type should be byte[], but receiving value has type of " +
                                            value[valueCount].GetType());
            }

            var tempValue = (byte[]) value[valueCount] ?? new byte[0];
            error = EncodingBerValHelper(berElement, tempValue, fmt);
            return error;
        }

        private static int BerPrintOctetStringFromBytes(BerSafeHandle berElement, char fmt, object[] value, int valueCount)
        {
            // we need to have one arguments
            if (valueCount >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length\n");
            }

            if (value[valueCount] != null && !(value[valueCount] is byte[]))
            {
                // argument is wrong
                throw new ArgumentException("type should be byte[], but receiving value has type of " +
                                            value[valueCount].GetType());
            }

            var tempValue = (byte[]) value[valueCount] ?? new byte[0];
            return EncodingByteArrayHelper(berElement, tempValue, fmt);
        }

        private static int BerPrintOctetString(BerSafeHandle berElement, char fmt, object[] value, int valueCount)
        {
            if (valueCount >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length\n");
            }

            if (value[valueCount] != null && !(value[valueCount] is string))
            {
                // argument is wrong
                throw new ArgumentException("type should be string, but receiving value has type of " +
                                            value[valueCount].GetType());
            }

            // one string argument       
            // value[valueCount] = value[valueCount] ?? string.Empty;
            var tempValue = Utf8Encoder.GetBytes((string) value[valueCount] ?? string.Empty);

            return EncodingByteArrayHelper(berElement, tempValue, 'o');
        }

        private static int BerPrintBool(BerSafeHandle berElement, char fmt, object[] value, int valueCount)
        {
            if (valueCount >= value.Length)
            {
                // we don't have enough argument for the format string
                throw new ArgumentException("value argument is not valid, valueCount >= value.Length");
            }

            if (!(value[valueCount] is bool))
            {
                // argument is wrong
                throw new ArgumentException("type should be boolean\n");
            }

            // one int argument                    
            return LdapNative.Instance.ber_printf_int(berElement, new string(fmt, 1), (bool) value[valueCount] ? 1 : 0);
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
            return LdapNative.Instance.ber_printf_int(berElement, new string(fmt, 1), (int) value[valueCount]);
        }

       

        private static int BerScanfBerValMultiByteArray(BerSafeHandle berElement, char fmt, out object result)
        {
            var error = DecodingBerValMultiByteArrayHelper(berElement, fmt, out var array);
            result = array;
            return error;
        }

        private static int BerScanfStringArray(BerSafeHandle berElement, char fmt, out object result)
        {
            int error;
            //null terminate strings
            string[] stringArray = null;

            error = DecodingMultiByteArrayHelper(berElement, fmt, out var byteArrayResult);
            if (error != -1)
            {
                if (byteArrayResult != null)
                {
                    stringArray = new string[byteArrayResult.Length];
                    for (var i = 0; i < byteArrayResult.Length; i++)
                    {
                        if (byteArrayResult[i] == null)
                        {
                            stringArray[i] = null;
                        }
                        else
                        {
                            stringArray[i] = Utf8EncoderWithChecks.GetString(byteArrayResult[i]);
                        }
                    }
                }
            }

            result = stringArray;

            return error;
        }

        private static int BerScanfBitString(BerSafeHandle berElement, char fmt, out object result)
        {
            int error;
            // return a bitstring and its length
            var ptrResult = IntPtr.Zero;
            var length = 0;
            result = null;
            error = LdapNative.Instance.ber_scanf_bitstring(berElement, new string(fmt, 1), ref ptrResult, ref length);

            if (error != -1)
            {
                byte[] byteArray = null;
                if (ptrResult != IntPtr.Zero)
                {
                    byteArray = new byte[length];
                    Marshal.Copy(ptrResult, byteArray, 0, length);
                }

                result = byteArray;
            }
            else
            {
                Debug.WriteLine("ber_scanf for format character 'B' failed");
            }

            return error;
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
            var error = BerScanfByteArray(berElement, fmt, out var byteArray);
            if (error != -1)
            {
                if (byteArray != null)
                {
                    result = Utf8EncoderWithChecks.GetString((byte[]) byteArray);
                }

            }

            return error;
        }

        private static int BerScanfByteArray(BerSafeHandle berElement, char fmt, out object result)
        {
            var rc = DecodingBerValByteArrayHelper(berElement, fmt, out var byteArray);
            result = byteArray;
            return rc;
        }

        private static int BerScanfString(BerSafeHandle berElement, char fmt, out object result)
        {
            int error;
            var ptr = Marshal.AllocHGlobal(IntPtr.Size);
            var length = -1;
            result = null;
            try
            {
                error = LdapNative.Instance.ber_scanf_string(berElement, new string(fmt, 1), ptr, ref length);
                if (error != -1)
                {
                    var byteArray = new byte[length];
                    Marshal.Copy(ptr, byteArray, 0, length);
                    var s = Utf8EncoderWithChecks.GetString(byteArray);
                    result = s;
                }
                else
                {
                    Debug.WriteLine("ber_scanf for format character 's' failed");
                }
            }
            finally
            {
                if (ptr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(ptr);
                }
            }

            return error;
        }

        private static int BerScanfInt(BerSafeHandle berElement, char fmt, out object result)
        {
            var intResult = 0;
            result = 0;
            var error = LdapNative.Instance.ber_scanf_int(berElement, new string(fmt, 1), ref intResult);

            if (error != -1)
            {
                result = fmt == 'b' ? (object) (intResult != 0) : intResult;
            }
            else
            {
                Debug.WriteLine("ber_scanf for format character 'i', 'e' or 'b' failed");
            }

            return error;
        }

        private static int BerScanfEmptyTag(BerSafeHandle berElement, char fmt, out object result)
        {
            result = null;
            return LdapNative.Instance.ber_scanf(berElement, new string (fmt, 1));
        }

        private static int EncodingByteArrayHelper(BerSafeHandle berElement, byte[] tempValue, char fmt)
        {
            int tag;

            // one byte array, one int arguments
            if (tempValue != null)
            {
                var tmp = Marshal.AllocHGlobal(tempValue.Length);
                Marshal.Copy(tempValue, 0, tmp, tempValue.Length);
                var memHandle = new HGlobalMemHandle(tmp);

                tag = LdapNative.Instance.ber_printf_bytearray(berElement, new string(fmt, 1), memHandle, tempValue.Length);
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
                if (error != -1)
                {
                    if (result != IntPtr.Zero)
                    {
                        Marshal.PtrToStructure(result, binaryValue);

                        byteArray = new byte[binaryValue.bv_len];
                        Marshal.Copy(binaryValue.bv_val, byteArray, 0, binaryValue.bv_len);
                    }
                }
                else
                    Debug.WriteLine("ber_scanf for format character 'O' failed");
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
                if (rc != -1)
                {
                    if (result != IntPtr.Zero)
                    {
                        Marshal.PtrToStructure(result, binaryValue);

                        byteArray = new byte[binaryValue.bv_len];
                        if (binaryValue.bv_val != IntPtr.Zero)
                        {
                            Marshal.Copy(binaryValue.bv_val, byteArray, 0, binaryValue.bv_len);
                        }
                    }
                }
                else
                    Debug.WriteLine("ber_scanf for format character 'O' failed");
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

        private static int EncodingBerValHelper(BerSafeHandle berElement, byte[] value, char fmt)
        {
            int error;
            var valPtr = IntPtr.Zero;
            try
            {
                if (value == null)
                {
                    value = new byte[0];
                }
                valPtr = MarshalUtils.ByteArrayToBerValue(value);
                error = LdapNative.Instance.ber_printf_berarray(berElement, new string(fmt, 1), valPtr);
            }
            finally
            {
                if (valPtr != IntPtr.Zero)
                {
                    MarshalUtils.BerValFree(valPtr);
                }
            }
            return error;
        }
        private static int EncodingMultiByteArrayHelper(BerSafeHandle berElement, byte[][] tempValue, char fmt)
        {
            var stringArray = IntPtr.Zero;
            int error;

            try
            {
                if (tempValue != null)
                {
                    int i;
                    stringArray = MarshalUtils.AllocHGlobalIntPtrArray(tempValue.Length + 1);

                    for (i = 0; i < tempValue.Length; i++)
                    {
                        var byteArray = tempValue[i] ?? new byte[0];

                        var valPtr = Marshal.AllocHGlobal(byteArray.Length+1);
                        Marshal.Copy(byteArray, 0, valPtr, byteArray.Length);
                        Marshal.WriteByte(valPtr,byteArray.Length,0);
                        
                        Marshal.WriteIntPtr(stringArray, IntPtr.Size * i, valPtr);
                    }

                    Marshal.WriteIntPtr(stringArray, tempValue.Length*IntPtr.Size, IntPtr.Zero);
                }

                error = LdapNative.Instance.ber_printf_berarray(berElement, new string(fmt, 1), stringArray);

            }
            finally
            {
                if (stringArray != IntPtr.Zero)
                {
                    foreach (var ptr in MarshalUtils.GetPointerArray(stringArray))
                    {
                        Marshal.FreeHGlobal(ptr);
                    }
                    Marshal.FreeHGlobal(stringArray);
                }
            }

            return error;
        }

        
        private static int EncodingBerValMultiByteArrayHelper(BerSafeHandle berElement, char fmt, byte[][] value)
        {
            var berValArray = IntPtr.Zero;
            Native.Native.SafeBerval[] managedBerVal = null;
            int error;

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

                error = LdapNative.Instance.ber_printf_berarray(berElement, new string(fmt, 1), berValArray);

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

            return error;
        }

        private static int DecodingBerValMultiByteArrayHelper(BerSafeHandle berElement, char fmt, out byte[][] result)
        {
            int error;
            var ptrResult = IntPtr.Zero;
            result = null;

            try
            {
                error = LdapNative.Instance.ber_scanf_ptr(berElement, new string(fmt, 1), ref ptrResult);

                if (error != -1 && ptrResult != IntPtr.Zero)
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

            return error;
        }
        
        private static int DecodingMultiByteArrayHelper(BerSafeHandle berElement, char fmt, out byte[][] result)
        {
            int error;
            var ptrResult = IntPtr.Zero;
            result = null;

            try
            {
                error = LdapNative.Instance.ber_scanf_ptr(berElement, new string(fmt, 1), ref ptrResult);

                if (error != -1)
                {
                    if (ptrResult != IntPtr.Zero)
                    {
                        result =  MarshalUtils.GetPointerArray(ptrResult)
                            .Select(ptr => MarshalUtils.GetBytes(ptr).ToArray())
                            .ToArray();
                    }
                }

            }
            finally
            {
                if (ptrResult != IntPtr.Zero)
                {
                    LdapNative.Instance.ber_memfree(ptrResult);
                }
            }

            return error;
        }
    }
}