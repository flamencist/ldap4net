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
    public static class BerConverter
    {
        public static byte[] Encode(string format, params object[] value)
        {
            if (format == null)
                throw new ArgumentNullException(nameof(format));

            // no need to turn on invalid encoding detection as we just do string->byte[] conversion.
            var utf8Encoder = new UTF8Encoding();
            byte[] encodingResult;
            // value is allowed to be null in certain scenario, so if it is null, just set it to empty array.
            if (value == null)
                value = Array.Empty<object>();

            Debug.WriteLine("Begin encoding\n");

            // allocate the berelement
            var berElement = new BerSafeHandle();

            var valueCount = 0;
            var error = 0;
            foreach (var fmt in format)
            {
                if (fmt == '{' || fmt == '}' || fmt == '[' || fmt == ']' || fmt == 'n')
                {
                    // no argument needed
                    error = LdapNative.Instance.ber_printf_emptyarg(berElement, new string(fmt, 1));
                }
                else if (fmt == 't' || fmt == 'i' || fmt == 'e')
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
                    error = LdapNative.Instance.ber_printf_int(berElement, new string(fmt, 1), (int)value[valueCount]);
                    
                    // increase the value count
                    valueCount++;
                }
                else if (fmt == 'b')
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
                    error = LdapNative.Instance.ber_printf_int(berElement, new string(fmt, 1), (bool)value[valueCount] ? 1 : 0);

                    // increase the value count
                    valueCount++;
                }
                else if (fmt == 's')
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
                    value[valueCount] = value[valueCount] ?? string.Empty;
                    var tempValue = utf8Encoder.GetBytes((string) value[valueCount]);

                    error = EncodingByteArrayHelper(berElement, tempValue, 'o');

                    // increase the value count
                    valueCount++;
                }
                else if (fmt == 'o' || fmt == 'X' || fmt == 'B')
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
                    error = EncodingByteArrayHelper(berElement, tempValue, fmt);

                    valueCount++;
                }
                else if (fmt == 'O')
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
                    error = EncodingBerValHelper(berElement, tempValue, fmt);
                    valueCount++;
                }
                else if (fmt == 'v')
                {
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
                                tempValues[i] = utf8Encoder.GetBytes(s);
                            }
                        }
                    }

                    error = EncodingMultiByteArrayHelper(berElement, tempValues, fmt);

                    valueCount++;
                }
                else if (fmt == 'V')
                {
                    // we need to have one arguments
                    if (valueCount >= value.Length)
                    {
                        // we don't have enough argument for the format string
                        throw new ArgumentException("value argument is not valid, valueCount >= value.Length\n");
                    }

                    if (value[valueCount] != null && !(value[valueCount] is byte[][]))
                    {
                        // argument is wrong
                        throw new ArgumentException("type should be byte[][], but receiving value has type of " +
                                                    value[valueCount].GetType());
                    }

                    var tempValue = (byte[][]) value[valueCount];

                    error = EncodingBerValMultiByteArrayHelper(berElement, tempValue, fmt);

                    valueCount++;
                }
                else
                {
                    throw new ArgumentException("Format string contains undefined character: " + new string(fmt, 1));
                }

                // process the return value
                if (error == -1)
                {
                    Debug.WriteLine("ber_printf failed\n");
                    throw new LdapException("ber_printf failed\n");
                }
            }

            // get the binary value back
            var binaryValue = new Native.Native.berval();
            var flattenptr = IntPtr.Zero;

            try
            {
                // can't use SafeBerval here as CLR creates a SafeBerval which points to a different memory location, but when doing memory
                // deallocation, wldap has special check. So have to use IntPtr directly here.
                error = LdapNative.Instance.ber_flatten(berElement, ref flattenptr);

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
            
            

            Debug.WriteLine("Begin decoding\n");

            if (!format.All(LdapNative.Instance.BerScanfSupports))
            {
                throw new ArgumentException($"{nameof(format)} has unsupported format characters");
            }
            
            var utf8Encoder = new UTF8Encoding(false, true);
            var berValue = new Native.Native.berval();
            var resultList = new ArrayList();
            BerSafeHandle berElement;

            object[] decodeResult = null;
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

            var error = 0;

            for (var index = 0; index < format.Length; index++)
            {
                var fmt = format[index];
                if (fmt == '{' || fmt == '[')
                {
                    var next = index+1<format.Length ? format[index + 1]:'\0';
                    if (next != 'v' && next != 'V' && next != 'W' && next != 'M')
                    {
                        error = LdapNative.Instance.ber_scanf(berElement, new string(fmt, 1));

                        if (error == -1)
                        {
                            Debug.WriteLine("ber_scanf for {, }, [, ], n or x failed");
                        }
                    }
                }
                else if (fmt == '}'  || fmt == ']' || fmt == 'n' || fmt == 'x')
                {
                    error = LdapNative.Instance.ber_scanf(berElement, new string(fmt, 1));

                    if (error == -1)
                    {
                        Debug.WriteLine("ber_scanf for {, }, [, ], n or x failed");
                    }
                }
                else if (fmt == 'i' || fmt == 'e' || fmt == 'b')
                {
                    var result = 0;
                    error = LdapNative.Instance.ber_scanf_int(berElement, new string(fmt, 1), ref result);

                    if (error != -1)
                    {
                        if (fmt == 'b')
                        {
                            // should return a bool
                            var boolResult = result != 0;
                            resultList.Add(boolResult);
                        }
                        else
                        {
                            resultList.Add(result);
                        }
                    }
                    else
                    {
                        Debug.WriteLine("ber_scanf for format character 'i', 'e' or 'b' failed");
                    }
                }
                else if (fmt == 's')
                {
                    var ptr = Marshal.AllocHGlobal(IntPtr.Size);
                    var length = -1;
                    try
                    {
                        error = LdapNative.Instance.ber_scanf_string(berElement, new string(fmt, 1), ptr, ref length);
                        if (error != -1)
                        {
                            var byteArray = new byte[length];
                            Marshal.Copy(ptr, byteArray, 0, length);
                            var s = utf8Encoder.GetString(byteArray);
                            resultList.Add(s);
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
                            //Marshal.FreeHGlobal(ptr);
                        }
                    }
                }
                else if (fmt == 'a')
                {
                    // return a string
                    var byteArray = DecodingBerValByteArrayHelper(berElement, 'O', ref error);
                    if (error != -1)
                    {
                        string s = null;
                        if (byteArray != null)
                        {
                            s = utf8Encoder.GetString(byteArray);
                        }

                        resultList.Add(s);
                    }
                }
                else if (fmt == 'O')
                {
                    // return berval                   
                    var byteArray = DecodingBerValByteArrayHelper(berElement, fmt, ref error);
                    if (error != -1)
                    {
                        // add result to the list
                        resultList.Add(byteArray);
                    }
                }
                else if (fmt == 'o')
                {
                    // return berval                   
                    var byteArray = DecodingBerValOstringHelper(berElement, fmt, ref error);
                    if (error != -1)
                    {
                        // add result to the list
                        resultList.Add(byteArray);
                    }
                }
                else if (fmt == 'B')
                {
                    // return a bitstring and its length
                    var ptrResult = IntPtr.Zero;
                    var length = 0;
                    error = LdapNative.Instance.ber_scanf_bitstring(berElement, new string(fmt, 1), ref ptrResult,
                        ref length);

                    if (error != -1)
                    {
                        byte[] byteArray = null;
                        if (ptrResult != IntPtr.Zero)
                        {
                            byteArray = new byte[length];
                            Marshal.Copy(ptrResult, byteArray, 0, length);
                        }

                        resultList.Add(byteArray);
                    }
                    else
                    {
                        Debug.WriteLine("ber_scanf for format character 'B' failed");
                    }

                    // no need to free memory as wldap32 returns the original pointer instead of a duplicating memory pointer that
                    // needs to be freed
                }
                else if (fmt == 'v')
                {
                    //null terminate strings
                    string[] stringArray = null;

                    var byteArrayResult = DecodingMultiByteArrayHelper(berElement, fmt, ref error);
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
                                    stringArray[i] = utf8Encoder.GetString(byteArrayResult[i]);
                                }
                            }
                        }

                        resultList.Add(stringArray);
                    }
                }
                else if (fmt == 'V')
                {
                    var result = DecodingBerValMultiByteArrayHelper(berElement, fmt, ref error);
                    if (error != -1)
                    {
                        resultList.Add(result);
                    }
                }
                else
                {
                    throw new ArgumentException("Format string contains undefined character\n");
                }

                if (error == -1)
                {
                    // decode failed, just return
                    return decodeResult;
                }
            }

            decodeResult = new object[resultList.Count];
            for (var count = 0; count < resultList.Count; count++)
            {
                decodeResult[count] = resultList[count];
            }

            decodeSucceeded = true;
            return decodeResult;
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
        
        private static byte[] DecodingBerValOstringHelper(BerSafeHandle berElement, char fmt, ref int error)
        {
            error = 1;
            var result = Marshal.AllocHGlobal(IntPtr.Size);
            var binaryValue = new Native.Native.berval();
            byte[] byteArray = null;

            error = LdapNative.Instance.ber_scanf_ostring(berElement, new string(fmt, 1), result);

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

            return byteArray;
        }

        private static byte[] DecodingBerValByteArrayHelper(BerSafeHandle berElement, char fmt, ref int error)
        {
            error = 0;
            var result = IntPtr.Zero;
            var binaryValue = new Native.Native.berval();
            byte[] byteArray = null;

            // can't use SafeBerval here as CLR creates a SafeBerval which points to a different memory location, but when doing memory
            // deallocation, wldap has special check. So have to use IntPtr directly here.
            error = LdapNative.Instance.ber_scanf_ptr(berElement, new string(fmt, 1), ref result);

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

            return byteArray;
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
            var error = 0;

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
                        //Marshal.FreeHGlobal(ptr);
                    }
                    Marshal.FreeHGlobal(stringArray);
                }
            }

            return error;
        }

        
        private static int EncodingBerValMultiByteArrayHelper(BerSafeHandle berElement, byte[][] tempValue, char fmt)
        {
            var berValArray = IntPtr.Zero;
            var tempPtr = IntPtr.Zero;
            Native.Native.SafeBerval[] managedBerVal = null;
            var error = 0;

            try
            {
                if (tempValue != null)
                {
                    var i = 0;
                    berValArray = MarshalUtils.AllocHGlobalIntPtrArray(tempValue.Length + 1);
                    var structSize = Marshal.SizeOf(typeof(Native.Native.SafeBerval));
                    managedBerVal = new Native.Native.SafeBerval[tempValue.Length];

                    for (i = 0; i < tempValue.Length; i++)
                    {
                        var byteArray = tempValue[i];

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
                            Marshal.Copy(byteArray, 0, managedBerVal[i].bv_val, byteArray.Length);
                        }

                        // allocate memory for the unmanaged structure
                        var valPtr = Marshal.AllocHGlobal(structSize);
                        Marshal.StructureToPtr(managedBerVal[i], valPtr, false);

                        tempPtr = (IntPtr)((long)berValArray + IntPtr.Size * i);
                        Marshal.WriteIntPtr(tempPtr, valPtr);
                    }

                    tempPtr = (IntPtr)((long)berValArray + IntPtr.Size * i);
                    Marshal.WriteIntPtr(tempPtr, IntPtr.Zero);
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

        private static byte[][] DecodingBerValMultiByteArrayHelper(BerSafeHandle berElement, char fmt, ref int error)
        {
            error = 0;
            // several berval
            var ptrResult = IntPtr.Zero;
            var i = 0;
            var binaryList = new ArrayList();
            var tempPtr = IntPtr.Zero;
            byte[][] result = null;

            try
            {
                error = LdapNative.Instance.ber_scanf_ptr(berElement, new string(fmt, 1), ref ptrResult);

                if (error != -1)
                {
                    if (ptrResult != IntPtr.Zero)
                    {
                        tempPtr = Marshal.ReadIntPtr(ptrResult);
                        while (tempPtr != IntPtr.Zero)
                        {
                            var ber = new Native.Native.berval();
                            Marshal.PtrToStructure(tempPtr, ber);

                            var berArray = new byte[ber.bv_len];
                            Marshal.Copy(ber.bv_val, berArray, 0, ber.bv_len);

                            binaryList.Add(berArray);

                            i++;
                            tempPtr = Marshal.ReadIntPtr(ptrResult, i * IntPtr.Size);
                        }

                        result = new byte[binaryList.Count][];
                        for (var j = 0; j < binaryList.Count; j++)
                        {
                            result[j] = (byte[])binaryList[j];
                        }
                    }
                }
                else
                    Debug.WriteLine("ber_scanf for format character 'V' failed");
            }
            finally
            {
                if (ptrResult != IntPtr.Zero)
                {
                    LdapNative.Instance.ber_bvecfree(ptrResult);
                }
            }

            return result;
        }
        
        private static byte[][] DecodingMultiByteArrayHelper(BerSafeHandle berElement, char fmt, ref int error)
        {
            error = 0;
            var ptrResult = IntPtr.Zero;
            var binaryList = new ArrayList();
            byte[][] result = null;

            try
            {
                error = LdapNative.Instance.ber_scanf_ptr(berElement, new string(fmt, 1), ref ptrResult);

                if (error != -1)
                {
                    if (ptrResult != IntPtr.Zero)
                    {
                        foreach (var tempPtr in MarshalUtils.GetPointerArray(ptrResult))
                        {
                            var arr = new List<byte>();

                            var @byte = Marshal.ReadByte(tempPtr);
                            var j = 0;
                            while (@byte != 0)
                            {
                                arr.Add(@byte);
                                j++;
                                @byte = Marshal.ReadByte(tempPtr, j);
                            }

                            binaryList.Add(arr.ToArray());
                        }

                        result = new byte[binaryList.Count][];
                        for (var j = 0; j < binaryList.Count; j++)
                        {
                            result[j] = (byte[])binaryList[j];
                        }
                    }
                }
                else
                    Debug.WriteLine("ber_scanf for format character 'v' failed");
            }
            finally
            {
                if (ptrResult != IntPtr.Zero)
                {
                    LdapNative.Instance.ber_memfree(ptrResult);
                }
            }

            return result;
        }
    }
}