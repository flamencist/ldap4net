using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace LdapForNet.Utils
{
    internal static class MarshalUtils
    {
        
        internal static List<string> PtrToStringArray(IntPtr ptr)
        {
            var count = 0;
            var result = new List<string>();
            if (ptr != IntPtr.Zero)
            {
                var tempPtr = Marshal.ReadIntPtr(ptr, IntPtr.Size * count);
                while (tempPtr != IntPtr.Zero)
                {
                    result.Add(Encoder.Instance.PtrToString(tempPtr));
                    count++;
                    tempPtr = Marshal.ReadIntPtr(ptr, IntPtr.Size * count);
                }
            }
            return result;
        }

        internal static List<byte[]> BerValArrayToByteArrays(IntPtr ptr)
        {
            var result = new List<byte[]>();
            if (ptr != IntPtr.Zero)
            {
                var count = 0;
                var tempPtr = Marshal.ReadIntPtr(ptr, IntPtr.Size * count);
                while (tempPtr != IntPtr.Zero)
                {
                    var bervalue = new Native.Native.berval();
                    Marshal.PtrToStructure(tempPtr, bervalue);
                    if (bervalue.bv_len > 0 && bervalue.bv_val != IntPtr.Zero)
                    {
                        var byteArray = new byte[bervalue.bv_len];
                        Marshal.Copy(bervalue.bv_val, byteArray, 0, bervalue.bv_len);
                        result.Add(byteArray);
                    }
                    count++;
                    tempPtr = Marshal.ReadIntPtr(ptr, IntPtr.Size * count);
                }
            }

            return result;
        }

        internal static void ByteArraysToBerValueArray(byte[][] sourceData, IntPtr ptr)
        {
            for (var i = 0; i < sourceData.Length; i++)
            {
                var berPtr = ByteArrayToBerValue(sourceData[i]);
                Marshal.WriteIntPtr(ptr,i*IntPtr.Size,berPtr);
            }
            Marshal.WriteIntPtr(ptr, sourceData.Length*IntPtr.Size,IntPtr.Zero);
        }

        internal static IntPtr ByteArrayToBerValue(byte[] bytes)
        {
            var berPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.Native.berval>());
            var valPtr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes,0,valPtr,bytes.Length);
            Marshal.StructureToPtr(new Native.Native.berval
            {
                bv_val = valPtr,
                bv_len = bytes.Length
            }, berPtr, true);
            return berPtr;
        }

        internal static void BerValFree(IntPtr berval)
        {
            if (berval != IntPtr.Zero)
            {
                var b = Marshal.PtrToStructure<Native.Native.berval>(berval);
                Marshal.FreeHGlobal(b.bv_val);
                Marshal.FreeHGlobal(berval);
            }
        }

        internal static void BerValuesFree(IntPtr array)
        {
            var count = 0;
            var tempPtr = Marshal.ReadIntPtr(array, count * IntPtr.Size);
            while (tempPtr != IntPtr.Zero)
            {
                BerValFree(tempPtr);
                count++;
                tempPtr = Marshal.ReadIntPtr(array, count * IntPtr.Size);
            }
        }

        

        internal static void StringArrayToPtr(IEnumerable<string> array, IntPtr ptr)
        {
            var ptrArray = array.Select(Encoder.Instance.StringToPtr).ToArray();
            Marshal.Copy(ptrArray,0,ptr,ptrArray.Length);
        }
        
        internal static void StructureArrayToPtr<T>(IEnumerable<T> array,IntPtr ptr, bool endNull = false) 
        {
            var ptrArray = array.Select(structure =>
            {
                var structPtr = Marshal.AllocHGlobal(Marshal.SizeOf<T>());
                Marshal.StructureToPtr(structure,structPtr,false);
                return structPtr;
            }).ToList();
            if (endNull)
            {
                ptrArray.Add(IntPtr.Zero);
            }

            Marshal.Copy(ptrArray.ToArray(),0,ptr,ptrArray.Count);  
        }

        internal static IntPtr BytesToPtr(byte[] bytes)
        {
            if (bytes == null)
            {
                return IntPtr.Zero;
            }
            var ptr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes,0,ptr,bytes.Length);
            return ptr;
        }

        internal static IntPtr AllocHGlobalIntPtrArray(int size)
        {
            checked
            {
                var intPtrArray = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(IntPtr)) * size);
                for (var i = 0; i < size; i++)
                {
                    var tempPtr = (IntPtr)((long)intPtrArray + Marshal.SizeOf(typeof(IntPtr)) * i);
                    Marshal.WriteIntPtr(tempPtr, IntPtr.Zero);
                }
                return intPtrArray;
            }
        }
    }
}