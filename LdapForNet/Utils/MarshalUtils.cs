using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet.Native;

namespace LdapForNet.Utils
{
    internal static class MarshalUtils
    {
        
        internal static List<string> PtrToStringArray(IntPtr ptr)
        {
            return GetPointerArray(ptr)
                .Select(tempPtr => Encoder.Instance.PtrToString(tempPtr))
                .ToList();
        }

        internal static List<byte[]> BerValArrayToByteArrays(IntPtr ptr)
        {
            var result = new List<byte[]>();
            foreach (var tempPtr in GetPointerArray(ptr))
            {
                var bervalue = new Native.Native.berval();
                Marshal.PtrToStructure(tempPtr, bervalue);
                if (bervalue.bv_len > 0 && bervalue.bv_val != IntPtr.Zero)
                {
                    var byteArray = new byte[bervalue.bv_len];
                    Marshal.Copy(bervalue.bv_val, byteArray, 0, bervalue.bv_len);
                    result.Add(byteArray);
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
        
        internal static IntPtr ByteArrayToGnuTlsDatum(byte[] bytes)
        {
            var berPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethodsLinux.gnutls_datum_t>());
            var valPtr = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes,0,valPtr,bytes.Length);
            Marshal.StructureToPtr(new NativeMethodsLinux.gnutls_datum_t
            {
                data = valPtr,
                size = bytes.Length
            }, berPtr, true);
            return berPtr;
        }
        
        internal static void TlsDatumFree(IntPtr datum)
        {
            if (datum != IntPtr.Zero)
            {
                var d = Marshal.PtrToStructure<NativeMethodsLinux.gnutls_datum_t>(datum);
                Marshal.FreeHGlobal(d.data);
                Marshal.FreeHGlobal(datum);
            }
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
            foreach (var ptr in GetPointerArray(array))
            {
                BerValFree(ptr);
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
                var intPtrArray = Marshal.AllocHGlobal(IntPtr.Size * size);
                for (var i = 0; i < size; i++)
                {
                    Marshal.WriteIntPtr(intPtrArray, IntPtr.Size * i,IntPtr.Zero);
                }
                return intPtrArray;
            }
        }

        internal static IEnumerable<IntPtr> GetPointerArray(IntPtr array)
        {
            if (array != IntPtr.Zero)
            {
                var count = 0;
                var tempPtr = Marshal.ReadIntPtr(array, count * IntPtr.Size);
                while (tempPtr != IntPtr.Zero)
                {
                    yield return tempPtr;
                    count++;
                    tempPtr = Marshal.ReadIntPtr(array, count * IntPtr.Size);
                }
            }

        }
    }
}