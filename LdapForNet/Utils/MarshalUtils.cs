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
                    result.Add(Marshal.PtrToStringAnsi(tempPtr));
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
            var sourceDataPtrs = sourceData.Select(_ => Marshal.AllocCoTaskMem(_.Length + 1)).ToArray();
            for (var i = 0; i < sourceData.Length; i++)
            {
                Marshal.Copy(sourceData[i].Union(new byte[] { 0 }).ToArray(), 0, sourceDataPtrs[i], sourceData[i].Length + 1);
            }

            for (var i = 0; i < sourceDataPtrs.Length; i++)
            {
                var berPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.Native.berval>());
                Marshal.StructureToPtr(new Native.Native.berval
                {
                    bv_val = sourceDataPtrs[i],
                    bv_len = sourceData[i].Length
                }, berPtr, true);
                Marshal.StructureToPtr(berPtr, new IntPtr(ptr.ToInt64() + i * IntPtr.Size), true);
            }
            Marshal.StructureToPtr(IntPtr.Zero, new IntPtr(ptr.ToInt64() + sourceDataPtrs.Length * IntPtr.Size), true);
        }

        internal static void StringArrayToPtr(IEnumerable<string> array, IntPtr ptr)
        {
            var ptrArray = array.Select(Marshal.StringToHGlobalAnsi).ToArray();
            Marshal.Copy(ptrArray,0,ptr,ptrArray.Length);
        }
        
        internal static void StructureArrayToPtr<T>(IEnumerable<T> array,IntPtr ptr, bool endNull = false) where T: struct
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
       
    }
}