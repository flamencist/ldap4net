﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;

namespace LdapForNet.Utils
{
    internal static class MarshalUtils
    {
        
        internal static List<string> PtrToStringArray(IntPtr ptr)
        {
            var offset = 0;
            var result = new List<string>();
            while (true)
            {
                var el = new IntPtr(ptr.ToInt64() + offset);
                var s = Marshal.PtrToStructure<IntPtr>(el);
                if (s == IntPtr.Zero)
                {
                    break;
                }
                result.Add(Marshal.PtrToStringUni(s));
                offset += IntPtr.Size;
            }
            return result;
        }
        
        internal static void StringArrayToPtr(IEnumerable<string> array, IntPtr ptr)
        {
            var ptrArray = array.Select(Marshal.StringToHGlobalUni).ToArray();
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