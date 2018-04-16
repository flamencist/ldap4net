using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static System.Text.Encoding;

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
                result.Add(Marshal.PtrToStringAnsi(s));
                offset += IntPtr.Size;
            }
            return result;
        }
        
        internal static IntPtr StringArrayToPtr(List<string> array)
        {
            var ptr = Marshal.AllocHGlobal(IntPtr.Size);
            for (var i = 0; i < array.Count; i++)
            {
                var chars = ASCII.GetBytes(array[i] + '\0');
                Marshal.Copy(chars, 0, Marshal.ReadIntPtr(ptr, i * IntPtr.Size), chars.Length);
            }

            return ptr;
        }
        
        internal static IntPtr StructureArrayToPtr<T>(List<T> array, bool endNull = false) where T: struct
        {
            var ptr = Marshal.AllocHGlobal(IntPtr.Size);
            for (var i = 0; i < array.Count; i++)
            {
                var p = new IntPtr(ptr.ToInt64() + i*IntPtr.Size);
                Marshal.StructureToPtr(array[i],p,true);
            }

            if (endNull)
            {
                var end = new IntPtr(ptr.ToInt64() + array.Count * IntPtr.Size);
                Marshal.StructureToPtr(IntPtr.Zero,end,true);
            }
            
            return ptr;
        }
       
    }
}