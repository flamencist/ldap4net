using System;
using System.Collections.Generic;
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
                result.Add(Marshal.PtrToStringAnsi(s));
                offset += IntPtr.Size;
            }
            return result;
        }
       
    }
}