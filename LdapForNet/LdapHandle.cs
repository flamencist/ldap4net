using System;
using System.Runtime.InteropServices;
using LdapForNet.Native;
using Microsoft.Win32.SafeHandles;

namespace LdapForNet
{
    internal class LdapHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public LdapHandle(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return LdapNative.Instance.ldap_unbind_s(handle) == (int) Native.Native.ResultCode.Success;
        }
    }
    
    internal sealed class BerSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal BerSafeHandle() : base(true)
        {
            SetHandle(LdapNative.Instance.ber_alloc_t((int)Native.Native.BerElementOption.LBER_USE_DER));
            if (handle == IntPtr.Zero)
            {
                throw new OutOfMemoryException();
            }
        }

        internal BerSafeHandle(Native.Native.berval value) : base(true)
        {
            var ptr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.Native.berval>());

            try
            {
                Marshal.StructureToPtr(value,ptr,false);
                SetHandle(LdapNative.Instance.ber_init(ptr));
                if (handle == IntPtr.Zero)
                {
                    throw new LdapException("Could not initialized ber value");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        protected override bool ReleaseHandle()
        {
            LdapNative.Instance.ber_free(handle, 1);
            return true;
        }
    }
    
    internal sealed class HGlobalMemHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal HGlobalMemHandle(IntPtr value) : base(true)
        {
            SetHandle(value);
        }

        protected override bool ReleaseHandle()
        {
            Marshal.FreeHGlobal(handle);
            return true;
        }
    }

}