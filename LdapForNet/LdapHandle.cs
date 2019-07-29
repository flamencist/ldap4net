using System;
using LdapForNet.Native;
using Microsoft.Win32.SafeHandles;

namespace LdapForNet
{
    public class LdapHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public LdapHandle(IntPtr handle) : base(true)
        {
            SetHandle(handle);
        }

        protected override bool ReleaseHandle()
        {
            return LdapNative.Instance.ldap_unbind_s(handle) == (int) Native.Native.LdapResultCode.LDAP_SUCCESS;
        }
    }
}