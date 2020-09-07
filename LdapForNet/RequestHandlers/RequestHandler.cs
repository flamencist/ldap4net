using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet.Native;
using LdapForNet.Utils;

namespace LdapForNet.RequestHandlers
{
    internal abstract class RequestHandler
    {
        protected LdapNative Native;

        protected RequestHandler()
        {
            Native = LdapNative.Instance;
        }

        internal void SetNative(LdapNative native) => Native = native;

        public virtual int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            var serverControlArray = AllocControls(request.Controls, true);
            var clientControlArray = AllocControls(request.Controls, false);
            try
            {
                return SendRequest(handle, request, serverControlArray, clientControlArray, ref messageId);
            }
            finally
            {
                FreeControls(serverControlArray);
                FreeControls(clientControlArray);
            }
        }
        
        protected abstract int SendRequest(SafeHandle handle, DirectoryRequest request, IntPtr serverControls, IntPtr clientControls, ref int messageId);

        public abstract LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg,
            out DirectoryResponse response);
        
        
        private static IntPtr AllocControls(IReadOnlyCollection<DirectoryControl> controls, bool isServerControl)
        {
            var result = IntPtr.Zero;

            var managedServerControls = BuildControlArray(controls, isServerControl);
            if (managedServerControls != null)
            {
                result = MarshalUtils.StructureArrayToPtr(managedServerControls);
            }

            return result;
        }

        private static void FreeControls(IntPtr controlArray)
        {

            foreach (var ptr in MarshalUtils.GetPointerArray(controlArray))
            {
                var ctrl = Marshal.PtrToStructure<Native.Native.LdapControl>(ptr);
                FreeManagedControl(ctrl);
            }

            MarshalUtils.FreeIntPtrArray(controlArray);
        }

        private static void FreeManagedControl(Native.Native.LdapControl ctrl)
        {
            if (ctrl.ldctl_oid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ctrl.ldctl_oid);
            }

            if (ctrl.ldctl_value != null && ctrl.ldctl_value.bv_val != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(ctrl.ldctl_value.bv_val);
            }
        }


        private static Native.Native.LdapControl[] BuildControlArray(IReadOnlyCollection<DirectoryControl> controls, bool isServerControl)
        {
            if (controls == null)
            {
                return null;
            }

            var serverSideControls = controls.Where(_ => _.ServerSide);
            var clientSideControls = controls.Where(_ => !_.ServerSide);
            var selectedControls = isServerControl? serverSideControls : clientSideControls;
            var ldapControls = selectedControls.Select(ToLdapControl).ToArray();

            return ldapControls.Any() ? ldapControls : null;
        }

        private static Native.Native.LdapControl ToLdapControl(DirectoryControl sourceCtrl)
        {
            var ctrl = new Native.Native.LdapControl
            {
                // Get the control type.
                ldctl_oid = Encoder.Instance.StringToPtr(sourceCtrl.Type),

                // Get the control cricality.
                ldctl_iscritical = sourceCtrl.IsCritical
            };

            // Get the control value.
            var byteControlValue = sourceCtrl.GetValue();
            if (byteControlValue == null || byteControlValue.Length == 0)
            {
                // Treat the control value as null.
                ctrl.ldctl_value = new Native.Native.berval
                {
                    bv_len = 0,
                    bv_val = IntPtr.Zero
                };
            }
            else
            {
                ctrl.ldctl_value = new Native.Native.berval
                {
                    bv_len = byteControlValue.Length,
                    bv_val = Marshal.AllocHGlobal(byteControlValue.Length)
                };
                Marshal.Copy(byteControlValue, 0, ctrl.ldctl_value.bv_val, ctrl.ldctl_value.bv_len);
            }
            return ctrl;

        }
    }
}