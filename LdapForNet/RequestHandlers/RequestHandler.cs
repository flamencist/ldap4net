using System;
using System.Collections;
using System.Collections.Generic;
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

        public int SendRequest(SafeHandle handle, DirectoryRequest request, ref int messageId)
        {
            AllocControls(request, out var serverControlArray, out var managedServerControls, out var clientControlArray, out var managedClientControls);
            try
            {
                return SendRequest(handle, request, serverControlArray, clientControlArray, ref messageId);
            }
            finally
            {
                FreeControls(serverControlArray,managedServerControls,clientControlArray,managedClientControls);
            }
        }
        
        protected abstract int SendRequest(SafeHandle handle, DirectoryRequest request, IntPtr serverControls, IntPtr clientControls, ref int messageId);

        public abstract LdapResultCompleteStatus Handle(SafeHandle handle, Native.Native.LdapResultType resType, IntPtr msg,
            out DirectoryResponse response);
        
        
        private static void AllocControls(DirectoryRequest request,
            out IntPtr serverControlArray, out Native.Native.LdapControl[] managedServerControls,
            out IntPtr clientControlArray, out Native.Native.LdapControl[] managedClientControls)
        {
            serverControlArray = IntPtr.Zero;
            managedServerControls = null;
            clientControlArray = IntPtr.Zero;
            managedClientControls = null;
            var tempPtr = IntPtr.Zero;

            // Build server control.
            managedServerControls = BuildControlArray(request.Controls, true);
            var structSize = Marshal.SizeOf(typeof(Native.Native.LdapControl));

            if (managedServerControls != null)
            {
                serverControlArray = MarshalUtils.AllocHGlobalIntPtrArray(managedServerControls.Length + 1);
                for (var i = 0; i < managedServerControls.Length; i++)
                {
                    var controlPtr = Marshal.AllocHGlobal(structSize);
                    Marshal.StructureToPtr(managedServerControls[i], controlPtr, false);
                    tempPtr = (IntPtr)((long)serverControlArray + IntPtr.Size * i);
                    Marshal.WriteIntPtr(tempPtr, controlPtr);
                }

                tempPtr = (IntPtr)((long)serverControlArray + IntPtr.Size * managedServerControls.Length);
                Marshal.WriteIntPtr(tempPtr, IntPtr.Zero);
            }

            // build client control
            managedClientControls = BuildControlArray(request.Controls, false);
            if (managedClientControls != null)
            {
                clientControlArray = MarshalUtils.AllocHGlobalIntPtrArray(managedClientControls.Length + 1);
                for (var i = 0; i < managedClientControls.Length; i++)
                {
                    var controlPtr = Marshal.AllocHGlobal(structSize);
                    Marshal.StructureToPtr(managedClientControls[i], controlPtr, false);
                    tempPtr = (IntPtr)((long)clientControlArray + IntPtr.Size * i);
                    Marshal.WriteIntPtr(tempPtr, controlPtr);
                }

                tempPtr = (IntPtr)((long)clientControlArray + IntPtr.Size * managedClientControls.Length);
                Marshal.WriteIntPtr(tempPtr, IntPtr.Zero);
            }
        }

        private static void FreeControls(IntPtr serverControlArray, IList<Native.Native.LdapControl> managedServerControls, IntPtr clientControlArray, IList<Native.Native.LdapControl> managedClientControls)
        {
            if (serverControlArray != IntPtr.Zero)
            {
                // Release the memory from the heap.
                for (int i = 0; i < managedServerControls.Count; i++)
                {
                    IntPtr tempPtr = Marshal.ReadIntPtr(serverControlArray, IntPtr.Size * i);
                    if (tempPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(tempPtr);
                    }
                }
                Marshal.FreeHGlobal(serverControlArray);
            }

            if (managedServerControls != null)
            {
                for (int i = 0; i < managedServerControls.Count; i++)
                {
                    if (managedServerControls[i].ldctl_oid != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(managedServerControls[i].ldctl_oid);
                    }

                    if (managedServerControls[i].ldctl_value != null)
                    {
                        if (managedServerControls[i].ldctl_value.bv_val != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(managedServerControls[i].ldctl_value.bv_val);
                        }
                    }
                }
            }

            if (clientControlArray != IntPtr.Zero)
            {
                // Release the memory from the heap.
                for (int i = 0; i < managedClientControls.Count; i++)
                {
                    IntPtr tempPtr = Marshal.ReadIntPtr(clientControlArray, IntPtr.Size * i);
                    if (tempPtr != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(tempPtr);
                    }
                }

                Marshal.FreeHGlobal(clientControlArray);
            }

            if (managedClientControls != null)
            {
                for (int i = 0; i < managedClientControls.Count; i++)
                {
                    if (managedClientControls[i].ldctl_oid != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(managedClientControls[i].ldctl_oid);
                    }

                    if (managedClientControls[i].ldctl_value != null)
                    {
                        if (managedClientControls[i].ldctl_value.bv_val != IntPtr.Zero)
                        {
                            Marshal.FreeHGlobal(managedClientControls[i].ldctl_value.bv_val);
                        }
                    }
                }
            }
        }
        
        
        private static Native.Native.LdapControl[] BuildControlArray(List<DirectoryControl> controls, bool serverControl)
        {
            Native.Native.LdapControl[] managedControls = null;

            if (controls != null && controls.Count != 0)
            {
                var controlList = new ArrayList();
                foreach (DirectoryControl col in controls)
                {
                    if (serverControl)
                    {
                        if (col.ServerSide)
                        {
                            controlList.Add(col);
                        }
                    }
                    else if (!col.ServerSide)
                    {
                        controlList.Add(col);
                    }
                }

                if (controlList.Count != 0)
                {
                    int count = controlList.Count;
                    managedControls = new Native.Native.LdapControl[count];

                    for (int i = 0; i < count; i++)
                    {
                        managedControls[i] = new Native.Native.LdapControl()
                        {
                            // Get the control type.
                            ldctl_oid = Encoder.Instance.StringToPtr(((DirectoryControl)controlList[i]).Type),

                            // Get the control cricality.
                            ldctl_iscritical = ((DirectoryControl)controlList[i]).IsCritical
                        };

                        // Get the control value.
                        DirectoryControl tempControl = (DirectoryControl)controlList[i];
                        byte[] byteControlValue = tempControl.GetValue();
                        if (byteControlValue == null || byteControlValue.Length == 0)
                        {
                            // Treat the control value as null.
                            managedControls[i].ldctl_value = new Native.Native.berval
                            {
                                bv_len = 0,
                                bv_val = IntPtr.Zero
                            };
                        }
                        else
                        {
                            managedControls[i].ldctl_value = new Native.Native.berval
                            {
                                bv_len = byteControlValue.Length,
                                bv_val = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(byte)) * byteControlValue.Length)
                            };
                            Marshal.Copy(byteControlValue, 0, managedControls[i].ldctl_value.bv_val, managedControls[i].ldctl_value.bv_len);
                        }
                    }
                }
            }

            return managedControls;
        }

    }
}