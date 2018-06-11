using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using LdapForNet.Native;
using LdapForNet.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LdapForNetTests.Utils
{
    [TestClass]
    public class MarshalUtilsTests
    {
        [TestMethod]
        public void MarshalUtils_PtrToStringArray_Returns_List_Of_String()
        {
            var data = Marshal.StringToHGlobalAnsi("test");
            var data2 = Marshal.StringToHGlobalAnsi("test2");
            
            var ptr = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.StructureToPtr(data, ptr, true);
            Marshal.StructureToPtr(data2, new IntPtr(ptr.ToInt64() + IntPtr.Size), true);
            Marshal.StructureToPtr(IntPtr.Zero, new IntPtr(ptr.ToInt64() + 2*IntPtr.Size), true);
                
            var actual = MarshalUtils.PtrToStringArray(ptr);
            
            Assert.AreEqual(2, actual.Count);
            Assert.AreEqual("test", actual[0]);
            Assert.AreEqual("test2", actual[1]);
            
            Marshal.FreeHGlobal(ptr);
            Marshal.FreeHGlobal(data);
            Marshal.FreeHGlobal(data2);
        }

        [TestMethod]
        public void MarshalUtils_StringArrayToPtr_Returns_Ptr_To_StringArray()
        {
            var data = new List<string> { "test","other","third"};
            var actual = Marshal.AllocHGlobal(IntPtr.Size*data.Count+1);
            MarshalUtils.StringArrayToPtr(data, actual);
            Assert.AreNotEqual(IntPtr.Zero, actual);

            var ptr1 = Marshal.ReadIntPtr(actual);
            var ptr2 = Marshal.ReadIntPtr(actual,IntPtr.Size);
            var ptr3 = Marshal.ReadIntPtr(actual,IntPtr.Size*2);
            
            var first = Marshal.PtrToStringAnsi(ptr1);
            var second = Marshal.PtrToStringAnsi(ptr2);
            var third = Marshal.PtrToStringAnsi(ptr3);
            
            Assert.AreEqual("test",first);
            Assert.AreEqual("other",second);
            Assert.AreEqual("third",third);
            
            Marshal.FreeHGlobal(actual);
        }

        [TestMethod]
        public void MarshalUtils_StructureArrayToPtr_Returns_Ptr_To_StructureArray()
        {
            var data = new List<Point>
            {
                new Point{X=1,Y=1},
                new Point{X=2,Y=2},
                new Point{X=3,Y=3},
            };
            var actual = Marshal.AllocHGlobal(IntPtr.Size*data.Count+1);
            MarshalUtils.StructureArrayToPtr(data, actual, true);
            Assert.AreNotEqual(IntPtr.Zero, actual);

            var ptr1 = Marshal.ReadIntPtr(actual);
            var ptr2 = Marshal.ReadIntPtr(actual,IntPtr.Size);
            var ptr3 = Marshal.ReadIntPtr(actual,IntPtr.Size*2);
            var ptr4 = Marshal.ReadIntPtr(actual, IntPtr.Size * 3);
            
            var first = Marshal.PtrToStructure<Point>(ptr1);
            var second = Marshal.PtrToStructure<Point>(ptr2);
            var third = Marshal.PtrToStructure<Point>(ptr3);
            
            Assert.AreEqual(1,first.X);
            Assert.AreEqual(1,first.Y);
            Assert.AreEqual(2,second.X);
            Assert.AreEqual(2,second.Y);
            Assert.AreEqual(3,third.X);
            Assert.AreEqual(3,third.Y);
            Assert.AreEqual(IntPtr.Zero,ptr4);
            
            Marshal.FreeHGlobal(actual);
        }
        
        [TestMethod]
        public void MarshalUtils_StructureArrayToPtr_LDAPMod()
        {
            var val = new List<string> { "test","other","third"};
            var valPtr = Marshal.AllocHGlobal(IntPtr.Size*val.Count+1);
            MarshalUtils.StringArrayToPtr(val,valPtr);
            var data = new List<LDAPMod>
            {
                new LDAPMod
                {
                    mod_op = (int) LDAP_MOD_OPERATION.LDAP_MOD_ADD,
                    mod_type = "test",
                    mod_vals_u = new LDAPMod.mod_vals
                    {
                        modv_strvals  = valPtr
                    }
                },
                new LDAPMod
                {
                    mod_op = (int) LDAP_MOD_OPERATION.LDAP_MOD_ADD,
                    mod_type = "test2",
                    mod_vals_u = new LDAPMod.mod_vals
                    {
                        modv_strvals  = IntPtr.Zero
                    }
                }
            };
            var actual = Marshal.AllocHGlobal(IntPtr.Size*data.Count+1);
            MarshalUtils.StructureArrayToPtr(data,actual, true);
            Assert.AreNotEqual(IntPtr.Zero, actual);

            var ptr1 = Marshal.ReadIntPtr(actual);
            var ptr2 = Marshal.ReadIntPtr(actual,IntPtr.Size);
            var ptr3 = Marshal.ReadIntPtr(actual, IntPtr.Size * 2);
            
            var first = Marshal.PtrToStructure<LDAPMod>(ptr1);
            var second = Marshal.PtrToStructure<LDAPMod>(ptr2);

            var valPtr1 = Marshal.ReadIntPtr(first.mod_vals_u.modv_strvals);
            var valPtr2 = Marshal.ReadIntPtr(first.mod_vals_u.modv_strvals,IntPtr.Size);
            var valPtr3 = Marshal.ReadIntPtr(first.mod_vals_u.modv_strvals,IntPtr.Size*2);
            
            var valFirst = Marshal.PtrToStringAnsi(valPtr1);
            var valSecond = Marshal.PtrToStringAnsi(valPtr2);
            var valThird = Marshal.PtrToStringAnsi(valPtr3);
                
            Assert.AreEqual(0,first.mod_op);
            Assert.AreEqual("test",first.mod_type);
            Assert.AreEqual("test",valFirst);
            Assert.AreEqual("other",valSecond);
            Assert.AreEqual("third",valThird);
            Assert.AreEqual(0,second.mod_op);
            Assert.AreEqual("test2",second.mod_type);
            Assert.AreEqual(IntPtr.Zero,second.mod_vals_u.modv_strvals);
            Assert.AreEqual(IntPtr.Zero,ptr3);
            
            Marshal.FreeHGlobal(actual);
            Marshal.FreeHGlobal(valPtr);
        }
        
    }
    
    public struct Point
    {
        public int X;
        public int Y;
    }

}