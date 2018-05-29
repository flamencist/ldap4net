using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
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
            var actual = MarshalUtils.StringArrayToPtr(data);
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
            var actual = MarshalUtils.StructureArrayToPtr(data, true);
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
    }
    
    public struct Point
    {
        public int X;
        public int Y;
    }

}