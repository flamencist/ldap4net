using System;
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
    }
}