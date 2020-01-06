using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet.Native;
using LdapForNet.Utils;
using Xunit;

namespace LdapForNetTests.Utils
{
    public class MarshalUtilsTests
    {
        [Fact]
        public void MarshalUtils_PtrToStringArray_Returns_List_Of_String()
        {
            var data = Encoder.Instance.StringToPtr("test");
            var data2 = Encoder.Instance.StringToPtr("test2");
            
            var ptr = Marshal.AllocCoTaskMem(3*IntPtr.Size);
            Marshal.StructureToPtr(data, ptr, true);
            Marshal.StructureToPtr(data2, new IntPtr(ptr.ToInt64() + IntPtr.Size), true);
            Marshal.StructureToPtr(IntPtr.Zero, new IntPtr(ptr.ToInt64() + 2*IntPtr.Size), true);
                
            var actual = MarshalUtils.PtrToStringArray(ptr);
            
            Assert.Equal(2, actual.Count);
            Assert.Equal("test", actual[0]);
            Assert.Equal("test2", actual[1]);
            
            Marshal.FreeCoTaskMem(ptr);
            Marshal.FreeHGlobal(data);
            Marshal.FreeHGlobal(data2);
        }

        [Fact]
        public void MarshalUtils_StringArrayToPtr_Returns_Ptr_To_StringArray()
        {
            var data = new List<string> { "test","other","third"};
            var actual = Marshal.AllocHGlobal(IntPtr.Size*data.Count+1);
            MarshalUtils.StringArrayToPtr(data, actual);
            Assert.NotEqual(IntPtr.Zero, actual);

            var ptr1 = Marshal.ReadIntPtr(actual);
            var ptr2 = Marshal.ReadIntPtr(actual,IntPtr.Size);
            var ptr3 = Marshal.ReadIntPtr(actual,IntPtr.Size*2);
            
            var first = Marshal.PtrToStringUni(ptr1);
            var second = Marshal.PtrToStringUni(ptr2);
            var third = Marshal.PtrToStringUni(ptr3);
            
            Assert.Equal("test",first);
            Assert.Equal("other",second);
            Assert.Equal("third",third);
            
            Marshal.FreeHGlobal(actual);
        }

        [Fact]
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
            Assert.NotEqual(IntPtr.Zero, actual);

            var ptr1 = Marshal.ReadIntPtr(actual);
            var ptr2 = Marshal.ReadIntPtr(actual,IntPtr.Size);
            var ptr3 = Marshal.ReadIntPtr(actual,IntPtr.Size*2);
            var ptr4 = Marshal.ReadIntPtr(actual, IntPtr.Size * 3);
            
            var first = Marshal.PtrToStructure<Point>(ptr1);
            var second = Marshal.PtrToStructure<Point>(ptr2);
            var third = Marshal.PtrToStructure<Point>(ptr3);
            
            Assert.Equal(1,first.X);
            Assert.Equal(1,first.Y);
            Assert.Equal(2,second.X);
            Assert.Equal(2,second.Y);
            Assert.Equal(3,third.X);
            Assert.Equal(3,third.Y);
            Assert.Equal(IntPtr.Zero,ptr4);
            
            Marshal.FreeHGlobal(actual);
        }
        
        [Fact]
        public void MarshalUtils_StructureArrayToPtr_LDAPMod()
        {
            var val = new List<string> { "test","other","third", null};
            var valPtr = Marshal.AllocHGlobal(IntPtr.Size*val.Count);
            MarshalUtils.StringArrayToPtr(val,valPtr);
            var data = new List<Native.LDAPMod>
            {
                new Native.LDAPMod
                {
                    mod_op = (int) Native.LdapModOperation.LDAP_MOD_ADD,
                    mod_type = Encoder.Instance.StringToPtr("test"),
                    mod_vals_u = new Native.LDAPMod.mod_vals
                    {
                        modv_strvals  = valPtr
                    }
                },
                new Native.LDAPMod
                {
                    mod_op = (int) Native.LdapModOperation.LDAP_MOD_ADD,
                    mod_type = Encoder.Instance.StringToPtr("test2"),
                    mod_vals_u = new Native.LDAPMod.mod_vals
                    {
                        modv_strvals  = IntPtr.Zero
                    }
                }
            };
            var actual = Marshal.AllocHGlobal(IntPtr.Size*(data.Count+1));
            MarshalUtils.StructureArrayToPtr(data,actual, true);
            Assert.NotEqual(IntPtr.Zero, actual);

            var ptr1 = Marshal.ReadIntPtr(actual);
            var ptr2 = Marshal.ReadIntPtr(actual,IntPtr.Size);
            var ptr3 = Marshal.ReadIntPtr(actual, IntPtr.Size * 2);
            
            var first = Marshal.PtrToStructure<Native.LDAPMod>(ptr1);
            var second = Marshal.PtrToStructure<Native.LDAPMod>(ptr2);

            var valPtr1 = Marshal.ReadIntPtr(first.mod_vals_u.modv_strvals);
            var valPtr2 = Marshal.ReadIntPtr(first.mod_vals_u.modv_strvals,IntPtr.Size);
            var valPtr3 = Marshal.ReadIntPtr(first.mod_vals_u.modv_strvals,IntPtr.Size*2);
            
            var valFirst = Encoder.Instance.PtrToString(valPtr1);
            var valSecond = Encoder.Instance.PtrToString(valPtr2);
            var valThird = Encoder.Instance.PtrToString(valPtr3);
                
            Assert.Equal(0,first.mod_op);
            Assert.Equal("test", Encoder.Instance.PtrToString(first.mod_type));
            Assert.Equal("test",valFirst);
            Assert.Equal("other",valSecond);
            Assert.Equal("third",valThird);
            Assert.Equal(0,second.mod_op);
            Assert.Equal("test2", Encoder.Instance.PtrToString(second.mod_type));
            Assert.Equal(IntPtr.Zero,second.mod_vals_u.modv_strvals);
            Assert.Equal(IntPtr.Zero,ptr3);
            
            Marshal.FreeHGlobal(actual);
            Marshal.FreeHGlobal(valPtr);
        }


        [Theory]
        [InlineData(new byte[] { 1, 2, 3, 4 },  new byte[] { 1, 2, 3, 4 , 5 })]
        public void MarshalUtils_BerValArrayToByteArray_Returns_List_Of_ByteArray(params byte[][] sourceData)
        {
            var sourceDataPtrs = sourceData.Select(_ => Marshal.AllocCoTaskMem(_.Length + 1)).ToArray();
            for (var i = 0; i < sourceData.Length; i++)
            {
                Marshal.Copy(sourceData[i].Union(new byte[]{0}).ToArray(),0,sourceDataPtrs[i], sourceData[i].Length + 1);
            }

            var ptr = Marshal.AllocCoTaskMem((sourceData.Length + 1) * IntPtr.Size);
            for (var i = 0; i < sourceDataPtrs.Length; i++)
            {
                var berPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.berval>());
                Marshal.StructureToPtr(new Native.berval
                {
                    bv_val = sourceDataPtrs[i],
                    bv_len = sourceData[i].Length
                }, berPtr, true);
                Marshal.StructureToPtr(berPtr, new IntPtr(ptr.ToInt64() + i*IntPtr.Size), true);
            }
            Marshal.StructureToPtr(IntPtr.Zero, new IntPtr(ptr.ToInt64() + sourceDataPtrs.Length * IntPtr.Size), true);

            var actual = MarshalUtils.BerValArrayToByteArrays(ptr);

            Assert.Equal(sourceData.Length, actual.Count);
            Assert.Equal(sourceData, actual);

            for (var i = 0; i < sourceDataPtrs.Length; i++)
            {
                var sourceDataPtr = sourceDataPtrs[i];
                var tempPtr = Marshal.ReadIntPtr(ptr, i * IntPtr.Size);
                Marshal.FreeHGlobal(tempPtr);
                Marshal.FreeCoTaskMem(sourceDataPtr);
            }

            Marshal.FreeCoTaskMem(ptr);
        }

        [Theory]
        [InlineData(new byte[] { 1, 2, 3, 4 }, new byte[] { 1, 2, 3, 4, 5 })]
        public void MarshalUtils_ByteArraysToBerValueArray_Returns_Ptr_To_BerValueArrays(params byte[][] sourceData)
        {
            var ptr = Marshal.AllocCoTaskMem((sourceData.Length + 1) * IntPtr.Size);
            MarshalUtils.ByteArraysToBerValueArray(sourceData, ptr);
            var actual = MarshalUtils.BerValArrayToByteArrays(ptr);
            Assert.Equal(sourceData, actual);
            Marshal.FreeCoTaskMem(ptr);
        }

    }
    
    public struct Point
    {
        public int X;
        public int Y;
    }

}