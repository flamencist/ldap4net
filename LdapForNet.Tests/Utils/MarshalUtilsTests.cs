using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet;
using LdapForNet.Native;
using LdapForNet.Utils;
using Xunit;

namespace LdapForNetTests.Utils
{
    public class MarshalUtilsTests
    {
        [Theory]
        [InlineData("test","test2")]
        [InlineData("раз", "два", "три")]
        [InlineData("fünf", "zwölf")]
        [InlineData("數字", "四")]
        public void MarshalUtils_PtrToStringArray_Returns_List_Of_String(params string[] data)
        {
            var dataPointers = data.Select(Encoder.Instance.StringToPtr).Union(new []{IntPtr.Zero, }).ToArray();
            var ptr = Marshal.AllocCoTaskMem(dataPointers.Length*IntPtr.Size);

            for (var i = 0; i < dataPointers.Length; i++)
            {
                Marshal.WriteIntPtr(ptr, IntPtr.Size * i, dataPointers[i]);
            }

            var actual = MarshalUtils.PtrToStringArray(ptr);

            foreach (var dataPtr in dataPointers)
            {
                Marshal.FreeHGlobal(dataPtr);
            }
            Marshal.FreeCoTaskMem(ptr);

            Assert.Equal(data, actual);
        }

        [Theory]
        [InlineData("test","other","third")]
        [InlineData("раз", "два", "три")]
        [InlineData("fünf", "zwölf")]
        [InlineData("數字", "四")]
        public void MarshalUtils_StringArrayToPtr_Returns_Ptr_To_StringArray(params string[] data)
        {
            var actual = Marshal.AllocHGlobal(IntPtr.Size*(data.Length+1));
            MarshalUtils.StringArrayToPtr(data, actual);
            Marshal.WriteIntPtr(actual, IntPtr.Size * (data.Length),IntPtr.Zero);

            var actualData = MarshalUtils.GetPointerArray(actual)
                .Select(Encoder.Instance.PtrToString)
                .ToList();

            Marshal.FreeHGlobal(actual);

            Assert.Equal(data, actualData);
            
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

        public static IEnumerable<object[]> LdapModifyAttributeData =>
            new List<object[]>
            {
                new object[] { new LdapModifyAttribute
                    {
                        LdapModOperation = Native.LdapModOperation.LDAP_MOD_ADD,
                        Type = "test",
                        Values = new List<string> { "test", "other", "third" }
                    } ,
                    new LdapModifyAttribute
                    {
                        LdapModOperation = Native.LdapModOperation.LDAP_MOD_ADD,
                        Type = "test2",
                        Values = new List<string> ()
                    }},
                new object[] { new LdapModifyAttribute
                    {
                        LdapModOperation = Native.LdapModOperation.LDAP_MOD_ADD,
                        Type = "rus",
                        Values = new List<string> { "раз", "два", "три" }
                    } ,
                    new LdapModifyAttribute
                    {
                        LdapModOperation = Native.LdapModOperation.LDAP_MOD_ADD,
                        Type = "de",
                        Values = new List<string> { "fünf", "zwölf" }
                    },
                    new LdapModifyAttribute
                    {
                        LdapModOperation = Native.LdapModOperation.LDAP_MOD_ADD,
                        Type = "ch",
                        Values = new List<string> { "數字", "四" }
                    }
                }
            };

        [Theory]
        [MemberData(nameof(LdapModifyAttributeData))]
        public void MarshalUtils_StructureArrayToPtr_LDAPMod(params LdapModifyAttribute[] attributes)
        {
            var data = attributes
                .Select(_ =>
                {
                    var values = _.Values.Union(new string[] {null}).ToArray();
                    var ptr =  Marshal.AllocHGlobal(IntPtr.Size * values.Length);
                    MarshalUtils.StringArrayToPtr(values, ptr);
                    return new Native.LDAPMod
                    {
                        mod_op = (int) _.LdapModOperation,
                        mod_type = Encoder.Instance.StringToPtr(_.Type),
                        mod_vals_u = new Native.LDAPMod.mod_vals
                        {
                            modv_strvals = ptr
                        }
                    };
                })
                .ToArray();

            var actual = Marshal.AllocHGlobal(IntPtr.Size*(data.Length+1));

            MarshalUtils.StructureArrayToPtr(data,actual, true);

            var actualData = new List<LdapModifyAttribute>();
            var count = 0;
            var tempPtr = Marshal.ReadIntPtr(actual);
            while (tempPtr != IntPtr.Zero)
            {
                var mod = Marshal.PtrToStructure<Native.LDAPMod>(tempPtr);
                var length = 0;
                var values = new List<string>();
                var ptr = Marshal.ReadIntPtr(mod.mod_vals_u.modv_strvals, IntPtr.Size*length);
                while (ptr != IntPtr.Zero)
                {
                    values.Add(Encoder.Instance.PtrToString(ptr));
                    length++;
                    ptr = Marshal.ReadIntPtr(mod.mod_vals_u.modv_strvals, IntPtr.Size * length);
                }
                actualData.Add(new LdapModifyAttribute
                {
                    Type = Encoder.Instance.PtrToString(mod.mod_type),
                    LdapModOperation = (Native.LdapModOperation)mod.mod_op,
                    Values = values
                });
                count++;
                tempPtr = Marshal.ReadIntPtr(actual, IntPtr.Size * count);
            }
            foreach (var ldapMod in data)
            {
                Marshal.FreeHGlobal(ldapMod.mod_vals_u.modv_strvals);
                Marshal.FreeHGlobal(ldapMod.mod_type);
            }
            Marshal.FreeHGlobal(actual);

            Assert.NotEmpty(actualData);
            Assert.Equal(attributes,actualData,new LambdaEqualityComparer<LdapModifyAttribute>((e, a) => e.LdapModOperation == a.LdapModOperation && e.Type == a.Type &&
                                                                                                         e.Values.SequenceEqual(a.Values)));
        }


        [Theory]
        [InlineData(new byte[] { 1, 2, 3, 4 },  new byte[] { 1, 2, 3, 4 , 5 })]
        public void MarshalUtils_BerValArrayToByteArray_Returns_List_Of_ByteArray(params byte[][] sourceData)
        {
            var sourceDataPointers = sourceData.Select(_ => Marshal.AllocCoTaskMem(_.Length + 1)).ToArray();
            for (var i = 0; i < sourceData.Length; i++)
            {
                Marshal.Copy(sourceData[i].Union(new byte[]{0}).ToArray(),0,sourceDataPointers[i], sourceData[i].Length + 1);
            }

            var ptr = Marshal.AllocCoTaskMem((sourceData.Length + 1) * IntPtr.Size);
            for (var i = 0; i < sourceDataPointers.Length; i++)
            {
                var berPtr = Marshal.AllocHGlobal(Marshal.SizeOf<Native.berval>());
                Marshal.StructureToPtr(new Native.berval
                {
                    bv_val = sourceDataPointers[i],
                    bv_len = sourceData[i].Length
                }, berPtr, true);
                Marshal.WriteIntPtr(ptr,i*IntPtr.Size,berPtr);
            }
            Marshal.WriteIntPtr(ptr, sourceDataPointers.Length * IntPtr.Size, IntPtr.Zero);

            var actual = MarshalUtils.BerValArrayToByteArrays(ptr);

            for (var i = 0; i < sourceDataPointers.Length; i++)
            {
                var sourceDataPtr = sourceDataPointers[i];
                var tempPtr = Marshal.ReadIntPtr(ptr, i * IntPtr.Size);
                Marshal.FreeHGlobal(tempPtr);
                Marshal.FreeCoTaskMem(sourceDataPtr);
            }

            Marshal.FreeCoTaskMem(ptr);

            Assert.Equal(sourceData.Length, actual.Count);
            Assert.Equal(sourceData, actual);
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
    
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    public struct Point
    {
        public int X;
        public int Y;
    }
}