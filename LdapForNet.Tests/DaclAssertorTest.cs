using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using LdapForNet.Adsddl;
using LdapForNet.Adsddl.dacl;
using Xunit;

namespace LdapForNetTests
{
    public class DaclAssertorTest
    {
        private readonly Sddl sdd = new Sddl(File.ReadAllBytes(Config.GetLocation("sddlSampleForAssertor.bin")));
        private readonly Sddl sddlDenials = new Sddl(File.ReadAllBytes(Config.GetLocation("sddlSampleForAssertor2.bin")));
        private readonly SID userSID = SID.Parse(GetSidAsByteBuffer("S-1-5-21-1835709989-2027683138-697581538-1139"));

        private readonly List<string> groupSIDList = new List<string>
        {
            "S-1-5-21-1835709989-2027683138-697581538-1440",
            "S-1-5-21-1835709989-2027683138-697581538-1107",
            "S-1-5-21-1835709989-2027683138-697581538-513"
        };

        private static byte[] GetSidAsByteBuffer(string strSID)
        {
            using (MemoryStream ms = new MemoryStream(256))
            {
                var bb = new BinaryWriter(ms);

                if (strSID != null)
                {
                    var comp = strSID.Split("-");
                    int count = comp.Length;

                    if (count > 3)
                    {
                        var version = byte.Parse(comp[1]);
                        bb.Write(version);

                        bb.Write((byte) ((count - 3) & 0xFF));

                        var authority = long.Parse(comp[2]);
                        bb.Write(GetLongAsByteBuffer(authority, true, 6));

                        for (var i = 3; i < count; i++)
                        {
                            var val = long.Parse(comp[i]);
                            bb.Write(GetLongAsByteBuffer(val, false, 4));
                        }
                    }
                }

                return ms.ToArray();
            }
        }

        /// <summary>
        ///     Convert a long to ByteBuffer, in little/big endian byte order, keeping byteCount bytes only
        /// </summary>
        /// <param name="val">Long value</param>
        /// <param name="isBigEndian">Is big endina</param>
        /// <param name="byteCount">Count of bytes</param>
        /// <returns></returns>
        private static byte[] GetLongAsByteBuffer(long val, bool isBigEndian, int byteCount)
        {
            var data = new byte[byteCount];
            var bytes = BitConverter.GetBytes(val);
            for (int i = 0; i < data.Length; i++)
            {
                if (isBigEndian)
                {
                    data[data.Length - 1 - i] = bytes[i];
                }
                else
                {
                    data[i] = bytes[i];   
                }
            }
            return data;
        }

        [Fact]
        public void TestDomainJoinRoleNegative()
        {
            // This should test negatively because the userSID is only granted one of the permissions (create computer)
            // and this test tells the assertor to NOT search groups.
            Acl dacl = this.sdd.GetDacl();
            DaclAssertor assertor = new DaclAssertor(dacl, false);

            DomainJoinRoleAssertion djAssertion = new DomainJoinRoleAssertion(this.userSID, false, null);
            bool result = assertor.DoAssert(djAssertion);
            Assert.False(result);

            // should be 6 of them
            List<AceAssertion> unsatisfiedAssertions = assertor.GetUnsatisfiedAssertions();
            Assert.Equal(6, unsatisfiedAssertions.Count);
        }

        [Fact]
        public void TestDomainJoinRolePositive()
        {
            // This should test positively because while the userSID is only granted one of the permissions (create computer),
            // the group SID ending with "-1440" has all of them, and the assertor will search groups.
            Acl dacl = this.sdd.GetDacl();
            DaclAssertor assertor = new DaclAssertor(dacl, true);

            List<SID> groupSiDs = this.groupSIDList.Select(s => SID.Parse(GetSidAsByteBuffer(s))).ToList();
            DomainJoinRoleAssertion djAssertion = new DomainJoinRoleAssertion(this.userSID, false, groupSiDs);
            bool result = assertor.DoAssert(djAssertion);
            Assert.True(result);
        }

        [Fact]
        public void testDomainJoinRoleNegative_Denials()
        {
            // This should test negatively because the userSID is denied one of the permissions (create computer),
            // within the OU the Sddl was pulled from (not inherited).
            Acl dacl = this.sddlDenials.GetDacl();
            DaclAssertor assertor = new DaclAssertor(dacl, true);

            List<SID> groupSiDs = this.groupSIDList.Select(s => SID.Parse(GetSidAsByteBuffer(s))).ToList();
            DomainJoinRoleAssertion djAssertion = new DomainJoinRoleAssertion(this.userSID, false, groupSiDs);
            bool result = assertor.DoAssert(djAssertion);
            Assert.False(result);

            // should be 1 of them
            Assert.Single(assertor.GetUnsatisfiedAssertions());
        }
    }
}