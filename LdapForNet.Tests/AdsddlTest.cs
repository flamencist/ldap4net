using System.IO;
using LdapForNet.Adsddl;
using LdapForNet.Adsddl.data;
using Xunit;

namespace LdapForNetTests
{
    public class AdsddlTest
    {
        [Fact]
        public void LdapConnection_GetNtSecurityDescriptor()
        {
            Sddl sddl = new Sddl(File.ReadAllBytes(Config.GetLocation("AdsddlTest.bin")));

            // sddl test
            byte revision = sddl.GetRevision();
            Assert.Equal(0x01, revision);

            byte[] flags = sddl.GetControlFlags();
            Assert.Equal(new byte[] { 0x84, 0x14 }, flags);

            int sddlSize = sddl.GetSize();
            Assert.Equal(2688, sddlSize);

            SID group = sddl.GetGroup();
            Assert.Equal("S-1-5-32-544", group.ToString());

            SID owner = sddl.GetOwner();
            Assert.Equal("S-1-5-32-544", owner.ToString());

            // dacl test
            Acl dacl = sddl.GetDacl();
            Assert.Equal("P(D;;Dc;;;S-1-1-0)(OA;CIIO;Rp;4c164200-20c0-11d0-a768-00aa006e0529;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIO;Rp;4c164200-20c0-11d0-a768-00aa006e0529;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIO;Rp;5f202010-79a5-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIO;Rp;5f202010-79a5-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIO;Rp;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIO;Rp;bc0ac240-79a9-11d0-9020-00c04fc2d4cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIO;Rp;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIO;Rp;59ba2f42-79a2-11d0-9020-00c04fc2d3cf;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIO;Rp;037088f8-0ae1-11d2-b422-00a0c968f939;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIO;Rp;037088f8-0ae1-11d2-b422-00a0c968f939;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;;Cr;3e0f7e18-2c7a-4c10-ba82-4d926db99a3e;;S-1-5-21-3915767550-1135939244-3079240635-522)(OA;;Cr;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-3915767550-1135939244-3079240635-498)(OA;;Cr;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-21-3915767550-1135939244-3079240635-516)(OA;CI;RpWp;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3915767550-1135939244-3079240635-526)(OA;CI;RpWp;5b47d60f-6090-40b2-9f37-2a4de88f3063;;S-1-5-21-3915767550-1135939244-3079240635-527)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-3-0)(OA;CIIO;SW;9b026da6-0d3c-465c-8bee-5199d7165cba;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;CIIO;Rp;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIO;Rp;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIO;Rp;b7c69e6d-2cc7-11d2-854e-00a0c983f608;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-9)(OA;CIIO;Wp;ea1b7b93-5e48-46d5-bc6c-4df4fda78a35;bf967a86-0de6-11d0-a285-00aa003049e2;S-1-5-10)(OA;;Cr;89e95b76-444d-4c62-991a-0facbeda640c;;S-1-5-32-544)(OA;;Cr;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-32-544)(OA;;Cr;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-32-544)(OA;;Cr;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-32-544)(OA;;Cr;1131f6ad-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-32-544)(OA;;Cr;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-32-544)(OA;;Cr;e2a36dc9-ae17-47c3-b58b-be34c55ba633;;S-1-5-32-557)(OA;;Rp;c7407360-20bf-11d0-a768-00aa006e0529;;S-1-5-32-554)(OA;;Rp;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;S-1-5-32-554)(OA;CIIO;LcRpLoRc;;4828cc14-1437-45bc-9b07-ad6f015e5f28;S-1-5-32-554)(OA;CIIO;LcRpLoRc;;bf967a9c-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;CIIO;LcRpLoRc;;bf967aba-0de6-11d0-a285-00aa003049e2;S-1-5-32-554)(OA;;Cr;05c74c5e-4deb-43b4-bd9f-86664c2a7fd5;;S-1-5-11)(OA;;Cr;89e95b76-444d-4c62-991a-0facbeda640c;;S-1-5-9)(OA;;Cr;ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501;;S-1-5-11)(OA;;Cr;280f369c-67c7-438e-ae98-1d46f3c6f541;;S-1-5-11)(OA;;Cr;1131f6aa-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-9)(OA;;Cr;1131f6ab-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-9)(OA;;Cr;1131f6ac-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-9)(OA;;Cr;1131f6ae-9c07-11d1-f79f-00c04fc2dcd2;;S-1-5-9)(OA;;Rp;b8119fd0-04f6-4762-ab7a-4986c76b3f9a;;S-1-5-11)(OA;OICI;RpWp;3f78c3e5-f79a-46bd-a0b8-9d18116ddc79;;S-1-5-10)(OA;CIIO;RpWpCr;91e647de-d96f-4b70-9557-d63ff4f3ccd8;;S-1-5-10)(A;;CcLcSWRpWpLoCrRcWdWo;;;S-1-5-21-3915767550-1135939244-3079240635-512)(A;CI;CcDcLcSWRpWpDtLoCrSdRcWdWo;;;S-1-5-21-3915767550-1135939244-3079240635-519)(A;;RpRc;;;S-1-5-32-554)(A;CI;Lc;;;S-1-5-32-554)(A;CI;CcLcSWRpWpLoCrSdRcWdWo;;;S-1-5-32-544)(A;;Rp;;;S-1-1-0)(A;;LcRpLoRc;;;S-1-5-9)(A;;LcRpLoRc;;;S-1-5-11)(A;;CcDcLcSWRpWpDtLoCrSdRcWdWo;;;S-1-5-18)", dacl.ToString());

            AclRevision daclRevision = dacl.GetRevision();
            Assert.Equal(AclRevision.AclRevisionDs, daclRevision);

            int acesCount = dacl.GetAceCount();
            Assert.Equal(54, acesCount);

            int daclSize = dacl.GetSize();
            Assert.Equal(2436, daclSize);

            // sacl test
            Acl sacl = sddl.GetSacl();
            Assert.Equal("P(OU;CISA;Wp;;;S-1-3191541491-0)(OU;CISA;Wp;;;S-1-3208318707-0)(AU;SA;Cr;;;S-1-5-21-3915767550-1135939244-3079240635-513)(AU;SA;Cr;;;S-1-5-32-544)(AU;SA;WpWdWo;;;S-1-1-0)", sacl.ToString());

            AclRevision saclRevision = sacl.GetRevision();
            Assert.Equal(AclRevision.AclRevisionDs, saclRevision);

            int saclAcesCount = sacl.GetAceCount();
            Assert.Equal(5, saclAcesCount);

            int saclSize = sacl.GetSize();
            Assert.Equal(200, saclSize);
        }
    }
}