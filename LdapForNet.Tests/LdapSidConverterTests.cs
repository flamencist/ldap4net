using LdapForNet;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LdapForNetTests
{
    [TestClass]
    public class LdapSidConverterTests
    {
        [TestMethod]
        public void LdapSidConverter_ConvertToHex_Return_String_In_Hex_Format()
        {
            var coverter = new LdapSidConverter();
            var actual = LdapSidConverter.ConvertToHex("S-1-5-21-2127521184-1604012920-1887927527-72713");
            Assert.AreEqual("010500000000000515000000A065CF7E784B9B5FE77C8770091C0100", actual);
        }
    }
}