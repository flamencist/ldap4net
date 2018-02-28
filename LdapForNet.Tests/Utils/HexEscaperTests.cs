using LdapForNet.Utils;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace LdapForNetTests.Utils
{
    [TestClass]
    public class HexEscaperTests
    {
        [TestMethod]
        public void HexEscaper_Escape_Should_Return_Hex_Chars_With_Back_Slash_Char()
        {
            var actual = HexEscaper.Escape("01052ABC");
            Assert.AreEqual(@"\01\05\2A\BC",actual);
        }
    }
}