using LdapForNet.Utils;
using Xunit;

namespace LdapForNetTests.Utils
{
    public class HexEscaperTests
    {
        [Fact]
        public void HexEscaper_Escape_Should_Return_Hex_Chars_With_Back_Slash_Char()
        {
            var actual = HexEscaper.Escape("01052ABC");
            Assert.Equal(@"\01\05\2A\BC",actual);
        }
    }
}