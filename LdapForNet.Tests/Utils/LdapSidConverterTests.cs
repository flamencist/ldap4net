using LdapForNet.Utils;
using Xunit;

namespace LdapForNetTests.Utils
{
    public class LdapSidConverterTests
    {
        [Fact]
        public void LdapSidConverter_ConvertToHex_Return_String_In_Hex_Format()
        {
            var actual = LdapSidConverter.ConvertToHex("S-1-5-21-2127521184-1604012920-1887927527-72713");
            Assert.Equal("010500000000000515000000A065CF7E784B9B5FE77C8770091C0100", actual);
        }
    }
}