using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using LdapForNet;
using Xunit;
using Xunit.Abstractions;

namespace LdapForNetTests
{
    public class BerConverterTests
    {
        public BerConverterTests(ITestOutputHelper testOutputHelper)
        {
            _testOutputHelper = testOutputHelper;
        }

        private readonly ITestOutputHelper _testOutputHelper;

        public static IEnumerable<object[]> Encode_TestData()
        {
            yield return new object[] {"", null, new byte[0]};
            yield return new object[] {"", new object[10], new byte[0]};
            yield return new object[] {"b", new object[] {true, false, true, false}, new byte[] {1, 1, 255}};

            //yield return new object[] {"{", new object[] {"a"}, new byte[] {48, 0, 0, 0, 0, 0}};
            //yield return new object[] {"{}", new object[] {"a"}, new byte[] {48, 132, 0, 0, 0, 0}};
            //yield return new object[] {"[", new object[] {"a"}, new byte[] {49, 0, 0, 0, 0, 0}};
            //yield return new object[] {"[]", new object[] {"a"}, new byte[] {49, 132, 0, 0, 0, 0}};
            yield return new object[] {"n", new object[] {"a"}, new byte[] {5, 0}};

            /*yield return new object[]
                {"tetie", new object[] {-1, 0, 1, 2, 3}, new byte[] {255, 1, 0, 1, 1, 2, 10, 1, 3}};*/
            /*yield return new object[]
            {
                "{tetie}", new object[] {-1, 0, 1, 2, 3}, new byte[] {48, 132, 0, 0, 0, 9, 255, 1, 0, 1, 1, 2, 10, 1, 3}
            };
            */

            yield return new object[] {"bb", new object[] {true, false}, new byte[] {1, 1, 255, 1, 1, 0}};
            /*yield return new object[]
                {"{bb}", new object[] {true, false}, new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0}};
                */

            yield return new object[]
                {"ssss", new object[] {null, "", "abc", "\0"}, new byte[] {4, 0, 4, 0, 4, 3, 97, 98, 99, 4, 1, 0}};
            /*yield return new object[]
            {
                "oXo", new object[] {null, new byte[] {0, 1, 1, 0}, new byte[0]},
                new byte[] {4, 0, 3, 4, 0, 1, 1, 0, 4, 0}
            };*/
            /*yield return new object[]
            {
                "{XX}", new object[] {new byte[] {1, 0, 0, 0}, new byte[] {0, 0, 0, 1}},
                new byte[] {48, 132, 0, 0, 0, 12, 3, 4, 1, 0, 0, 0, 3, 4, 0, 0, 0, 1}
            };*/
            yield return new object[]
                {"vv", new object[] {null, new[] {"abc", "", null}}, new byte[] {4, 3, 97, 98, 99, 4, 0, 4, 0}};
            /*yield return new object[]
            {
                "{vv}", new object[] {null, new[] {"abc", "", null}},
                new byte[] {48, 132, 0, 0, 0, 9, 4, 3, 97, 98, 99, 4, 0, 4, 0}
            };*/
            yield return new object[]
            {
                "VVVV", new object[] {null, new[] {new byte[] {0, 1, 2, 3}, null}, new[] {new byte[0]}, new byte[0][]},
                new byte[] {4, 4, 0, 1, 2, 3, 4, 0, 4, 0}
            };
            /*yield return new object[]
            {
                "{VV}", new object[] {new[] {new byte[] {1, 2, 3, 4}}, new[] {new byte[] {5, 6, 7, 8}}},
                new byte[] {48, 132, 0, 0, 0, 12, 4, 4, 1, 2, 3, 4, 4, 4, 5, 6, 7, 8}
            };*/
        }

        [Theory]
        [MemberData(nameof(Encode_TestData))]
        public void Encode_Objects_ReturnsExpected(string format, object[] values, byte[] expected)
        {
            var actual = BerConverter.Encode(format, values);
            _testOutputHelper.WriteLine($"expected: [{string.Join(',', expected)}]");
            _testOutputHelper.WriteLine($"actual: [{string.Join(',', actual)}]");
            Assert.Equal(expected, actual);
        }

        public static IEnumerable<object[]> Encode_Invalid_TestData()
        {
            yield return new object[] {"t", new object[0]};
            yield return new object[] {"t", new object[] {"string"}};
            yield return new object[] {"t", new object[] {null}};

            yield return new object[] {"i", new object[0]};
            yield return new object[] {"i", new object[] {"string"}};
            yield return new object[] {"i", new object[] {null}};

            yield return new object[] {"e", new object[0]};
            yield return new object[] {"e", new object[] {"string"}};
            yield return new object[] {"e", new object[] {null}};

            yield return new object[] {"b", new object[0]};
            yield return new object[] {"b", new object[0]};
            yield return new object[] {"b", new object[] {"string"}};
            yield return new object[] {"b", new object[] {null}};

            yield return new object[] {"s", new object[0]};
            yield return new object[] {"s", new object[] {123}};

            yield return new object[] {"o", new object[0]};
            yield return new object[] {"o", new object[] {"string"}};
            yield return new object[] {"o", new object[] {123}};

            yield return new object[] {"X", new object[0]};
            yield return new object[] {"X", new object[] {"string"}};
            yield return new object[] {"X", new object[] {123}};

            yield return new object[] {"v", new object[0]};
            yield return new object[] {"v", new object[] {"string"}};
            yield return new object[] {"v", new object[] {123}};

            yield return new object[] {"V", new object[0]};
            yield return new object[] {"V", new object[] {"string"}};
            yield return new object[] {"V", new object[] {new byte[0]}};

            yield return new object[] {"a", new object[0]};
        }

        [Theory]
        [MemberData(nameof(Encode_Invalid_TestData))]
        public void Encode_Invalid_ThrowsArgumentException(string format, object[] values)
        {
            Assert.Throws<ArgumentException>(null, () => BerConverter.Encode(format, values));
        }

        [Theory]
        [InlineData("]")]
        [InlineData("}")]
        [InlineData("{{}}}")]
        public void Encode_InvalidFormat_ThrowsBerConversionException(string format)
        {
            Assert.Throws<LdapException>(() => BerConverter.Encode(format));
        }

        public static IEnumerable<object[]> Decode_TestData()
        {
            yield return new object[] {"{}", new byte[] {48, 0, 0, 0, 0, 0}, new object[0]};
            yield return new object[] {"{a}", new byte[] {48, 132, 0, 0, 0, 5, 4, 3, 97, 98, 99}, new object[] {"abc"}};
            yield return new object[]
                {"{ie}", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0}, new object[] {-1, 0}};
            yield return new object[]
                {"{bb}", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0}, new object[] {true, false}};
            yield return new object[]
            {
                "{OO}", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0},
                new object[] {new byte[] {255}, new byte[] {0}}
            };
            yield return new object[]
            {
                "{BB}", new byte[] {48,8,3,2,2,42,3,2,0,85},
                new object[] {new byte[] {0, 1, 0, 1, 0, 1}, new byte[] {1, 0, 1, 0, 1, 0, 1, 0}}
            };
            /*yield return new object[]
                {
                    "{BB}", new byte[] {48,132,0,0,0,18,3,6,42,0,37,0,112,0,3,8,85,0,10,10,10,0,0,0},
                    new object[] {new byte[] {0, 1, 0, 1, 0, 1}, new byte[] {1, 0, 1, 0, 1, 0, 1, 0}}
                };*/
            yield return new object[]
            {
                "{BB}", new byte[] {48,10,3,3,7,1,1,3,3,7,15,1},
                new object[] {new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 1}, new byte[] {1, 1, 1, 1, 0, 0, 0, 0, 1}}
            };
            yield return new object[]
                {"{vv}", new byte[] {48, 132, 0, 0, 0, 9, 4, 3, 97, 98, 99, 4, 0, 4, 0}, new object[] {null, null}};
            /*yield return new object[]
                {"{vv}", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0}, new object[] {new[] {"\x01"}, null}};*/
            /*yield return new object[]
                {"{VV}", new byte[] {48, 132, 0, 0, 0, 9, 4, 3, 97, 98, 99, 4, 0, 4, 0}, new object[] {null, null}};*/
            yield return new object[]
            {
                "{VV}", new byte[] {48,16,48,6,4,4,1,2,3,4,48,6,4,4,5,6,7,8},
                new object[] {new[] {new byte[] {1, 2, 3, 4}}, new[] {new byte[] {5, 6, 7, 8}}}
            };
        }

        [Theory]
        [MemberData(nameof(Decode_TestData))]
        public void Decode_Bytes_ReturnsExpected(string format, byte[] values, object[] expected)
        {
            var value = BerConverter.Decode(format, values);
            _testOutputHelper.WriteLine($"expected: [{string.Join(',', expected)}]");
            _testOutputHelper.WriteLine($"actual: [{string.Join(',', value)}]");
            Assert.Equal(expected, value);
        }

        [Theory]
        [InlineData("p", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0})]
        public void UnknownFormat_ThrowsArgumentException(string format, byte[] values)
        {
            Assert.Throws<ArgumentException>(null, () => BerConverter.Decode(format, values));
        }

        [Theory]
        [InlineData("{", new byte[] {1})]
        //[InlineData("}", new byte[] {1})]
        [InlineData("{}{}{}{}{}{}{}", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0})]
        //[InlineData("aaa", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0})]
        [InlineData("iii", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0})]
        [InlineData("eee", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0})]
        [InlineData("bbb", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0})]
        [InlineData("OOO", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0})]
        [InlineData("BBB", new byte[] {48, 132, 0, 0, 0, 6, 1, 1, 255, 1, 1, 0})]
        public void Decode_Invalid_ThrowsBerConversionException(string format, byte[] values)
        {
            Assert.Throws<LdapException>(() => BerConverter.Decode(format, values));
        }

        public static IEnumerable<object[]> Encode_Decode_TestData()
        {
            yield return new object[] {"{bb}", "{bb}", new object[] {true, false}};
            yield return new object[] {"{ee}", "{ee}", new object[] {2, 3}};
            yield return new object[] {"{ii}", "{ii}", new object[] {2, 3}};
            yield return new object[]
                {"{BB}", "{BB}", new object[] {new byte[] {0, 1, 0, 1, 0, 1}, new byte[] {1, 0, 1, 0, 1, 0, 1, 0}}};
            yield return new object[]
            {
                "{XX}", "{BB}",
                new object[] {new byte[] {1, 0, 0, 0, 0, 0, 0, 0, 1}, new byte[] {1, 1, 1, 1, 0, 0, 0, 0, 1}}
            };
            yield return new object[] {"{n}", "{n}", new object[0]};
            yield return new object[] {"{OO}", "{OO}", new object[] {new byte[] {3}, new byte[] {4}}};
            yield return new object[] {"{OO}", "{oo}", new object[] {new byte[] {3}, new byte[] {4}}};
            yield return new object[] {"{oo}", "{OO}", new object[] {new byte[] {3}, new byte[] {4}}};
            yield return new object[] {"{oo}", "{oo}", new object[] {new byte[] {3}, new byte[] {4}}};
            yield return new object[] {"{OO}", "{OO}", new object[] {new byte[] {3}, new byte[] {4}}};
            yield return new object[] {"{OO}", "{mm}", new object[] {new byte[] {3}, new byte[] {4}}};
            yield return new object[] {"{ss}", "{ss}", new object[] {"abc", "dfe"}};
            yield return new object[] {"{ss}", "{aa}", new object[] {"abc", "dfe"}};
            yield return new object[] {"{ss}", "{AA}", new object[] {"abc", "dfe"}};
            yield return new object[] {"{{v}{v}}", "{vv}", new object[] {new[] {"82DA", "82AB"}, new[] {"81AD"}}};
            yield return new object[]
            {
                "{{V}{V}}", "{VV}", new object[] {new[] {new byte[] {1, 2, 3, 4}}, new[] {new byte[] {5, 6, 7, 8}}}
            };
            yield return new object[]
            {
                "{W}{W}", "{W}{W}", new object[] {new[] {new byte[] {1, 2, 3, 4}}, new[] {new byte[] {5, 6, 7, 8}}},
                new[] {OSPlatform.Linux.ToString(), OSPlatform.OSX.ToString()}
            };
            yield return new object[]{"{iit{ii}}", "{iit{ii}}", new object[] { 0, 1, 4, 129, 1},};
            yield return new object[]
            {
                "ii", "iT", new object[] { 2, 2}, 
                new[] {OSPlatform.Linux.ToString(), OSPlatform.OSX.ToString()}
            };
            yield return new object[]
            {
                "ii", "li", new object[] { 1, 1},
                new[] {OSPlatform.Linux.ToString(), OSPlatform.OSX.ToString()}
            };
            yield return new object[]
            {
                "{iit{ii}}", "{iit{ilx}}", new object[] { 0, 1, 4, 129, 1},
                new[] {OSPlatform.Linux.ToString(), OSPlatform.OSX.ToString()}
            };
        }

        [Theory]
        [MemberData(nameof(Encode_Decode_TestData))]
        public void Encode_Decode_Should_Returns_Expected(string printFormat, string scanFormat, object[] values,
            string[] platforms = null)
        {
            if (platforms != null && !platforms.Any(_ => RuntimeInformation.IsOSPlatform(OSPlatform.Create(_)))) return;
            var encoded = BerConverter.Encode(printFormat, values);
            _testOutputHelper.WriteLine($"encoded: [{string.Join(',', encoded)}]");
            var decoded = BerConverter.Decode(scanFormat, encoded);
            Assert.Equal(values, decoded);
        }

        [Fact]
        public void Decode_NullFormat_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>("format", () => BerConverter.Decode(null, new byte[0]));
        }

        [Fact]
        public void Encode_NullFormat_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>("format", () => BerConverter.Encode(null));
        }
    }
}