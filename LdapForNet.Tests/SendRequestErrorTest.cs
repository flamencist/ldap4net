using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using LdapForNet;
using LdapForNet.Native;
using Xunit;
using Xunit.Abstractions;
using static LdapForNet.Native.Native;

namespace LdapForNetTests
{
    public class SendRequestErrorTest
    {        
        private readonly ITestOutputHelper _testOutputHelper;
        /// <summary>
        /// https://github.com/delphij/openldap/blob/master/clients/tools/ldapwhoami.c
        /// </summary>
        /// <returns></returns>
        

        private static List<string> GetAttributeValue(Dictionary<string, List<string>> attributes, string name)
        {
            if (!attributes.TryGetValue(name, out var result))
            {
                if (!attributes.TryGetValue(name.ToLower(), out result))
                {
                    throw new KeyNotFoundException(name);
                }
            }

            return result;
        }
    }
}