using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using LdapForNet;
using LdapForNet.Native;

namespace LdapExample.Net
{
    internal class Program
    {
        public static async Task Main(string[] args)
        {
            var auth = Native.LdapAuthMechanism.SIMPLE;
            var host = "ldap.forumsys.com";
            var @base = "dc=example,dc=com";
            var filter = "(objectclass=*)";
            var port = 389;

            using (var cn = new LdapConnection())
            {
                cn.Connect(host, port);
                
                var who = "cn=read-only-admin,dc=example,dc=com";
                var password = "password";
                cn.Bind(Native.LdapAuthMechanism.SIMPLE,who,password);

                IList<LdapEntry> entries;

               
                entries = await cn.SearchAsync(@base, filter);
                foreach (var ldapEntry in entries)
                {
                    PrintEntry(ldapEntry);
                }
            }
        }
        
        private static void PrintEntry(LdapEntry entry)
        {
            Console.WriteLine($"dn: {entry.Dn}");
            foreach (var pair in entry.Attributes.SelectMany(_ => _.Value.Select(x => new KeyValuePair<string, string>(_.Key, x))))
            {
                Console.WriteLine($"{pair.Key}: {pair.Value}");
            }
            Console.WriteLine();
        }
    }
}