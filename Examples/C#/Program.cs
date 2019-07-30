using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using LdapForNet;
using static LdapForNet.Native.Native;

namespace LdapExample
{
    class Program
    {
        /// <summary>
        /// LdapSearch
        /// </summary>
        /// <example>
        ///  LdapExample --auth=GSSAPI --host=v04.example.com --base="dc=v04,dc=example,dc=com" --filter="(objectclass=*)" --port=389
        /// </example>
        ///  <example>
        ///  LdapExample --auth=Simple --host=ldap.forumsys.com --base="dc=example,dc=com" --filter="(objectclass=*)" --who="cn=read-only-admin,dc=example,dc=com" --password=password --port=389
        /// </example>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            var cmds = ParseCommandLine(args);
            cmds.TryGetValue("host", out var host);
            cmds.TryGetValue("auth", out var authString);
            cmds.TryGetValue("base", out var @base);
            cmds.TryGetValue("filter", out var filter);
            cmds.TryGetValue("port", out var portStr);
            int.TryParse(portStr, out var port);
            var auth = authString == LdapAuthMechanism.GSSAPI ? LdapAuthMechanism.GSSAPI : LdapAuthMechanism.SIMPLE;
            host = host ?? "ldap.forumsys.com";
            @base = @base ?? "dc=example,dc=com";
            filter = filter ?? "(objectclass=*)";
            port = port > 0 ? port : 389;

            try
            {
                var token = new CancellationTokenSource();
                Console.CancelKeyPress+=(sender, eventArgs) => token.Cancel();
                while (!token.IsCancellationRequested)
                {
                    UsingOpenLdap(auth, host, @base, port, filter, cmds).Wait();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
            Console.WriteLine("End");
        }

        private static Dictionary<string, string> ParseCommandLine(string[] args)
        {
            var pattern = "^--([^=\"]*)=\"?(.*)\"?$";
            return args.Select(_ => Regex.Matches(_, pattern, RegexOptions.IgnoreCase).FirstOrDefault()?.Groups)
                .Where(_ => _ != null)
                .ToDictionary(_ => _[1].Value, _ => _[2].Value);
        }

        private static async Task UsingOpenLdap(string authType, string host, string @base, int port, string filter, IDictionary<string, string> cmds)
        {
            Console.WriteLine($"{nameof(authType)}:{authType}; {nameof(host)}:{host}; {nameof(@base)}:{@base}; {nameof(port)}:{port} ");
            using (var cn = new LdapConnection())
            {
                cn.Connect(host, port);
                if (authType == LdapAuthMechanism.GSSAPI)
                {
                    await cn.BindAsync();
                }
                else
                {
                    cmds.TryGetValue("who", out var who);
                    cmds.TryGetValue("password", out var password);
                    who = who ?? "cn=read-only-admin,dc=example,dc=com";
                    password = password ?? "password";
                    cn.Bind(LdapAuthMechanism.SIMPLE,who,password);
                }

                IList<LdapEntry> entries;

                if (cmds.TryGetValue("sid", out var sid))
                {
                    entries = await cn.SearchBySidAsync(@base, sid);
                }
                else
                {
                    entries = await cn.SearchAsync(@base, filter);
                }
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