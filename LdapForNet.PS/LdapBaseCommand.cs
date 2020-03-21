using System;
using System.Management.Automation;

namespace LdapForNet.PS
{
    public abstract class LdapBaseCommand : PSCmdlet
    {
        [Parameter(
            Position = 0)]
        public string HostName { get; set; }

        [Parameter(
            Position = 1)]
        public int Port { get; set; } = 389;

        [Parameter(
            Position = 2)]
        public int LdapVersion { get; set; } = 3;

        [Parameter(
            Position = 3)]
        [ValidateSet("simple", "kerberos", "digest")]
        public string Auth { get; set; } = "kerberos";

        [Parameter(
            Position = 4)]
        public string UserName { get; set; }

        [Parameter(
            Position = 5)]
        public string Password { get; set; }

        [Parameter(
            Position = 6)]
        public string Realm { get; set; }

        [Parameter(
            Position = 7)]
        public string AuthorizationId { get; set; }

        protected override void ProcessRecord()
        {
            using (var cn = new LdapConnection())
            {
                if (string.IsNullOrEmpty(HostName))
                {
                    cn.Connect(Port, GetLdapVersion());
                }
                else if(!string.IsNullOrEmpty(HostName))
                {
                    cn.Connect(HostName,Port, GetLdapVersion());
                }
                
                cn.Bind(ToAuthType(Auth), new LdapCredential
                {
                    UserName = UserName,
                    Password = Password,
                    Realm = Realm,
                    AuthorizationId = AuthorizationId
                });
                OnLdapBind(cn);
            }
        }

        private Native.Native.LdapAuthType ToAuthType(string authType)
        {
            switch (authType)
            {
                case "kerberos":
                    return Native.Native.LdapAuthType.Negotiate;
                case "simple":
                    return Native.Native.LdapAuthType.Simple;
                case "digest":
                    return Native.Native.LdapAuthType.Digest;
                default:
                    throw new ArgumentException($"Unknown {nameof(Auth)}");
            }
        }

        private Native.Native.LdapVersion GetLdapVersion()
        {
            return (Native.Native.LdapVersion)Enum.Parse(typeof(Native.Native.LdapVersion),LdapVersion.ToString());
        }

        protected abstract void OnLdapBind(LdapConnection ldapConnection);

    }
}
