using System;
using System.Collections.Generic;
using System.Text;

namespace LdapForNet
{
    [Flags]
    public enum CertificateOptions
    {
        SslTls = 0,
        StartTls = 1
    }
}
