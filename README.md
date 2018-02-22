# ldap4net

Port of OpenLdap Client library (https://www.openldap.org/software/man.cgi?query=ldap) to DotNet Core (Ubuntu only)
Supported on the .NET Standard - minimum required is 2.0 - compatible .NET runtimes: .NET Core, Mono.
Supported platforms:
  
  * Ubuntu 14.04, 16.04, 18.04
  
It works with any LDAP protocol compatible directory server (including Microsoft Active Directory).

[![Build Status](https://travis-ci.org/flamencist/ldap4net.svg?branch=master)](https://travis-ci.org/flamencist/ldap4net) - Linux Build <br />
[![NuGet](https://img.shields.io/nuget/v/LdapForNet.svg)](https://www.nuget.org/packages/LdapForNet/)

Supported SASL GSSAPI (Kerberos) authentication!

Sample usage (GSSAPI authentication)

```cs
using (var cn = new LdapConnection())
{
	// connect
	cn.Connect("<<hostname>>", 389);
	// bind using kerberos credential cache file
	cn.Bind();
	// call ldap op
	var entries = cn.Search("<<basedn>>", "(objectClass=*)");
}

```

Supported API:

  * Connect
  * Bind
  * Search
  


Contributions and bugs reports are welcome.
