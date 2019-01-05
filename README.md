# ldap4net

[![Build Status](https://travis-ci.org/flamencist/ldap4net.svg?branch=master)](https://travis-ci.org/flamencist/ldap4net)
[![NuGet](https://img.shields.io/nuget/v/LdapForNet.svg)](https://www.nuget.org/packages/LdapForNet/)

Port of OpenLdap Client library (https://www.openldap.org/software/man.cgi?query=ldap) to DotNet Core

  
It works with any LDAP protocol compatible directory server (including Microsoft Active Directory).



Supported SASL GSSAPI (Kerberos) authentication!

Sample usage (GSSAPI authentication)

```cs
using (var cn = new LdapConnection())
{
	// connect
	cn.Connect();
	// bind using kerberos credential cache file
	cn.Bind();
	// call ldap op
	var entries = cn.Search("<<basedn>>", "(objectClass=*)");
}

```

## Overview

* [Supported platforms](#supported-platforms)
* [Installation](#installation)
* [API](#api)
	* [Connect](#connect)
	* [Bind](#bind)
	* [Search](#search)
	* [SearchByCn](#searchbycn)
	* [SearchBySid](#searchbysid)
	* [SetOption](#setoption)
	* [Add](#add)
	* [Modify](#modify)
	* [Delete](#delete)
	* [Rename](#rename)
	* [GetNativeLdapPtr](#getnativeldapptr)
	* [Native](#native)
	* [License](#license)
	* [Authors](#authors)

## Supported platforms

* Most of popular Linux distributives
* Supported on the .NET Standard - minimum required is 2.0 - compatible .NET runtimes: .NET Core, Mono.

## Installation

``` Install-Package LdapForNet -Version 0.1.0-beta ``` 

``` dotnet add package LdapForNet --version 0.1.0-beta ```

## Api

### Connect

```cs
using (var cn = new LdapConnection())
{
	// connect use Domain Controller host from computer hostname and default port 389
	// Computer hostname - mycomp.example.com => DC host - example.com
	cn.Connect();
	....
}

```


```cs
using (var cn = new LdapConnection())
{
	// connect use hostname and port
	cn.Connect("dc.example.com",636);
	....
}

```


### Bind


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	// bind using kerberos credential cache file
	cn.Bind();
	...
}

```


```cs
using (var cn = new LdapConnection())
{
	cn.Connect("ldap.forumsys.com");
	// bind using userdn and password
	cn.Bind(LdapAuthMechanism.SIMPLE,"cn=read-only-admin,dc=example,dc=com","password");
	...
}

```


### Search

```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search all objects in catalog (default search scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
	var entries = cn.Search("dc=example,dc=com","(objectClass=*)");
}
```


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search  objects in catalog at first level scope
	var entries = cn.Search("dc=example,dc=com","(objectClass=*)", LdapSearchScope.LDAP_SCOPE_ONELEVEL);
}
```

### SearchByCn  


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search  by CN, get @base from machine hostname (my.example.com => dn=example,dn=com )
	var entries = cn.SearchByCn("read-only-admin");
}
```


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search  by CN
	var entries = cn.SearchByCn("ou=admins,dn=example,dn=com", "read-only-admin", LdapSearchScope.LDAP_SCOPE_ONELEVEL);
}

```


### SearchBySid  


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search  by CN, get @base from machine hostname (my.example.com => dn=example,dn=com )
	var entries = cn.SearchBySid("S-1-5-21-2127521184-1604012920-1887927527-72713");
}
```


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search  by CN
	var entries = cn.SearchBySid("ou=admins,dn=example,dn=com", "S-1-5-21-2127521184-1604012920-1887927527-72713", LdapSearchScope.LDAP_SCOPE_ONELEVEL);
}

```



### SetOption


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	var ldapVersion = (int)LdapVersion.LDAP_VERSION3;
	cn.SetOption(LdapOption.LDAP_OPT_PROTOCOL_VERSION, ref ldapVersion);
	cn.Bind();
}
```

### Add


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	cn.Add(new LdapEntry
	{
	Dn = "cn=test,dc=example,dc=com",
	Attributes = new Dictionary<string, List<string>>
	{
	    {"sn", new List<string> {"Winston"}},
	    {"objectclass", new List<string> {"inetOrgPerson"}},
	    {"givenName", new List<string> {"your_name"}},
	    {"description", new List<string> {"your_description"}}
	}
	});
}
```

### Modify


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	cn.Modify(new LdapModifyEntry
	{
	Dn = "cn=test,dc=example,dc=com",
	Attributes = new List<LdapModifyAttribute>
	{
	    new LdapModifyAttribute
	    {
		LdapModOperation = LdapModOperation.LDAP_MOD_REPLACE,
		Type = "givenName",
		Values = new List<string> {"test_value_2"}
	    },
	    new LdapModifyAttribute
	    {
		LdapModOperation = LdapModOperation.LDAP_MOD_ADD,
		Type = "displayName",
		Values = new List<string> {"test_display_name"}
	    },
	    new LdapModifyAttribute
	    {
		LdapModOperation = LdapModOperation.LDAP_MOD_ADD,
		Type = "sn",
		Values = new List<string> {"test"}
	    },
	    new LdapModifyAttribute
	    {
		LdapModOperation = LdapModOperation.LDAP_MOD_DELETE,
		Type = "description",
		Values = new List<string> {"test_value"}
	    }
	}
	});
}
```

### Delete


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	cn.Delete("cn=test,dc=example,dc=com");
}
```

### Rename


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	cn.Rename("cn=test,dc=example,dc=com", "cn=test2", null, true);
}
```


### GetNativeLdapPtr

For own implementations or not implemented OpenLdap functions use ```GetNativeLdapPtr```. It's provided pointer to native structure LDAP. So we can use this pointer in own implementations.
For example, implement "DIGEST-MD5" authentication 

```cs
using static LdapForNet.Native.Native;

using (var cn = new LdapConnection())
{
	cn.Connect();
	var ld = cn.GetNativeLdapPtr();
	var defaults = new LdapSaslDefaults { 
		mech = "DIGEST-MD5",
		passwd="password",
        	authcid="user",
        	realm="realm.com",
        	authzid="user"
	};
	var ptr = Marshal.AllocHGlobal(Marshal.SizeOf(defaults));
            Marshal.StructureToPtr(defaults, ptr, false);
	int rc = ldap_sasl_interactive_bind_s( ld, null,defaults.mech, IntPtr.Zero, IntPtr.Zero,
                (uint)LdapInteractionFlags.LDAP_SASL_QUIET, (l, flags, d, interact) => (int)LdapResultCode.LDAP_SUCCESS, ptr);
...
}
```

### Native

OpenLdap native methods can be used directly. Native methods implemented in static class ```LdapForNet.Native.Native```:


```cs
using static LdapForNet.Native.Native;

using (var cn = new LdapConnection())
{
	cn.Connect();
	var ld = cn.GetNativeLdapPtr();
	var res = ldap_sasl_interactive_bind_s(ld,...);
	if (res != (int)LdapResultCode.LDAP_SUCCESS)
	{
		Trace.TraceError($"Error {method}: {LdapError2String(res)} ({res}).");
	}
}
```

### License

This software is distributed under the terms of the MIT License (MIT).

### Authors

Alexander Chermyanin / [LinkedIn](https://www.linkedin.com/in/alexander-chermyanin)



Contributions and bugs reports are welcome.
