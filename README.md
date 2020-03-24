# ldap4net

[![Build Status](https://travis-ci.org/flamencist/ldap4net.svg?branch=master)](https://travis-ci.org/flamencist/ldap4net)
[![Build Status](https://dev.azure.com/achermyanin/ldap4net/_apis/build/status/flamencist.ldap4net?branchName=master)](https://dev.azure.com/achermyanin/ldap4net/_build/latest?definitionId=1&branchName=master)
[![NuGet](https://img.shields.io/nuget/v/LdapForNet.svg)](https://www.nuget.org/packages/LdapForNet/)

Cross platform port of OpenLdap Client library (https://www.openldap.org/software/man.cgi?query=ldap)  
and Windows Ldap (https://docs.microsoft.com/en-us/windows/win32/api/_ldap/) to DotNet Core

Help support the project:

<a href="https://www.buymeacoffee.com/flamencist" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee" style="height: auto !important;width: auto !important;" ></a>

For Linux\OSX you must ensure you have the latest OpenLDAP client libraries installed from http://www.openldap.org

  
It works with any LDAP protocol compatible directory server (including Microsoft Active Directory).

Supported paswordless authentication (Kerberos) on all platforms (on Linux\OSX supported SASL GSSAPI (Kerberos) authentication!).



Sample usage (Kerberos authentication)

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
	* [BindAsync](#bindAsync)
	* [Bind DIGEST-MD5](#bind-digest-md5)
	* [Bind SASL proxy](#bind-sasl-proxy)
	* [Search](#search)
	* [Search (attributes with binary values)](#search-attributes-with-binary-values)
	* [Search (retrieve concrete list of attributes)](#search-retrieve-concrete-list-of-attributes)
	* [SearchAsync](#searchAsync)
	* [SearchByCn](#searchbycn)
	* [SearchBySid](#searchbysid)
	* [SetOption](#setoption)
	* [Add](#add)
	* [AddAsync](#addAsync)
	* [Modify](#modify)
	* [ModifyAsync](#modifyAsync)
	* [Delete](#delete)
	* [DeleteAsync](#deleteAsync)
	* [Rename](#rename)
	* [RenameAsync](#renameAsync)
	* [SendRequest](#sendRequest)
	* [SendRequestAsync](#sendRequestAsync)
	* [GetRootDse](#getRootDse)
	* [WhoAmI](#whoami)
	* [GetNativeLdapPtr (deprecated)](#getnativeldapptr)
	* [License](#license)
	* [Authors](#authors)

## Supported platforms

* Most of popular Linux distributives
* OSX
* Windows
* Supported on the .NET Standard - minimum required is 2.0 - compatible .NET runtimes: .NET Core, Mono, .NET Framework.
* Supported authentications:
	- Simple \ Basic
	- SASL:
		- GSSAPI \ Kerberos V5 \ Negotiate 
		- [DIGEST-MD5](https://ldapwiki.com/wiki/DIGEST-MD5)
	- [SASL proxy authorization](https://www.openldap.org/doc/admin24/sasl.html#SASL%20Proxy%20Authorization)

## Installation

``` Install-Package LdapForNet ``` 

``` dotnet add package LdapForNet ```

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

```cs
using (var cn = new LdapConnection())
{
	// connect with URI
	cn.Connect(new URI("ldaps://dc.example.com:636"));
	....
}

```

```cs
using (var cn = new LdapConnection())
{
	// connect with ldap version 2
	cn.Connect(new URI("ldaps://dc.example.com:636",LdapForNet.Native.Native.LdapVersion.LDAP_VERSION2));
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

### BindAsync

```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	// bind using kerberos credential cache file
	cn.BindAsync().Wait();
	...
}

```

### Bind DIGEST-MD5
[About DIGEST-MD5](https://ldapwiki.com/wiki/DIGEST-MD5)

```cs
using (var cn = new LdapConnection())
{
    connection.Connect();

    connection.Bind(LdapAuthType.Digest, new LdapCredential
    {
        UserName = "username",
        Password = "clearTextPassword"
    });
	...
}

```

### Bind SASL proxy
[About SASL auhtorization proxy](https://www.openldap.org/doc/admin24/sasl.html#SASL%20Proxy%20Authorization)

Works on UNIX systems
```cs

using (var cn = new LdapConnection())
{
    connection.Connect();

    connection.Bind(LdapAuthType.Digest, new LdapCredential
    {
        UserName = "username",
        Password = "clearTextPassword",
        AuthorizationId = "dn:cn=admin,dc=example,dc=com" 
    });
	...
}

```

Works on UNIX systems
```cs
using (var cn = new LdapConnection())
{
    connection.Connect();

    connection.Bind(LdapAuthType.Digest, new LdapCredential
    {
        UserName = "username",
        Password = "clearTextPassword",
        AuthorizationId = "u:admin" 
    });
	...
}

```

Works on UNIX systems
```cs
using (var cn = new LdapConnection())
{
    connection.Connect();

    connection.Bind(LdapAuthType.GssApi, new LdapCredential
    {
        AuthorizationId = "u:admin" 
    });
	...
}

```

Works on Windows system
```cs
using (var cn = new LdapConnection())
{
    connection.Connect();

    connection.Bind(LdapAuthType.Negotiate, new LdapCredential
    {
        UserName = "username",
        Password = "clearTextPassword"
    });
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

### Search (attributes with binary values)

```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	var response = (SearchResponse) connection.SendRequest(new SearchRequest("cn=admin,dc=example,dc=com", "(&(objectclass=top)(cn=admin))", LdapSearchScope.LDAP_SCOPE_SUBTREE));
	var directoryAttribute = response.Entries.First().Attributes["objectSid"];
	var objectSid = directoryAttribute.GetValues<byte[]>().First();
}
```

### Search (retrieve concrete list of attributes)

```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	var response = (SearchResponse)connection.SendRequest(new SearchRequest(Config.RootDn, "(&(objectclass=top)(cn=admin))",LdapSearchScope.LDAP_SCOPE_SUBTREE,"cn","objectClass"));
	var count = entries[0].Attributes.AttributeNames.Count; // 2
}
```

### SearchAsync

```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search all objects in catalog (default search scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
	var entries = cn.SearchAsync("dc=example,dc=com","(objectClass=*)").Result;
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

### AddAsync


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	await cn.AddAsync(new LdapEntry
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

### ModifyAsync


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	await cn.ModifyAsync(new LdapModifyEntry
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

### DeleteAsync


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	await cn.DeleteAsync("cn=test,dc=example,dc=com");
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

### RenameAsync


```cs
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	await cn.RenameAsync("cn=test,dc=example,dc=com", "cn=test2", null, true);
}
```

### SendRequest
Generic method for ldap requests.
Inspired by .NET Framework LdapConnection.SendRequest

 ```cs
 using (var cn = new LdapConnection())
 {
 	cn.Connect();
 	cn.Bind();
 	cn.SendRequest(new DeleteRequest("cn=test,dc=example,dc=com"));
 }
 ```

### SendRequestAsync
Generic method for ldap requests.
Inspired by .NET Framework LdapConnection.SendRequest

 ```cs
 using (var cn = new LdapConnection())
 {
 	cn.Connect();
 	cn.Bind();
 	var cancellationTokenSource = new CancellationTokenSource();
 	//whoami
 	var res = await cn.SendRequestAsync(new ExtendedRequest("1.3.6.1.4.1.4203.1.11.3"), cancellationTokenSource.Token);
 	var extendedResponse = (ExtendedResponse) res;
 	var name = Encoding.UTF8.GetString(extendedResponse.ResponseValue);
 }
 ```

### GetRootDse
Information about server https://ldapwiki.com/wiki/RootDSE

```cs

 using (var cn = new LdapConnection())
 {
 	cn.Connect();
 	cn.Bind();
	var rootDse =  connection.GetRootDse();
 }
```

### WhoAmI
Returns authorization id of user https://ldapwiki.com/wiki/Who%20Am%20I%20Extended%20Operation

```cs

 using (var cn = new LdapConnection())
 {
 	cn.Connect();
 	cn.Bind();
	var authzId = connection.WhoAmI().Result;
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

### License

This software is distributed under the terms of the MIT License (MIT).

### Authors

Alexander Chermyanin / [LinkedIn](https://www.linkedin.com/in/alexander-chermyanin)



Contributions and bugs reports are welcome.
