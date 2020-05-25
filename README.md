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
	* [Connect TLS](#connect-tls)
	* [Connect SSL (with self signed certificate)](#connect-ssl-with-self-signed-certificate)
	* [Connect Timeout](#connect-timeout)
	* [Bind](#bind)
	* [BindAsync](#bindAsync)
	* [Bind Anonymous](#bind-anonymous)
	* [Bind DIGEST-MD5](#bind-digest-md5)
	* [Bind SASL EXTERNAL (Client certificate)](#bind-sasl-external-client-certificate)
	* [Bind SASL EXTERNAL (Client certificate & Active Directory)](#bind-sasl-external-client-certificate--active-directory)
	* [Bind SASL EXTERNAL (Unix Socket)](#bind-sasl-external-unix-socket)
	* [Bind SASL proxy](#bind-sasl-proxy)
	* [Search](#search)
	* [Search (attributes with binary values)](#search-attributes-with-binary-values)
	* [Search (retrieve concrete list of attributes)](#search-retrieve-concrete-list-of-attributes)
	* [SearchAsync](#searchAsync)
	* [SearchByCn](#searchbycn)
	* [SearchBySid](#searchbysid)
	* [GetOption](#getoption)
	* [SetOption](#setoption)
	* [Add](#add)
	* [Add Binary Values](#add-binary-values)
	* [AddAsync](#addAsync)
	* [Modify](#modify)
	* [Modify Binary Values](#modify-binary-values)
	* [Reset password](#reset-password)
	* [ModifyAsync](#modifyAsync)
	* [Delete](#delete)
	* [DeleteAsync](#deleteAsync)
	* [Rename](#rename)
	* [RenameAsync](#renameAsync)
	* [SendRequest](#sendRequest)
	* [SendRequestAsync](#sendRequestAsync)
	* [Ldap V3 Controls](#ldap-v3-controls)
		* [PageResultRequestControl\PageResultResponseControl](#pageresultrequestcontrolpageresultresponsecontrol-1284011355614319)
		* [DirSyncRequestControl\DirSyncRequestControl](#dirsyncrequestcontroldirsyncresponsecontrol-1284011355614841)
		* [SortRequestControl\SortResponseControl](#sortrequestcontrolsortresponsecontrol-12840113556144731284011355614474)
		* [AsqRequestControl\AsqResponseControl](#asqrequestcontrolasqresponsecontrol-12840113556141504)
		* [DirectoryNotificationControl](#directorynotificationcontrol-1284011355614528)
		* [VlvRequestControl\VlvResponseControl](#vlvrequestcontrolvlvresponsecontrol-216840111373034921684011137303410)
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

## Features:
* Supported TLS\SSL
* Supported Unicode\Binary values
* Supported authentications:
	- Simple \ Basic \ Anonymous
	- SASL:
		- GSSAPI \ Kerberos V5 \ Negotiate 
		- [DIGEST-MD5](https://ldapwiki.com/wiki/DIGEST-MD5)
		- [EXTERNAL](https://ldapwiki.com/wiki/SASL%20EXTERNAL)
	- [SASL proxy authorization](https://www.openldap.org/doc/admin24/sasl.html#SASL%20Proxy%20Authorization)
* Supported LDAP V3 controls:
	- PageResultRequestControl\PageResultResponseControl
	- DirSyncRequestControl\DirSyncRequestControl
	- SortRequestControl\SortResponseControl
	- AsqRequestControl\AsqResponseControl
	- DirectoryNotificationControl
	- VlvRequestControl\VlvResponseControl

## Installation

``` Install-Package LdapForNet ``` 

``` dotnet add package LdapForNet ```

## Api

### Connect

```c#
using (var cn = new LdapConnection())
{
	// connect use Domain Controller host from computer hostname and default port 389
	// Computer hostname - mycomp.example.com => DC host - example.com
	cn.Connect();
	....
}

```


```c#
using (var cn = new LdapConnection())
{
	// connect use hostname and port
	cn.Connect("dc.example.com",636);
	....
}

```

```c#
using (var cn = new LdapConnection())
{
	// connect with URI
	cn.Connect(new URI("ldaps://dc.example.com:636"));
	....
}

```

```c#
using (var cn = new LdapConnection())
{
	// connect with ldap version 2
	cn.Connect(new URI("ldaps://dc.example.com:636",LdapForNet.Native.Native.LdapVersion.LDAP_VERSION2));
	....
}

```

### Connect TLS
```c#
using (var cn = new LdapConnection())
{
	// connect use hostname and port
	cn.Connect("dc.example.com",389);
	//set true if use self signed certificate for developing purpose
 	cn.StartTransportLayerSecurity(true); 
	....
}

```

### Connect SSL (with self signed certificate)
```c#
using (var cn = new LdapConnection())
{
	cn.Connect("dc.example.com", 636, LdapSchema.LDAPS);
	cn.TrustAllCertificates();
	....
}

```

### Connect Timeout
```c#
using (var cn = new LdapConnection())
{
	cn.Timeout = new TimeSpan(0, 1 ,0); // 1 hour
	....
}
```

### Bind


```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	// bind using kerberos credential cache file
	cn.Bind();
	...
}

```


```c#
using (var cn = new LdapConnection())
{
	cn.Connect("ldap.forumsys.com");
	// bind using userdn and password
	cn.Bind(LdapAuthMechanism.SIMPLE,"cn=read-only-admin,dc=example,dc=com","password");
	...
}

```

### BindAsync

```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	// bind using kerberos credential cache file
	cn.BindAsync().Wait();
	...
}

```

### Bind Anonymous


```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind(LdapAuthType.Anonymous, new LdapCredential());
	...
}

```

### Bind DIGEST-MD5
[About DIGEST-MD5](https://ldapwiki.com/wiki/DIGEST-MD5)

```c#
using (var cn = new LdapConnection())
{
    cn.Connect();

    cn.Bind(LdapAuthType.Digest, new LdapCredential
    {
        UserName = "username",
        Password = "clearTextPassword"
    });
	...
}

```

### Bind SASL EXTERNAL (Client certificate)
[About client certificate authentication in openldap](https://jpmens.net/pages/ldap-external/)

```c#
using (var cn = new LdapConnection())
{
    cn.Connect("dc.example.com",636,LdapSchema.LDAPS);
    var cert = new X509Certificate2("yourcert.pfx", "yourstrongpassword",
        X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

    cn.SetClientCertificate(cert);

    cn.Bind(LdapAuthType.External, new LdapCredential());
	...
}

```

### Bind SASL EXTERNAL (Client certificate & Active Directory)
[About client certificate authentication](https://techcommunity.microsoft.com/t5/iis-support-blog/client-certificate-authentication-part-1/ba-p/324623#) 

```c#
using (var cn = new LdapConnection())
{
    cn.Connect("dc.example.com",636,LdapSchema.LDAPS);
    var cert = new X509Certificate2("yourcert.pfx", "yourstrongpassword",
        X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

    cn.SetClientCertificate(cert);

    cn.Bind(LdapAuthType.ExternalAd, new LdapCredential());
	...
}

```

### Bind SASL EXTERNAL (Unix Socket)
```c#
using (var cn = new LdapConnection())
{
    cn.ConnectI("/tmp/yoursocketfile.unix");
    cn.Bind(LdapAuthType.External, new LdapCredential());
	...
}

```

### Bind SASL proxy
[About SASL auhtorization proxy](https://www.openldap.org/doc/admin24/sasl.html#SASL%20Proxy%20Authorization)

Works on UNIX systems
```c#

using (var cn = new LdapConnection())
{
    cn.Connect();

    cn.Bind(LdapAuthType.Digest, new LdapCredential
    {
        UserName = "username",
        Password = "clearTextPassword",
        AuthorizationId = "dn:cn=admin,dc=example,dc=com" 
    });
	...
}

```

Works on UNIX systems
```c#
using (var cn = new LdapConnection())
{
    cn.Connect();

    cn.Bind(LdapAuthType.Digest, new LdapCredential
    {
        UserName = "username",
        Password = "clearTextPassword",
        AuthorizationId = "u:admin" 
    });
	...
}

```

Works on UNIX systems
```c#
using (var cn = new LdapConnection())
{
    cn.Connect();

    cn.Bind(LdapAuthType.GssApi, new LdapCredential
    {
        AuthorizationId = "u:admin" 
    });
	...
}

```

Works on Windows system
```c#
using (var cn = new LdapConnection())
{
    cn.Connect();

    cn.Bind(LdapAuthType.Negotiate, new LdapCredential
    {
        UserName = "username",
        Password = "clearTextPassword"
    });
	...
}

```

### Search

```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search all objects in catalog (default search scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
	var entries = cn.Search("dc=example,dc=com","(objectClass=*)");
}
```


```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search  objects in catalog at first level scope
	var entries = cn.Search("dc=example,dc=com","(objectClass=*)", LdapSearchScope.LDAP_SCOPE_ONELEVEL);
}
```

### Search (attributes with binary values)

```c#
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

```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	var response = (SearchResponse)connection.SendRequest(new SearchRequest(Config.RootDn, "(&(objectclass=top)(cn=admin))",LdapSearchScope.LDAP_SCOPE_SUBTREE,"cn","objectClass"));
	var count = entries[0].Attributes.AttributeNames.Count; // 2
}
```

### SearchAsync

```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search all objects in catalog (default search scope = LdapSearchScope.LDAP_SCOPE_SUBTREE)
	var entries = cn.SearchAsync("dc=example,dc=com","(objectClass=*)").Result;
}
```

### SearchByCn  


```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search  by CN, get @base from machine hostname (my.example.com => dn=example,dn=com )
	var entries = cn.SearchByCn("read-only-admin");
}
```


```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search  by CN
	var entries = cn.SearchByCn("ou=admins,dn=example,dn=com", "read-only-admin", LdapSearchScope.LDAP_SCOPE_ONELEVEL);
}

```


### SearchBySid  


```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search  by CN, get @base from machine hostname (my.example.com => dn=example,dn=com )
	var entries = cn.SearchBySid("S-1-5-21-2127521184-1604012920-1887927527-72713");
}
```


```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	//search  by CN
	var entries = cn.SearchBySid("ou=admins,dn=example,dn=com", "S-1-5-21-2127521184-1604012920-1887927527-72713", LdapSearchScope.LDAP_SCOPE_ONELEVEL);
}

```

### GetOption

```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	var ldapVersion = cn.GetOption<int>(LdapOption.LDAP_OPT_PROTOCOL_VERSION);
	var host = cn.GetOption<string>(LdapOption.LDAP_OPT_HOST_NAME);
	var refferals = cn.GetOption<IntPtr>(LdapOption.LDAP_OPT_REFERRALS);
	cn.Bind();
}
```

### SetOption


```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	var ldapVersion = (int)LdapVersion.LDAP_VERSION3;
	cn.SetOption(LdapOption.LDAP_OPT_PROTOCOL_VERSION, ref ldapVersion);
	cn.Bind();
}
```

### Add
   
   
```c#
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

### Add Binary Values

```c#
using (var cn = new LdapConnection())
{
    cn.Connect();
    cn.Bind();
    var image = new DirectoryAttribute
    {
        Name = "jpegPhoto"
    };
    image.Add(new byte[]{1,2,3,4});
    directoryEntry.Attributes.Add(image);
    var response = (AddResponse)connection.SendRequest(new AddRequest("cn=test,dc=example,dc=com", image));
}
   ```


### AddAsync


```c#
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


```c#
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


### Modify Binary Values

```c#
using (var cn = new LdapConnection())
{
    cn.Connect();
    cn.Bind();
    var image = new DirectoryModificationAttribute
    {
        LdapModOperation = LdapModOperation.LDAP_MOD_REPLACE,
        Name = "jpegPhoto"
    };
    image.Add(new byte[]{ 5, 6, 7, 8});
    var response = (ModifyResponse)connection.SendRequest(new ModifyRequest("cn=test,dc=example,dc=com", image));
}
```

### Reset password

Microsoft Active Directory

```c#
using (var cn = new LdapConnection())
{
      // need use ssl/tls for reset password
      cn.Connect("dc.example.com", 636, LdapSchema.LDAPS);
      cn.Bind();
    
      var attribute = new DirectoryModificationAttribute()
      {
          Name = "unicodePwd",
          LdapModOperation = Native.LdapModOperation.LDAP_MOD_REPLACE
      };
    
      string password = "\"strongPassword\"";
      byte[] encodedBytes = System.Text.Encoding.Unicode.GetBytes(password);
      attribute.Add<byte[]>(encodedBytes);
    
      var response = (ModifyResponse)cn.SendRequest(new ModifyRequest("CN=yourUser,CN=Users,dc=dc,dc=local", attribute));
}
```

### ModifyAsync


```c#
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


```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	cn.Delete("cn=test,dc=example,dc=com");
}
```

### DeleteAsync

```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	await cn.DeleteAsync("cn=test,dc=example,dc=com");
}
```

### Rename

```c#
using (var cn = new LdapConnection())
{
	cn.Connect();
	cn.Bind();
	cn.Rename("cn=test,dc=example,dc=com", "cn=test2", null, true);
}
```

### RenameAsync

```c#
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

### Ldap V3 Controls
#### PageResultRequestControl\PageResultResponseControl [(1.2.840.113556.1.4.319)](https://ldapwiki.com/wiki/Simple%20Paged%20Results%20Control)
```c#

using (var cn = new LdapConnection())
{
    var results = new List<DirectoryEntry>();
    cn.Connect();
    cn.Bind();
    var directoryRequest = new SearchRequest("dc=example,dc=com", "(objectclass=top)", LdapSearchScope.LDAP_SCOPE_SUB);
    var resultRequestControl = new PageResultRequestControl(3);
    directoryRequest.Controls.Add(resultRequestControl);

    var response = (SearchResponse)cn.SendRequest(directoryRequest);
    results.AddRange(response.Entries);

    PageResultResponseControl pageResultResponseControl;
    while (true)
    {
        pageResultResponseControl = (PageResultResponseControl)response.Controls.FirstOrDefault(_ => _ is PageResultResponseControl);
        if (pageResultResponseControl == null || pageResultResponseControl.Cookie.Length == 0)
        {
            break;
        }

        resultRequestControl.Cookie = pageResultResponseControl.Cookie;
        response = (SearchResponse)connection.SendRequest(directoryRequest);
        results.AddRange(response.Entries);
    }
    var entries = results.Select(_=>_.ToLdapEntry()).ToList();
}
```

#### DirSyncRequestControl\DirSyncResponseControl [(1.2.840.113556.1.4.841)](https://ldapwiki.com/wiki/Directory%20Synchronization%20Control)
Ldap user should have ``DS-Replication-Get-Changes`` extended right (https://docs.microsoft.com/en-us/windows/win32/ad/polling-for-changes-using-the-dirsync-control)
```c#

using (var cn = new LdapConnection())
{
    cn.Connect();
    cn.Bind();
    var directoryRequest = new SearchRequest("dc=example,dc=com", "(objectclass=top)", LdapSearchScope.LDAP_SCOPE_SUB);
    var dirSyncRequestControl = new DirSyncRequestControl
    {
        Cookie = new byte[0],
        Option = DirectorySynchronizationOptions.IncrementalValues,
        AttributeCount = int.MaxValue
    };
    directoryRequest.Controls.Add(dirSyncRequestControl);

    var response = (SearchResponse)cn.SendRequest(directoryRequest);
        
    while (true)
    {
        var responseControl = (DirSyncResponseControl)response.Controls.FirstOrDefault(_ => _ is DirSyncResponseControl);
        if (responseControl == null || responseControl.Cookie.Length == 0)
        {
            break;
        }

        dirSyncRequestControl.Cookie = responseControl.Cookie;

		Thread.Sleep(60*1000);
        response = (SearchResponse)connection.SendRequest(directoryRequest);
            
        if (response.Entries.Any())
        {
            //handle changes
        }
    }
}
```

#### SortRequestControl\SortResponseControl [(1.2.840.113556.1.4.473\1.2.840.113556.1.4.474)](https://ldapwiki.com/wiki/Server%20Side%20Sort%20Control)
```c#

using (var cn = new LdapConnection())
{
    cn.Connect();
    cn.Bind();
    var directoryRequest = new SearchRequest("dc=example,dc=com", "(objectclass=top)", LdapSearchScope.LDAP_SCOPE_SUB);

    directoryRequest.Controls.Add(new SortRequestControl("cn", true));

    var response = (SearchResponse)cn.SendRequest(directoryRequest);
}
```

#### AsqRequestControl\AsqResponseControl [(1.2.840.113556.1.4.1504)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/77d880bf-aadd-4f6f-bb78-076af8e22cd8)
```c#

// get all members of group 'Domain Admins'
using (var connection = new LdapConnection())
{
    connection.Connect();
    connection.BindAsync().Wait();
    var directoryRequest = new SearchRequest("CN=Domain Admins,CN=Users,dc=example,dc=com", "(objectClass=user)", LdapSearchScope.LDAP_SCOPE_BASE);
    directoryRequest.Controls.Add(new AsqRequestControl("member"));

    var response = (SearchResponse)connection.SendRequest(directoryRequest);
}
```

#### DirectoryNotificationControl [(1.2.840.113556.1.4.528)](https://ldapwiki.com/wiki/LDAP_SERVER_NOTIFICATION_OID)
```c#

//get single notification from ldap server
var cts = new CancellationTokenSource();
using (var connection = new LdapConnection())
{
    var results = new List<DirectoryEntry>();
    connection.Connect();
    connection.BindAsync().Wait();
    var directoryRequest = new SearchRequest("CN=Administrator,CN=Users,dc=example,dc=com", "(objectClass=*)", LdapSearchScope.LDAP_SCOPE_BASE, "mail")
    {
        OnPartialResult = searchResponse =>
        {
            results.AddRange(searchResponse.Entries);
            cts.Cancel();
        }
    };
    var directoryNotificationControl = new DirectoryNotificationControl();
    directoryRequest.Controls.Add(directoryNotificationControl);


    var response = (SearchResponse) connection.SendRequestAsync(directoryRequest,cts.Token).Result;
                
}
```

#### VlvRequestControl\VlvResponseControl [(2.16.840.1.113730.3.4.9\2.16.840.1.113730.3.4.10)](https://docs.microsoft.com/en-us/windows/win32/controls/use-virtual-list-view-controls)

```c#
using (var connection = new LdapConnection())
{
    var results = new List<DirectoryEntry>();
    connection.Connect();
    connection.Bind();
    var directoryRequest = new SearchRequest("dc=example,dc=com", "(objectClass=*)", LdapSearchScope.LDAP_SCOPE_SUB);
    var pageSize = 3;

    var vlvRequestControl = new VlvRequestControl(0, pageSize - 1, 1);
    directoryRequest.Controls.Add(new SortRequestControl("cn", false));
    directoryRequest.Controls.Add(vlvRequestControl);

    while (true)
    {
        var response = (SearchResponse)connection.SendRequest(directoryRequest);
        results.AddRange(response.Entries);
        var vlvResponseControl = (VlvResponseControl)response.Controls.Single(_ => _.GetType() == typeof(VlvResponseControl));
        vlvRequestControl.Offset += pageSize;
        if(vlvRequestControl.Offset > vlvResponseControl.ContentCount)
        {
            break;
        }
    }
                
    var entries = results.Select(_ => _.ToLdapEntry()).ToList();
}

```

### GetRootDse
Information about server https://ldapwiki.com/wiki/RootDSE

```c#

using (var cn = new LdapConnection())
{
    cn.Connect();
    cn.Bind();
    var rootDse =  connection.GetRootDse();
}
```

### WhoAmI
Returns authorization id of user https://ldapwiki.com/wiki/Who%20Am%20I%20Extended%20Operation

```c#

using (var cn = new LdapConnection())
{
    cn.Connect();
    cn.Bind();
    var authzId = connection.WhoAmI().Result;
}
```

### License

This software is distributed under the terms of the MIT License (MIT).

### Authors

Alexander Chermyanin / [LinkedIn](https://www.linkedin.com/in/alexander-chermyanin)



Contributions and bugs reports are welcome.
