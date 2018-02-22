# ldap4net

[![Build Status](https://travis-ci.org/flamencist/ldap4net.svg?branch=master)](https://travis-ci.org/flamencist/ldap4net)
[![NuGet](https://img.shields.io/nuget/v/LdapForNet.svg)](https://www.nuget.org/packages/LdapForNet/)

Port of OpenLdap Client library (https://www.openldap.org/software/man.cgi?query=ldap) to DotNet Core (supported Ubuntu only)

  
It works with any LDAP protocol compatible directory server (including Microsoft Active Directory).



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

## Overview

* [Supported platforms](#supported-platforms)
* [Installation](#installation)
* [API](#api)
	* [Connect](#connect)
	* [Bind](#bind)
	* [Search](#search)
	* [SearchByCn](#searchbycn)
	* 

## Supported platforms

* Ubuntu 14.04, 16.04, 18.04
* Supported on the .NET Standard - minimum required is 2.0 - compatible .NET runtimes: .NET Core, Mono.

## Installation
``` Install-Package LdapForNet -Version 0.0.1-alpha ``` (https://www.nuget.org/packages/LdapForNet)

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
	// connect use Domain Controller host from computer hostname and default port 389
	// Computer hostname - mycomp.example.com => DC host - example.com
	cn.Connect("<<hostname>>","<<port>>");
	....
}

```


### Bind
### Search
### SearchByCn  


Contributions and bugs reports are welcome.
