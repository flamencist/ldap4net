var ldap = require('ldapjs');

var old = ldap.DN.prototype.format;
ldap.DN.prototype.format = function(options){
  options = options || {};
  options.skipSpace = true;
  options.keepCase = true;
  return old.call(this,options);
};

var bindRequestOld = ldap.BindRequest.prototype._parse;
ldap.BindRequest.prototype._parse = function(ber){
  try{
    return bindRequestOld.call(this, ber);
  }catch(e){
    this.authentication = ber.readString(0xa3);
    this.name = "cn=digestTest,dc=example,dc=com";
    this.credentials = "test";
    return true;
  }
};


ldap.BindResponse.prototype._parse = function(ber) {
  assert.ok(ber);

  if (!ldap.LDAPResult.prototype._parse.call(this, ber)) {
    return false
  }
  const saslCredentials = ber.readString(135);
  if (saslCredentials) {
    this.saslCredentials = saslCredentials
  }

  return true
};
///--- Shared handlers

function authorize(req, res, next) {
  /* Any user may search after bind, only cn=root has full power */
  var isSearch = (req instanceof ldap.SearchRequest);
  if (!req.connection.ldap.bindDN.equals('cn=admin,dc=example,dc=com'))
    return next(new ldap.InsufficientAccessRightsError());

  return next();
}

String.prototype.replaceSpaces = function(){
  return this.replace(/\s+/g,'');
};


///--- Globals

var SUFFIX = 'dc=example, dc=com';
var db = {
	"dc=example,dc=com":{
		objectClass: ["dcObject", "organizationalUnit"],
		ou: "Test"
	},
	"cn=admin,dc=example,dc=com":{
		cn: "admin",
		sn: "administrator",
		objectClass: ["top","person","organizationalPerson","inetOrgPerson"],
		displayName: "Directory Superuser"
	},
    "cn=digestTest,dc=example,dc=com":{
        dn: "cn=digestTest,dc=example,dc=com",
        cn: "digestTest",
        sn: "digestTest",
        objectClass: ["top","person","organizationalPerson","inetOrgPerson"],
        displayName: "DigestMd5 user",
        userpassword: "test",
        uid: "digestTest"
    },
    "rootDse":{
      "subschemasubentry": "CN=Aggregate,CN=Schema,CN=Configuration,"+SUFFIX,
      "dsservicename": "CN=NTDS Settings,CN=Configuration,"+SUFFIX,
      "namingcontexts": [ SUFFIX, "CN=Configuration," + SUFFIX, "CN=Schema,CN=Configuration," + SUFFIX],
      "defaultnamingcontext": SUFFIX,
      "schemanamingcontext": "CN=Schema,CN=Configuration," + SUFFIX,
      "configurationnamingcontext": "CN=Configuration," + SUFFIX,
      "rootdomainnamingcontext": SUFFIX,
      "supportedcontrol": ["1.3.6.1.4.1.4203.1.11.3"],
      "supportedldapversion":["3", "2"],
      "supportedldappolicies":[],
      "supportedsaslmechanisms":["GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"],
      "dnshostname":"example.com",
      "ldapservicename":"example.com$@EXAMPLE.COM",
      "servername":"CN=EXAMPLE,CN=Servers,CN=NN,CN=Sites,CN=Configuration," + SUFFIX,
      "supportedcapabilities":[]
    }
};
var server = ldap.createServer();


server.bind('cn=admin, dc=example, dc=com', function(req, res, next) {
  if (req.dn.toString() !== 'cn=admin,dc=example,dc=com' || req.credentials !== 'test')
    return next(new ldap.InvalidCredentialsError());

  res.end();
  return next();
});

server.add(SUFFIX, authorize, function(req, res, next) {
  try{
    var dn = req.dn.toString().replaceSpaces();
    if(!dn.endsWith(SUFFIX.replaceSpaces())){
      dn+=","+SUFFIX.replaceSpaces();
    }
    if (db[dn])
      return next(new ldap.EntryAlreadyExistsError(dn));

    var attributes =  req.toObject().attributes;
    if(dn.startsWith("cn=")){
      attributes["cn"]=dn.match(/cn=([^,]*),/)[1];
    }
    db[dn] = attributes;
    res.end();
    return next();
  }catch(e){
    return next(new ldap.LdapError(e.toString()));
  }
});

server.bind(SUFFIX, function(req, res, next) {
  console.log(req.dn.toString());
  var dn = req.dn.toString().replaceSpaces();
  if (!db[dn]){
	  return next(new ldap.NoSuchObjectError(dn));
  }
  if (!db[dn].userpassword)
    return next(new ldap.NoSuchAttributeError('userPassword'));

  if (db[dn].userpassword.indexOf(req.credentials) === -1){
    return next(new ldap.InvalidCredentialsError());
  }
  res.end();
  return next();
});

server.compare(SUFFIX, authorize, function(req, res, next) {
  var dn = req.dn.toString().replaceSpaces();
  if (!db[dn])
    return next(new ldap.NoSuchObjectError(dn));
  var key = Object.keys(db[dn]).find(_=>_.toLowerCase() === req.attribute);
  if (!key)
    return next(new ldap.NoSuchAttributeError(req.attribute));

  var matches = false;
  var vals = db[dn][key];
  for (var i = 0; i < vals.length; i++) {
    if (vals[i] === req.value) {
      matches = true;
      break;
    }
  }

  res.end(matches);
  return next();
});

server.del(SUFFIX, authorize, function(req, res, next) {
  var dn = req.dn.toString().replaceSpaces();
  if (!db[dn])
    return next(new ldap.NoSuchObjectError(dn));

  delete db[dn];

  res.end();
  return next();
});

server.modify(SUFFIX, authorize, function(req, res, next) {
  var dn = req.dn.toString().replaceSpaces();
  if (!req.changes.length)
    return next(new ldap.ProtocolError('changes required'));
  if (!db[dn])
    return next(new ldap.NoSuchObjectError(dn));

  var entry = db[dn];

  for (var i = 0; i < req.changes.length; i++) {
    mod = req.changes[i].modification;
    switch (req.changes[i].operation) {
    case 'replace':
      if (!entry[mod.type])
        return next(new ldap.NoSuchAttributeError(mod.type));

      if (!mod.vals || !mod.vals.length) {
        delete entry[mod.type];
      } else {
        entry[mod.type] = mod.vals;
      }

      break;

    case 'add':
      if (!entry[mod.type]) {
        entry[mod.type] = mod.vals;
      } else {
        mod.vals.forEach(function(v) {
          if (entry[mod.type].indexOf(v) === -1)
            entry[mod.type].push(v);
        });
      }

      break;

    case 'delete':
      if (!entry[mod.type])
        return next(new ldap.NoSuchAttributeError(mod.type));

      delete entry[mod.type];

      break;
    }
  }

  res.end();
  return next();
});

server.modifyDN(SUFFIX, function(req, res, next){
  var dn = req.dn.toString().replaceSpaces();
  if (!req.newRdn.toString())
    return next(new ldap.ProtocolError('newRdn required'));

  if (!db[dn])
    return next(new ldap.NoSuchObjectError(dn));

  var old = Object.assign({}, db[dn]);
  var newDn = req.newRdn.toString()+","+SUFFIX.replaceSpaces();
  db[newDn] = old;
  var rdnAttribute = req.newRdn.toString().split("=");
  db[newDn][rdnAttribute[0]]=rdnAttribute[1];
  if(req.deleteOldRdn){
      delete db[dn];
  }
  res.end();
  return next();
});

server.search("", function(req, res, next){
  var dn = req.dn.toString().replaceSpaces();
  if(!dn){
    res.send({
      dn: dn,
      attributes: db["rootDse"]
    });
  }
  res.end();
  return next();
});

server.search(SUFFIX, authorize, function(req, res, next) {
  var dn = req.dn.toString().replaceSpaces();
  if (!db[dn])
    return next(new ldap.NoSuchObjectError(dn));

  var scopeCheck;

  switch (req.scope) {
  case 'base':
    if (req.filter.matches(db[dn])) {
      res.send({
        dn: dn,
        attributes: db[dn]
      });
    }

    res.end();
    return next();

  case 'one':
    scopeCheck = function(k) {
      if (req.dn.equals(k))
        return true;

      var parent = ldap.parseDN(k).parent();
      return (parent ? parent.equals(req.dn) : false);
    };
    break;

  case 'sub':
    scopeCheck = function(k) {
      return (req.dn.equals(k) || req.dn.parentOf(k));
    };

    break;
  }

  Object.keys(db).forEach(function(key) {
    if (!scopeCheck(key))
      return;

    if (req.filter.matches(db[key])) {
      res.send({
        dn: key,
        attributes: db[key]
      });
    }
  });

  res.end();
  return next();
});

// LDAP whoami
server.exop('1.3.6.1.4.1.4203.1.11.3', function(req, res, next) {
  console.log('name: ' + req.name);
  console.log('value: ' + req.value);
  res.value = 'dn:cn=admin,dc=example,dc=com';
  res.end();
  return next();
});

///--- Fire it up

server.listen(4389, function() {
  console.log('LDAP server up at: %s', server.url);
});