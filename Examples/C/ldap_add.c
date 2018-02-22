#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <lber.h>
#include <ldap.h>

#define RCSID "$Id: ldap_add.c,v 1.3 2003/07/14 15:21:56 rory Exp $"

int main( int argc, char *argv[] ) {
  LDAP *ld;
  int  result;
  int  auth_method = LDAP_AUTH_SIMPLE;
  int desired_version = LDAP_VERSION3;
  char *ldap_host = "localhost";
  char *root_dn = "cn=Manager, dc=example, dc=com";
  char *root_pw = "secret";
  
  char *user_dn = "cn=Rory Winston, ou=Developers, dc=example, dc=com";

  char *cn_values[] = {"Rory Winston", NULL};
  char *sn_values[] = {"Winston", NULL};
  char *givenName_values[] = {"Rory", NULL};
  char *uid_values[] = {"rwinston", NULL};
  char *title_values[] = {"Internet Developer", NULL};
  char *objectClass_values[] = {"inetOrgPerson", NULL};
  char *ou_values[] = {"Development", NULL};

  LDAPMod cn, sn, givenName, uid, title, objectClass, ou;
  LDAPMod *mods[8];
  
  /* Initialize the attributes */
  cn.mod_op = LDAP_MOD_ADD;
  cn.mod_type = "cn";
  cn.mod_values = cn_values;

  sn.mod_op = LDAP_MOD_ADD;
  sn.mod_type = "sn";
  sn.mod_values = sn_values;

  givenName.mod_op = LDAP_MOD_ADD;
  givenName.mod_type = "givenName";
  givenName.mod_values = givenName_values;

  uid.mod_op = LDAP_MOD_ADD;
  uid.mod_type = "uid";
  uid.mod_values = uid_values;

  title.mod_op = LDAP_MOD_ADD;
  title.mod_type = "title";
  title.mod_values = title_values;

  objectClass.mod_op = LDAP_MOD_ADD;
  objectClass.mod_type = "objectClass";
  objectClass.mod_values = objectClass_values;

  ou.mod_op = LDAP_MOD_ADD;
  ou.mod_type = "ou";
  ou.mod_values = ou_values;

  mods[0] = &cn;
  mods[1] = &sn;
  mods[2] = &givenName;
  mods[3] = &uid;
  mods[4] = &title;
  mods[5] = &objectClass;
  mods[6] = &ou;
  mods[7] = NULL;


  if ((ld = ldap_init(ldap_host, LDAP_PORT)) == NULL ) {
    perror( "ldap_init failed" );
    exit( EXIT_FAILURE );
  }

  /* set the LDAP version to be 3 */
  if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version) != LDAP_OPT_SUCCESS)
   {
      ldap_perror(ld, "ldap_set_option");
      exit(EXIT_FAILURE);
   }
   
  if (ldap_bind_s(ld, root_dn, root_pw, auth_method) != LDAP_SUCCESS ) {
    ldap_perror( ld, "ldap_bind" );
    exit( EXIT_FAILURE );
  }
  
  if (ldap_add_s(ld, user_dn, mods) != LDAP_SUCCESS) {
    ldap_perror( ld, "ldap_add_s" );
    exit(EXIT_FAILURE);
  }
 
  result = ldap_unbind_s(ld);
  
  if (result != 0) {
    fprintf(stderr, "ldap_unbind_s: %s\n", ldap_err2string(result));
    exit( EXIT_FAILURE );
  }

  return EXIT_SUCCESS;
}









