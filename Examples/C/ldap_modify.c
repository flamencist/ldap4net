#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <lber.h>
#include <ldap.h>

#define RCSID "$Id: ldap_modify.c,v 1.3 2003/07/14 15:21:56 rory Exp $"

int main( int argc, char *argv[] ) {
  LDAP *ld;
  int  result;
  int  auth_method = LDAP_AUTH_SIMPLE;
  int desired_version = LDAP_VERSION3;
  char *ldap_host = "localhost";
  char *root_dn = "cn=Manager, dc=example, dc=com";
  char *root_pw = "secret";
  
  char *user_dn = "cn=Rory Winston, ou=Developers, dc=example, dc=com";

  char *title_values[] = {"Internet Development Manager", NULL};

  LDAPMod title;
  LDAPMod *mods[2];
  
  /* Initialize the attributes */
  title.mod_op = LDAP_MOD_REPLACE;
  title.mod_type = "title";
  title.mod_values = title_values;

  mods[0] = &title;
  mods[1] = NULL;


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
  
  if (ldap_modify_s(ld, user_dn, mods) != LDAP_SUCCESS) {
    ldap_perror( ld, "ldap_modify_s" );
    exit(EXIT_FAILURE);
  }
  
  result = ldap_unbind_s(ld);
  
  if (result != 0) {
    fprintf(stderr, "ldap_unbind_s: %s\n", ldap_err2string(result));
    exit( EXIT_FAILURE );
  }

  return EXIT_SUCCESS;
}









