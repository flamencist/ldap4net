INCLUDE=/usr/local/include
LIB=/usr/local/lib
CFLAGS=-ansi -pedantic

all:
	gcc $(CFLAGS) -DWITH_OPENLDAP -o ldap_add ldap_add.c -I$(INCLUDE)/ -L$(LIB) -lldap -llber
	gcc $(CFLAGS) -DWITH_OPENLDAP -o ldap_search ldap_search.c -I$(INCLUDE)/ -L$(LIB) -lldap -llber
	gcc $(CFLAGS) -DWITH_OPENLDAP -o ldap_delete ldap_delete.c -I$(INCLUDE)/ -L$(LIB) -lldap -llber
	gcc $(CFLAGS) -DWITH_OPENLDAP -o ldap_modify ldap_modify.c -I$(INCLUDE)/ -L$(LIB) -lldap -llber
	gcc $(CFLAGS) -DWITH_OPENLDAP -o ldap_search_async ldap_search_async.c -I$(INCLUDE)/ -L$(LIB) -lldap -llber

clean:
	rm -f ldap_add ldap_search ldap_delete ldap_modify ldap_search_async
