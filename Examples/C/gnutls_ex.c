#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <gnutls/gnutls.h>

int main( int argc, char *argv[] ) {
  int size;
  gnutls_x509_crt_t certs[6] = {0};
  size = sizeof(certs[0]);
  int i;
  for(i = 0; i < 6; i++){
    printf("certs[%i] is %p\n", i, certs[i]);
  }
  printf("Size of [gnutls_x509_crt_t] is [%i] bytes\n", size);
  return EXIT_SUCCESS;
}









