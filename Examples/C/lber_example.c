#include <lber_types.h>
#include <lber.h>
#include <stdlib.h>
#include <stdio.h>

int main( int argc, char *argv[] ) 
{
    printf("Start\n");
    char* value1;
    ber_int_t len1;
    char* value2;
    ber_int_t len2;
    BerElement* ber;
    BerElement* ber2;
    int i;
    unsigned char dataStack[2] = {
        255, 1
    };  

    ber = ber_alloc_t(0);
    
    int rc = ber_printf(ber,"{BB}",&dataStack[0], 1, &dataStack[1], 1);
    if(rc == -1){
        printf("Error %i\n",rc);
    }
    struct berval *bv;
    if(ber_flatten(ber,&bv) == -1){
        printf("ber_flatten failed\n");
    }

    for(i=0;i < bv->bv_len;i++){
        printf("bv_val[%i] %u\n",i, (unsigned char)bv->bv_val[i]);
    }

    ber_reset(ber,1);
    ber_tag_t tag = ber_scanf(ber,"{");
    tag = ber_scanf(ber,"B", &value1, &len1);
    tag = ber_scanf(ber,"B", &value2, &len2);
    tag = ber_scanf(ber,"}");
    
    if(tag == LBER_ERROR){
        printf("Error: %li\n",tag);
        exit(-1);
        return -1;
    }
    printf("Result %li\n",tag);
    printf("Got value %s with length %i\n", value1, len1);
    
    return 0;
}