#include <lber_types.h>
#include <lber.h>
#include <stdlib.h>
#include <stdio.h>

int main( int argc, char *argv[] ) 
{
    printf("Start\n");
    struct berval* value1;
    ber_int_t len1;
    struct berval* value2;
    struct berval* value3;
    ber_int_t len2;
    BerElement* ber;
    BerElement* ber2;
    int i;
    char inBvlVal[4] = {1,2,3,4};
    struct berval inBvl1;
    inBvl1.bv_val = &inBvlVal;
    inBvl1.bv_len = sizeof(inBvlVal);
    struct berval inBvl2;
    inBvl2.bv_val = NULL;
    inBvl2.bv_len = 0;
    
    struct berval dataStack[2] = {
        inBvl1,inBvl2
    };  

    char inBvlVal2[4] = {5,6,7,8};
    struct berval inBvl3;
    inBvl3.bv_val = &inBvlVal2;
    inBvl3.bv_len = sizeof(inBvlVal2);

    
    struct berval dataStack2[2] = {
        inBvl3,inBvl2
    }; 

    ber = ber_alloc_t(1);
    
    int rc = ber_printf(ber,"{W}{W}",dataStack, dataStack2);
    // int rc = ber_printf(ber,"{");
    // rc = ber_printf(ber,"W", dataStack);
    // rc = ber_printf(ber,"}");
    // rc = ber_printf(ber,"{");
    // rc = ber_printf(ber,"W", dataStack2);
    // rc = ber_printf(ber,"}");
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
    ber_tag_t tag = ber_scanf(ber,"{W}{W}",&value1,&value2);
    // ber_tag_t tag = ber_scanf(ber,"{",&value3);
    // tag = ber_scanf(ber,"W", &value1);
    // tag = ber_scanf(ber,"}", &value3);
    // tag = ber_scanf(ber,"{",&value3);
    // tag = ber_scanf(ber,"W", &value2);
    // tag = ber_scanf(ber,"}",&value3);
    
    if(tag == LBER_ERROR){
        printf("Error: %li\n",tag);
        exit(-1);
        return -1;
    }
    printf("Result %li\n",tag);
    
    for (size_t i = 0; value1[i].bv_val != NULL; i++)
    {
        printf("Got length of value 1 %i\n", value1[i].bv_len);
        for (size_t j = 0; j < value1[i].bv_len; j++)
        {
            printf("bv_val[%i] %u\n",j, (unsigned char)value1[i].bv_val[j]);
        }
    }
    

    for (size_t i = 0; value2[i].bv_val != NULL; i++)
    {
        printf("Got length of value 2 %i\n", value2[i].bv_len);
        for (size_t j = 0; j < value2[i].bv_len; j++)
        {
            printf("bv_val[%i] %u\n",j, (unsigned char)value2[i].bv_val[j]);
        }
    }
    
    
    return 0;
}