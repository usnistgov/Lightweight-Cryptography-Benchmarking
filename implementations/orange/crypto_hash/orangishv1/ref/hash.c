
#include <stdio.h>
#include<string.h>
#include "photon.h"
#include "api.h"
#include "crypto_hash.h"
int crypto_hash(
                u8 * out,
                const unsigned char *in,
                unsigned long long inlen
                )
{
    u8 upper[CRYPTO_BYTES/2]={0},lower[CRYPTO_BYTES/2]={0},block[CRYPTO_BYTES]={0};
    int flag=0;
    if (inlen==0) {
        PHOTON_256_Permutation(block);
        for (int i=0; i<(CRYPTO_BYTES/2); i++) {
            out[i]= block[i];
        }
        PHOTON_256_Permutation(block);
        for (int i=0; i<(CRYPTO_BYTES/2); i++) {
            out[i+(CRYPTO_BYTES/2)]= block[i];
        }
        return 0;
    }
    
    ul count=0;
    int i =0;

    
    while (count<inlen) {
        for(i=0;i<(CRYPTO_BYTES/2);i++)
        {
            
            if(count<inlen)
                upper[i] = in[count];
           else if(count==inlen)
            {
                upper[i] =0x01;
                flag=1;
            }
            if(count>inlen)
            {
                upper[i]= 0x00;
            }
            if(count>CRYPTO_BYTES/2)
                lower[i] = in[count - (CRYPTO_BYTES/2)];
           
            count = count+1;
        }
        
    
            for (i=0; i<CRYPTO_BYTES/2; i++)
            {
                block[i] = block[i]^upper[i];
                block[i+(CRYPTO_BYTES/2)]= block[i+(CRYPTO_BYTES/2)]^lower[i];
            }
        
            PHOTON_256_Permutation(block);
    }
    
    for (i=0; i<(CRYPTO_BYTES/2); i++)
    {
        lower[i] = upper[i];
        
        upper[i] = 0x00;
    }
    
    if(flag==1)
        upper[0] = 0x02;
    else
        upper[0] = 0x01;
    
    for (i=0; i<(CRYPTO_BYTES/2); i++)
    {
        
        block[i] = block[i]^upper[i];
        block[i+(CRYPTO_BYTES/2)]= block[i+(CRYPTO_BYTES/2)]^lower[i];
        
    }

    
    PHOTON_256_Permutation(block);
    
    for(i=0;i<(CRYPTO_BYTES/2);i++)
        out[i] = block[i];
    PHOTON_256_Permutation(block);
    for(i=0;i<(CRYPTO_BYTES/2);i++)
        out[i+(CRYPTO_BYTES/2)] = block[i];
    
    return 0;
}


