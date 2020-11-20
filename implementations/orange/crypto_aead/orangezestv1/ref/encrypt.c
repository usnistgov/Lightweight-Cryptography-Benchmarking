//
//  main.c
//  orangealg
//
//  Created by Bishwajit Chakraborty on 23/02/19.
//  Copyright © 2019 Bishwajit Chakraborty. All rights reserved.
//

#include <stdio.h>
#include<string.h>
#include "orangemodule.h"
#include "api.h"
#include "crypto_aead.h"
#define CRYPTO_BLKBYTES (CRYPTO_NPUBBYTES + CRYPTO_KEYBYTES)
int crypto_aead_encrypt(
                        unsigned char *c,unsigned long long *clen,
                        const unsigned char *m,unsigned long long mlen,
                        const unsigned char *ad,unsigned long long adlen,
                        const unsigned char *nsec,
                        const unsigned char *npub,
                        const unsigned char *k
                        )
{
    
    
    /*################################################################################################################
     
     Encryption Initialization Module
     
     ################################################################################################################*/
    
    if(nsec !=NULL){
        u32 unused[1];                               // using Nsec
        memcpy(unused,nsec,0);
    }

    u8 photon_in[CRYPTO_BLKBYTES] ={0};
    for(int j=0 ; j<CRYPTO_NPUBBYTES ;j++)
    {
        photon_in[j] = npub[j];
                                                               // Initialization of input
    }
    for(int j=0 ; j<CRYPTO_KEYBYTES ;j++)
    {
        photon_in[j+CRYPTO_NPUBBYTES] = k[j];                  // Initialization of input
    }
    u8 key[CRYPTO_KEYBYTES];
    memcpy(key, k, CRYPTO_KEYBYTES);
    
    /*################################################################################################################
     
     Enccryption Associate Data Processing Module
     
     ################################################################################################################*/
    if(adlen==0 && mlen == 0)
    {
        photon_in[CRYPTO_BLKBYTES/2] = photon_in[CRYPTO_BLKBYTES/2]^0x02;
        PHOTON_256_Permutation(photon_in);
        for(int j=0; j<CRYPTO_ABYTES;j++)
            c[j] = photon_in[j];
        *clen = CRYPTO_ABYTES;
        return 0;
    }
    if(adlen==0)
    {
        photon_in[CRYPTO_BLKBYTES/2] = photon_in[CRYPTO_BLKBYTES/2]^0x01;
        PHOTON_256_Permutation(photon_in);
        txt(key, photon_in, m , &c[0], mlen, 1);
        
        tag(photon_in);
        for (ul j=0;j<CRYPTO_ABYTES;j++)
        {
            c[mlen+j]= photon_in[j];
            
        }
       
        *clen = mlen+CRYPTO_ABYTES;
        return 0;
    }
    else
    {
        PHOTON_256_Permutation(photon_in);
                                                         // Associated Data processing
        hash(photon_in, ad, adlen, 1, 2);
        /*################################################################################################################
         
         Encryption Message Processing Module
         
         ################################################################################################################*/
        if(mlen!=0)
        {
            PHOTON_256_Permutation(photon_in);
            txt(key, photon_in, m, &c[0], mlen, 1);
        }
        
         tag(photon_in);
        for (int j=0;j<CRYPTO_ABYTES;j++)
        {
            c[mlen+j]= photon_in[j];
           
        }
        *clen = mlen+CRYPTO_ABYTES;
        return 0;
        
    }

    return 0;
}

int crypto_aead_decrypt(
                        unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c, unsigned long long clen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub,
                        const unsigned char *k
                        )
{
    /*################################################################################################################
     
     Decryption Initialization Module
     
     ################################################################################################################*/
    
    if(nsec !=NULL){
        u32 unused[1];                               // using Nsec
        memcpy(unused,nsec,0);
    }
    
    *mlen = clen-CRYPTO_ABYTES;
    
    u8 photon_in[CRYPTO_BLKBYTES] ={0};
    for(int j=0 ; j<CRYPTO_NPUBBYTES ;j++)
    {
        photon_in[j] = npub[j];
                                                           // Initialization of input
    }
    for(int j=0 ; j<CRYPTO_KEYBYTES ;j++)
    {
        photon_in[j+CRYPTO_NPUBBYTES] = k[j];                  // Initialization of input
    }
    u8 key[CRYPTO_KEYBYTES];
    memcpy(key, k, CRYPTO_KEYBYTES);
    
    /*################################################################################################################
     
     Decryption Associate Data Processing Module
     
     ################################################################################################################*/
    if(adlen==0 && * mlen == 0)
    {
        photon_in[CRYPTO_BLKBYTES/2] = photon_in[CRYPTO_BLKBYTES/2]^0x02;
        PHOTON_256_Permutation(photon_in);
        for (int j=0;j<CRYPTO_ABYTES;j++)
        {
            if(c[j]!= photon_in[j])
                return -1;
        }
        return 0;
    }
    if(adlen==0)
    {
        photon_in[CRYPTO_BLKBYTES/2] = photon_in[CRYPTO_BLKBYTES/2]^0x01;
        PHOTON_256_Permutation(photon_in);
        txt(key, photon_in, c , &m[0], *mlen, -1);
        tag(photon_in);
        ul j=0;
        while(j<CRYPTO_ABYTES)
        {
            if(c[*mlen+j]!=photon_in[j])
                return -1;
            j++;
        }
        
        return 0;
    }
    else
    {
        
        PHOTON_256_Permutation(photon_in);
        
        hash(photon_in, ad, adlen, 1, 2);
/*################################################################################################################
         
         Decryption Message Processing Module
         
##############################################################################################################*/
        
        
        if(*mlen!=0)
        {
            PHOTON_256_Permutation(photon_in);
            txt(key, photon_in, c, &m[0], *mlen, -1);
        }
        
        tag(photon_in);
        for (int j=0;j<CRYPTO_ABYTES;j++)
        {
            if(c[*mlen+j]!= photon_in[j])
                return -1;
        }
        return 0;
        
    }
    
    return 0;
}

