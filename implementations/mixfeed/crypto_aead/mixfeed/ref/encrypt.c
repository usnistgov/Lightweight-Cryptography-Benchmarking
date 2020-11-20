//
//  main.c
//  mixfeed
//
//  Created by Bishwajit Chakraborty on 24/02/19.
//  Copyright © 2019 Bishwajit Chakraborty. All rights reserved.
//

#include <stdio.h>
#include <string.h>
#include "api.h"
#include "aes.h"
#include "crypto_aead.h"
#define CRYPTO_BLKBYTES 16
/*#######################################################################################
 
 FeedBack Function
 
 
 #####################################################################################*/
int feed(u8 * Y,const u8 * D, u8 * C, ul dlen ,int a)
{
    u8 A[CRYPTO_BLKBYTES]={0},B[CRYPTO_BLKBYTES]={0};
    for(ul i=0;i<dlen;i++)
        {
            C[i] = D[i] ^ Y[i];
            B[i] =  D[i];
            A[i] = C[i];
        }
    
    if(dlen<CRYPTO_BLKBYTES)
    {
        B[dlen] = 0x01;             //Pading  incomple message/cyphertext block
        A[dlen] = 0x01;
    }
    
    if(a==1)
    {
        for( int i= 0;i<8;i++)
        {
            Y[i] ^=B[i];                          // message input
            Y[i+8] ^= A[i+8];                     // ciphertext input
        }
    }
    else{
        for( int i= 0;i<8;i++)
        {
            Y[i]  ^= A[i];
            Y[i+8] ^= B[i+8];
        }
    }
    
    return 0;
}
/*#######################################################################################
 
 Assosiate data Processing
 
 
 #####################################################################################*/
int proc_ad(u8 * K , u8 * Y , const u8 * D,u8 a, ul dlen )
{
    u8 X[CRYPTO_BLKBYTES];
    u8 C[CRYPTO_BLKBYTES];
    ul blen=CRYPTO_BLKBYTES;
    ul d = (dlen%CRYPTO_BLKBYTES) ? (dlen/CRYPTO_BLKBYTES)+1 : (dlen/CRYPTO_BLKBYTES);
    for(ul i=0;i<d-1;i++)
    {
        
        feed(Y, &D[i*CRYPTO_BLKBYTES], C, blen, 1);
        aes_enc(K, Y, X);
        memcpy(Y,X,CRYPTO_BLKBYTES);
    }
    blen = dlen+CRYPTO_BLKBYTES- d*CRYPTO_BLKBYTES;
    feed(Y, &D[(d-1)*CRYPTO_BLKBYTES], C, blen, 1);
    aes_enc(K, Y, X);
    memcpy(Y,X,CRYPTO_BLKBYTES);
    Y[0]= Y[0]^a;
    aes_enc(K,Y,X);
    memcpy(Y,X,CRYPTO_BLKBYTES);
    return 0;
}
/*#######################################################################################
 
 Message/Ciphertext processing
 
 
 #####################################################################################*/
int proc_txt (u8 * K , u8 * Y, const u8 * D , u8 * C,u8 a, ul dlen, int b)
{
    u8 X[CRYPTO_BLKBYTES];
    ul d = (dlen%CRYPTO_BLKBYTES) ? (dlen/CRYPTO_BLKBYTES)+1 : (dlen/CRYPTO_BLKBYTES);
    for(ul i=0;i<d-1;i++)
    {
        
        feed(Y, &D[i*CRYPTO_BLKBYTES], &C[i*CRYPTO_BLKBYTES], CRYPTO_BLKBYTES, b);
        aes_enc(K, Y, X);
        memcpy(Y, X, CRYPTO_BLKBYTES);
    }
    ul blen = dlen+CRYPTO_BLKBYTES- d*CRYPTO_BLKBYTES;
    feed(Y, &D[(d-1)*CRYPTO_BLKBYTES], &C[(d-1)*CRYPTO_BLKBYTES], blen, b);
    aes_enc(K, Y, X);
    memcpy(Y, X, CRYPTO_BLKBYTES);
    Y[0]= Y[0]^a;
    aes_enc(K, Y, X);
    memcpy(Y, X, CRYPTO_BLKBYTES);
    return 0;
}
/*#######################################################################################
 
 Mix Feed Encryption
 
 
 #####################################################################################*/
int crypto_aead_encrypt(
                        unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec,
                        const unsigned char *npub,
                        const unsigned char *k
                        )
{
     *clen = mlen+CRYPTO_ABYTES;
    if(nsec !=NULL){
        u32 unused[1];
        memcpy(unused,nsec,0);
    }
    u8 key[CRYPTO_BLKBYTES],nonce[CRYPTO_BLKBYTES]={0};
    memcpy(key, k, CRYPTO_KEYBYTES);
    memcpy(&nonce[1],npub,CRYPTO_NPUBBYTES);
    
    if(adlen==0 && mlen ==0)
    {
        nonce[0]= 0x02;
        aes_enc(key, nonce, &c[0]);
        *clen = CRYPTO_BLKBYTES;
        return 0;
    }

    u8 d_a, d_m;
    u8 tw= (adlen==0) ? 0x01 : 0x00;
    
    nonce[0]= tw;
    aes_enc(key, nonce,&c[0]);
    memcpy(key,&c[0],CRYPTO_BLKBYTES);
   
    aes_enc(key, nonce, nonce);
    
    if(adlen!=0)
    {
       
        if ((mlen!=0 && adlen%CRYPTO_BLKBYTES !=0))
            d_a = 0x06;
        else if (mlen!=0 && adlen%CRYPTO_BLKBYTES ==0)
            d_a = 0x04;
        else if (mlen==0 && adlen%CRYPTO_BLKBYTES!=0)
            d_a =0x0e;
        else
            d_a = 0x0c;
        proc_ad(key, nonce, ad, d_a, adlen);
    }
    if(mlen!=0)
    {
        d_m = (mlen%CRYPTO_BLKBYTES) ? 0x0f : 0x0d;
       
        proc_txt(key, nonce, m, &c[0], d_m, mlen,1);
        
    }
    memcpy(&c[mlen], nonce, CRYPTO_BLKBYTES);
   
    return 0;

    
}
/*#######################################################################################
 
 Mix Feed Decryption
 
 
 #####################################################################################*/
int crypto_aead_decrypt(
                        unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec,
                        const unsigned char *c, unsigned long long clen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *npub,
                        const unsigned char *k
                        )
{
    *mlen =clen- CRYPTO_ABYTES;
    if(nsec !=NULL){
        u32 unused[1];
        memcpy(unused,nsec,0);
    }
    u8 key[CRYPTO_KEYBYTES],nonce[CRYPTO_BLKBYTES]={0};
    memcpy(key, k, CRYPTO_KEYBYTES);
    memcpy(&nonce[1], npub, CRYPTO_NPUBBYTES);
    if(adlen==0 && *mlen ==0)
    {
        nonce[0]=0x02;
        aes_enc(key, nonce, nonce);
        if(memcmp(nonce, c, CRYPTO_BLKBYTES)!=0)
            return -1;
       
        return 0;
    }
    
    u8 tw= (adlen==0) ? 0x01 : 0x00;
    nonce[0]= tw;
    aes_enc(key, nonce, key);
   
    aes_enc(key, nonce, nonce);
    
    if(adlen!=0)
    {
        u8 d_a;
        if(*mlen!=0 && adlen%CRYPTO_BLKBYTES !=0)
            d_a = 0x06;
        else if (*mlen!=0 && adlen%CRYPTO_BLKBYTES ==0)
            d_a = 0x04;
        else if (*mlen==0 && adlen%CRYPTO_BLKBYTES!=0)
            d_a =0x0e;
        else
            d_a = 0x0c;
        proc_ad(key, nonce, ad, d_a, adlen);
    }
    if(*mlen!=0)
    {
        u8 d_m = (*mlen%CRYPTO_BLKBYTES) ? 0x0f : 0x0d;
        proc_txt(key, nonce, c, &m[0], d_m, *mlen,-1);
        
    }
    if(memcmp(nonce, &c[*mlen], CRYPTO_ABYTES)!=0)
        return -1;
    return 0;
}
