/*
SUNDAE AEAD scheme
Prepared by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 25 Mar 2019
*/
#include <stdint.h>
#include <stdlib.h>

#include "gift128.h"

void doubling(uint8_t* A){
/*doubling uses x^{16} + x^5 + x^3 + x + 1 at byte level*/
uint8_t ADD=A[0];
int i;
for(i=0; i<15; i++){
    A[i] = A[i+1];
}
A[15] = ADD;
A[14] ^= ADD;
A[12] ^= ADD;
A[10] ^= ADD;

return;
}

int sundae_enc(const uint8_t* N, unsigned long long Nlen,
                const uint8_t* A, unsigned long long Alen,
                const uint8_t* M, unsigned long long Mlen,
                const uint8_t K[16],
                uint8_t* C,
                int outputTag){
/*
member 1 takes 96-bit nonce   (Nlen = 12)
member 2 does not take in nonce (Nlen = 0)
member 3 takes 128-bit nonce  (Nlen = 16)
member 4 takes 64-bit nonce   (Nlen = 8)
*/

/*
return -1 if invalid parameter
return 0 if encryption successful
*/

unsigned long long i;
const uint8_t* startM = M;
uint8_t V[16],*AS;
uint8_t ib[16]={};

if(Alen!=0) ib[0] |= 0x80;
if(Mlen!=0) ib[0] |= 0x40;;

if(Nlen==16) ib[0] |= 0xb0;
else if(Nlen==12) ib[0] |= 0xa0;
else if(Nlen==8) ib[0] |= 0x90;
else if(Nlen!=0) return -1; /*Invalid tag length*/

/*Prepend N to A*/
unsigned long long ADlen = Alen+Nlen;

uint8_t* AD = (uint8_t*)malloc(ADlen*sizeof(uint8_t));
AS=AD;

for(i=0; i<Nlen; i++){
    AD[i] = N[i];
}
for(i=0; i<Alen; i++){
    AD[Nlen+i] = A[i];
}

//uint8_t* V = (uint8_t*)malloc(16*sizeof(uint8_t));

/*Initialisation*/
giftb128(ib,K,V);

/*Process AD*/
while(ADlen>16){
    for(i=0; i<16; i++){
        V[i]^=AD[i];
    }

    giftb128(V,K,V);

    AD+=16;
    ADlen-=16;
}

if(ADlen==16){
    for(i=0; i<16; i++){
        V[i]^=AD[i];
    }

    doubling(V);
    doubling(V);
    giftb128(V,K,V);
}
else if(ADlen>0){
    for(i=0; i<ADlen; i++){
        V[i]^=AD[i];
    }

    /*10*-padding*/
    V[ADlen]^=0x80;

    doubling(V);
    giftb128(V,K,V);
}
AD=AS;
free(AD);
/*Process M*/
unsigned long long Clen = Mlen;
while(Mlen>16){
    for(i=0; i<16; i++){
        V[i]^=M[i];
    }

    giftb128(V,K,V);

    M+=16;
    Mlen-=16;
}

if(Mlen==16){
    for(i=0; i<16; i++){
        V[i]^=M[i];
    }

    doubling(V);
    doubling(V);
    giftb128(V,K,V);
}
else if(Mlen>0){
    for(i=0; i<Mlen; i++){
        V[i]^=M[i];
    }

    /*10*-padding*/
    V[Mlen]^=0x80;

    doubling(V);
    giftb128(V,K,V);
}

/*output the Tag*/
for(i=0; i<16; i++){
    C[i]=V[i];
}

if(outputTag) return 0; /*for decryption, early termination*/

C+=16;

/*output C*/
M = startM;
while(Clen>=16){
    giftb128(V,K,V);

    for(i=0; i<16; i++){
        C[i]=M[i]^V[i];
    }

    Clen-=16;
    C+=16;
    M+=16;
}

if(Clen>0){
    giftb128(V,K,V);

    for(i=0; i<Clen; i++){
        C[i]=M[i]^V[i];
    }
}

return 0;}


int sundae_dec(const uint8_t* N, unsigned long long Nlen,
                const uint8_t* A, unsigned long long Alen,
                uint8_t* M,
                const uint8_t K[16],
                const uint8_t* C, unsigned long long Clen){
/*
-1 for authentication fail
-2 for invalid tag length
*/
uint8_t Tprime[16],V[16],T[16];
unsigned long long i;

if(Clen<16) return -2; /*invalid tag length*/

uint8_t* startM=M;

//uint8_t* V = (uint8_t*)malloc(16*sizeof(uint8_t));
//uint8_t* T = (uint8_t*)malloc(16*sizeof(uint8_t));

/*Extract the Tag*/
for(i=0; i<16; i++){
    V[i] = C[i];
    T[i] = C[i];
}

C+=16;
Clen-=16;

unsigned long long Mlen = Clen;

/*Decrypt C*/
while(Clen>=16){
    giftb128(V,K,V);

    for(i=0; i<16; i++){
        M[i]=C[i]^V[i];
    }

    Clen-=16;
    M+=16;
    C+=16;
}

if(Clen>0){
    giftb128(V,K,V);

    for(i=0; i<Clen; i++){
        M[i]=C[i]^V[i];
    }
}

/*Generate T*/
//uint8_t* Tprime = (uint8_t*)malloc(16*sizeof(uint8_t));
sundae_enc(N,Nlen,A,Alen,startM,Mlen,K,Tprime,1);

/*Match tags*/
for(i=0; i<16; i++){
    if(T[i] != Tprime[i]){
        return -1;
    }
}
return 0;}
