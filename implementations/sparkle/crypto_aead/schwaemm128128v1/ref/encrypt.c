///////////////////////////////////////////////////////////////////////////////
// encrypt.c: C implementation of the SCHWAEMM AEAD algorithm                //
// This file is part of the NIST's submission "Schwaemm and Esch: Lightweight//
// Authenticated Encryption and Hashing using the Sparkle Permutation Family //
// Version 1.0.0 (2019-03-29), see <http://www.cryptolux.org/> for updates.  //
// Authors: The SPARKLE Group (C. Beierle, A. Biryukov, L. Cardoso dos       //
// Santos, J. Groszschaedl, L. Perrin, A. Udovenko, V. Velichkov, Q. Wang).  //
// License: GPLv3 (see LICENSE file), other licenses available upon request. //
// Copyright (C) 2019 University of Luxembourg <http://www.uni.lu/>.         //
// ------------------------------------------------------------------------- //
// This program is free software: you can redistribute it and/or modify it   //
// under the terms of the GNU General Public License as published by the     //
// Free Software Foundation, either version 3 of the License, or (at your    //
// option) any later version. This program is distributed in the hope that   //
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied     //
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  //
// GNU General Public License for more details. You should have received a   //
// copy of the GNU General Public License along with this program. If not,   //
// see <http://www.gnu.org/licenses/>.                                       //
///////////////////////////////////////////////////////////////////////////////


// should be compiled with
// -std=c99 -Wall -Wextra -Wshadow -fsanitize=address,undefined -O2

// gencat_aead.c shall be used to generate the test vector output file. The test vector output
// file shall be provided in the corresponding crypto_aead/[algorithm]/ directory

#include "api.h"
#include "crypto_aead.h"
#include "stdint.h"
#include "schwaemmconfig.h"
#include "util.h"
#include "string.h" //for memcpy

#ifdef _DEBUG
#include "stdio.h"
#endif

/*___________________________Helper debug functions___________________________*/
#ifdef _DEBUG
    void pstate(uint32_t *state){
        for(int i=0; i<WORD(STATESIZE); i++){
            printf("%02d:%08x ", i, state[i]);
            if(i%4==3) printf("\n");
        }
        printf("\n");
    }

    void countstate(uint32_t *state){
        for(int i=0; i<WORD(STATESIZE); i++)
            state[i]=i;
    }

    void p8state(uint32_t *state){
        u8 *s;
        s=(u8 *)(state);
        for(int i=0; i<BYTE(STATESIZE); i++){
            printf("%02x ", s[i]);
            if(i%4==3) printf(" ");
            //if (i%16==15) printf("\n");
        }
        printf("\n");
    }
#endif

/*____________________________Low Level Functions_____________________________*/

/*
 The initialize function loads nonce and key into the internal state, and
 executes a SPARKLE permutation.
*/
INLINE void initialize(uint32_t *state, const u8 *key, const u8 *nonce){
    //load nonce into state.
    for(int i=0; i<CRYPTO_NPUBWORDS; i++)
        state[i]=load32((u8 *)nonce+(4*i));
    //load key into state.
    for(int i=0; i<CRYPTO_KEYWORDS; i++)
        state[i+CRYPTO_NPUBWORDS]=load32((u8 *)(key)+(4*i));
    //Apply permutation to state
    sparklePermutation(state, STEPSBIG);
}

/*
processAD absorbs additional data into the sponge.
*/
INLINE void  processAD(uint32_t *state, const u8 *ad,  u64 adlen){
    if(adlen != 0){
        int constA = (adlen % BYTE(RATE) != 0) ? PADADCONST : NOPADADCONST;
        //absorption loop
        while (adlen > BYTE(RATE)){
            rho1(state, (uint32_t *)ad);
            RATEWHITENING(state);
            sparklePermutation(state, STEPSSLIM);
            ad += BYTE(RATE);
            adlen -= BYTE(RATE);
        }
        //pad lBlock
        uint32_t lBlock[WORD(RATE)];
        pad(lBlock, (u8*)(ad), (u8)(adlen));

        //process last block
        rho1(state, lBlock);
        INJECTCONST(state, constA);
        RATEWHITENING(state);
        sparklePermutation(state, STEPSBIG);
    }
}
/*
encryptPT absorbs message blocks of size RATE, and generates the respective
ciphertext blocks. At the end of the encryption operation, an authentication tag
is generated and appended to the end of the cyphertext. It is expected that the
memory allocated for the ciphertext is CRYPTO_ABYTES larger than the message buffer
*/
INLINE void  encryptPT(uint32_t *state, u8 *c, u64 *clen, const u8 *m, u64 mlen, const unsigned char *k){
    *clen = mlen + CRYPTO_ABYTES;
    if (mlen != 0){
        int constM = (mlen % BYTE(RATE) != 0) ? PADPTCONST : NOPADPTCONST;

        /*main encryption loop*/
        while (mlen > BYTE(RATE)){
            // $C_j \leftarrpow$C_j \leftarrow \rho_2(S_L , M_j)$
            memcpy(c, m, BYTE(RATE));
            rho2((uint32_t *)(c), state);
            // $S_L \parallel S_r \leftarrow \text{SparkleRATE}_{slim} (\rho_1 (S_L, M_j) \parallel S_R)$
            rho1(state, (uint32_t *)(m));
            RATEWHITENING(state);
            sparklePermutation(state, STEPSSLIM);
            m += BYTE(RATE);
            c += BYTE(RATE);
            mlen -= BYTE(RATE);
        }
        //pad last block
        uint32_t lBlock[WORD(RATE)];
        pad(lBlock, (u8 *)(m), mlen);

        //process last lBlock
        // $C_{\ell_{M-1}} \leftarrow \text{trunc}_t(\rho_2(S_L, M_{\ell_{M-1}}))$
        rho2(lBlock, state);
        memcpy(c, lBlock, mlen);
        // $S_L \parallel S_R \leftarrow \text{SparkleRATE}_{big}(\rho_1 (S_L, M_{\ell_{M-1}}) \parallel S_R \oplus \text{Const}_M))$
        pad(lBlock, (u8 *)(m), mlen);
        rho1(state, lBlock);
        INJECTCONST(state, constM);
        RATEWHITENING(state);
        sparklePermutation(state, STEPSBIG);
    }
        //write tag to ciphertext
        memcpy(c+mlen, (u8*)(state)+BYTE(RATE), CRYPTO_ABYTES);

        for(int i=0; i<CRYPTO_ABYTES; i++){
            (c+mlen)[i] ^= k[i];
        }
}
/*
Simple constant-time comparison. Returns 0 equal inputs. Considers that the
arguments are CRYPTO_ABYTES long.
*/
INLINE int verifyTag(uint32_t *state, u8 *tag){
    //constant time. 0 for sucess, -1 for diffence
    u8 *tag1;
    tag1=(u8*)(state);
    tag1 += BYTE(RATE);
    unsigned int r = 0;
    for (int i=0; i<CRYPTO_ABYTES; i++)
        r |= tag1[i] ^ tag[i];
    return (((r-1) >> 8) &1)-1;
}
/*
The decryptCT function processes a cyphertext of mlen+CRYPTO_ABYTES and generates
the respective plaintext. It also verifies the authentication tag on the last
CRYPTO_ABYTES bytes of the buffer *c. If the tag is valid, the function returns 0.
If it fails, the function zeros the message buffer and returns -1.
*/
INLINE  int  decryptCT(uint32_t *state, u8 *m, u64 *mlen, const u8 *c, u64 clen,  const unsigned char *k){
    clen -= CRYPTO_ABYTES;
    *mlen = clen;
    if (clen != 0){
        //main decryption loop
        while (clen > BYTE(RATE)){
            //$M_j \leftarrow p^\prime_2 (S_L, C_j)$
            for(int i=0; i<BYTE(RATE); i++)
                m[i]=c[i];
            rho2((uint32_t*)(m), state);
            //$S_L \parallel S_R \leftarrow \text{SparkleRATE}_{slim}(\rho^\prime_1(S_L, C_j) \parallel S_R)$
            rhop1(state, (uint32_t*)(c));
            RATEWHITENING(state);
            sparklePermutation(state, STEPSSLIM);
            //Move pointers
            clen -= BYTE(RATE); m += BYTE(RATE); c += BYTE(RATE);
        }
        //decrypt last block
        uint32_t lBlock[WORD(RATE)];
        pad(lBlock, (u8 *)(c), clen);
        rho2(lBlock, state);
        memcpy(m, lBlock, clen);
        //Finalization
        if (clen < BYTE(RATE)){
            pad(lBlock, m, clen);
            rho1(state, lBlock);
            INJECTCONST(state, PADPTCONST);
            RATEWHITENING(state);
            sparklePermutation(state, STEPSBIG);
        }
        else {
            rhop1(state, (uint32_t *)(c));
            INJECTCONST(state, NOPADPTCONST);
            RATEWHITENING(state);
            sparklePermutation(state, STEPSBIG);
        }
    }
    c+=clen; //move c to point to tag.

    for(int i=0; i<CRYPTO_ABYTES; i++){ //xor key to tag location on state
        ((uint8_t *)(state) + BYTE(RATE) )[i] ^= k[i];
    }

    if (verifyTag(state, (u8 *)(c)) == 0)
        return 0;
    else{
        #ifndef _DEBUG
            //Zero generated plaintext in case of failure to authenticate
            for (unsigned long long i=0; i < *mlen; i++) m[i]=0;
        #endif
        return -1;
    }
}


/*_____________________________Main API functions_____________________________*/
//nsec is kept for compatibility with SUPERCOP, but is not used.
int crypto_aead_encrypt(
unsigned char *c,unsigned long long *clen,
const unsigned char *m,unsigned long long mlen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *nsec,
const unsigned char *npub,
const unsigned char *k
)
{
    #ifdef _DEBUG
        uint32_t state[WORD(STATESIZE)]={0};
    #else
        uint32_t state[WORD(STATESIZE)];
    #endif
    initialize(state, k, npub);
    processAD(state, ad, adlen);
    encryptPT(state, c, clen, m, mlen, k);

    return 0;
}

int crypto_aead_decrypt(
unsigned char *m,unsigned long long *mlen,
unsigned char *nsec,
const unsigned char *c,unsigned long long clen,
const unsigned char *ad,unsigned long long adlen,
const unsigned char *npub,
const unsigned char *k
)
{
	//returns -1 if the ciphertext is not valid
    int decSucess;
    uint32_t state[WORD(STATESIZE)];
    initialize(state, k, npub);
    processAD(state, ad, adlen);
    decSucess = decryptCT(state, m, mlen, c, clen, k);
    return decSucess;
}
