#include "saef.h"

#include <string.h>
#include <stdint.h>

#include "api.h"
#include "forkskinny.h"

#ifdef SAEF
int saef_encrypt(
    unsigned char *c,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, // nonce, of which the length is specified in api.h
    const unsigned char *k) { // key, of which the length is specified in api.h

    /* Declarations */
    int i, j;
    unsigned char A_j[CRYPTO_BLOCKSIZE], M_j[CRYPTO_BLOCKSIZE];
    unsigned char C0[CRYPTO_BLOCKSIZE], C1[CRYPTO_BLOCKSIZE];
    unsigned char tweakey[TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE];
    unsigned char delta[CRYPTO_BLOCKSIZE];

    uint64_t nbABlocks = adlen / CRYPTO_BLOCKSIZE;
    uint64_t nbMBlocks = mlen / CRYPTO_BLOCKSIZE;

    unsigned char AD[(nbABlocks+1) * CRYPTO_BLOCKSIZE], M[(nbMBlocks+1) * CRYPTO_BLOCKSIZE]; /* Allocate one more block in case padding is needed */

    int last_m_block_size = mlen % CRYPTO_BLOCKSIZE;
    uint8_t ad_incomplete = (adlen != nbABlocks*CRYPTO_BLOCKSIZE) | ((adlen == 0) & (mlen == 0));  /* Boolean flag to indicate whether the final block is complete */
    uint8_t m_incomplete = (last_m_block_size != 0);  /* Boolean flag to indicate whether the final block is complete */

    memset(delta, 0, CRYPTO_BLOCKSIZE); /* Set delta to zero */

    /* Padding of A */
    memcpy(AD, ad, adlen);

    /* Pad A if it is incomplete OR if it is empty and there is no message either*/
    if (ad_incomplete)
        nbABlocks++;

    AD[adlen] = 0x80;

    for (i = adlen+1; i < nbABlocks*CRYPTO_BLOCKSIZE; i++)
        AD[i] = 0x00;

    /* Pad M if it is incomplete */
    if (last_m_block_size != 0)
        nbMBlocks++;

    memcpy(M,m,mlen);

    M[mlen] = 0x80;

    for (i = mlen+1; i < nbMBlocks*CRYPTO_BLOCKSIZE; i++)
        M[i] = 0x00;

    /* Construct baseline tweakey: key part remains unchanged throughout the execution. Initialize the flag part of the tweakey state to zero. */
    
    // Key
    memcpy(tweakey,k,CRYPTO_KEYBYTES);
    
    // Nonce
    memset(&tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES], 0, CRYPTO_TWEAKEYSIZE-CRYPTO_KEYBYTES-CRYPTO_NPUBBYTES);

    // For ForkSkinny-128-192, the tweakey state needs to be zero-padded.
    for (i = CRYPTO_TWEAKEYSIZE; i < TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE; i++)
        tweakey[i] = 0; 

    /* Processing associated data */
    
    for (j = 1; j <= nbABlocks; j++) {

        /* Load next block */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            A_j[i] = AD[(j-1)*CRYPTO_BLOCKSIZE+i] ^ delta[i]; // Add delta too

        /* Build tweakey */
        if (j == 1) {
        	memcpy(&tweakey[CRYPTO_KEYBYTES], npub, CRYPTO_NPUBBYTES); // First invocation: T = N | 1000
            tweakey[CRYPTO_TWEAKEYSIZE-1] = 0x08;
        } 
        else {
        	memset(&tweakey[CRYPTO_KEYBYTES], 0, CRYPTO_NPUBBYTES); // T = 0* | flags (no nonce)
            tweakey[CRYPTO_TWEAKEYSIZE-1] = 0x00;
        }
        if ((j==nbABlocks) & ad_incomplete) {
            if (mlen == 0) // noM == 1
                tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x07; // Flag 111
            else
                tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x03; // Flag 011
        }
        else if (j==nbABlocks){
            if (mlen == 0) // noM == 1
                tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x06; // Flag 110
            else
                tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x02; // Flag 010
        }
        else 
            tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x00; // Flag 000
            
        /* ForkEncrypt */
        forkEncrypt(C0, delta, A_j, tweakey, ENC_C1);
    }

    if (mlen == 0) /* If message is empty, copy tag to output buffer */
        memcpy(c, delta, CRYPTO_BLOCKSIZE);

    /* Processing message */
    
    for (j = 1; j <= nbMBlocks; j++) {

        /* Load next block */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            M_j[i] = M[(j-1)*CRYPTO_BLOCKSIZE+i] ^ delta[i];

        /* Build tweakey */
        if ((j == 1) & (adlen == 0)) {
        	memcpy(&tweakey[CRYPTO_KEYBYTES], npub, CRYPTO_NPUBBYTES); // If there was no associated data, first invocation: T = N | 1000
            tweakey[CRYPTO_TWEAKEYSIZE-1] = 0x08;
        } 
        else {
        	memset(&tweakey[CRYPTO_KEYBYTES], 0, CRYPTO_NPUBBYTES);  // T = 0* | flags (no nonce)
            tweakey[CRYPTO_TWEAKEYSIZE-1] = 0x00;
        }

        if ((j==nbMBlocks) & m_incomplete)
            tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x05; // Flag 101

        else if (j==nbMBlocks)
            tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x04; // Flag 100

        else
            tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x01; // Flag 001
            
        /* ForkEncrypt */
        forkEncrypt(C0, C1, M_j, tweakey, ENC_BOTH);

        /* Move C0 xor delta to ciphertext output */ 
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            c[(j-1)*CRYPTO_BLOCKSIZE+i] = C0[i] ^ delta[i];

        /* C1 is the new delta */
        memcpy(delta, C1, CRYPTO_BLOCKSIZE);
    }
    
    /* Delta contains the final tag. Move it to the ciphertext output. */
    if (m_incomplete)
        for (i = 0; i < last_m_block_size; i++)
            c[mlen+CRYPTO_BLOCKSIZE - last_m_block_size+i] = delta[i];
    else
    	memcpy(&c[mlen], delta, CRYPTO_BLOCKSIZE);

    return 0;
}

int saef_decrypt(
	unsigned char *m,
	const unsigned char *c,unsigned long long clen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k){


    /* Declarations */
    int i, j;
    uint8_t res = 0;
    unsigned char A_j[CRYPTO_BLOCKSIZE], C_j[CRYPTO_BLOCKSIZE], redundancy[CRYPTO_BLOCKSIZE];
    unsigned char P[CRYPTO_BLOCKSIZE], C0[CRYPTO_BLOCKSIZE], C1[CRYPTO_BLOCKSIZE];
    unsigned char tweakey[TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE];
    unsigned char delta[CRYPTO_BLOCKSIZE];

    uint64_t nbABlocks = adlen / CRYPTO_BLOCKSIZE;
    uint64_t nbMBlocks = clen / CRYPTO_BLOCKSIZE - 1;
    
    unsigned char AD[(nbABlocks+1) * CRYPTO_BLOCKSIZE]; /* Allocate one more block in case padding is needed */

    uint8_t ad_incomplete = (adlen != nbABlocks*CRYPTO_BLOCKSIZE) | ((adlen == 0) & (clen == CRYPTO_BLOCKSIZE));  /* Boolean flag to indicate whether the final block is complete */
    uint8_t c_incomplete = (clen % CRYPTO_BLOCKSIZE != 0);  /* Boolean flags to indicate whether the final block is complete */
    int last_c_block_size = clen % CRYPTO_BLOCKSIZE;

    memset(delta, 0, CRYPTO_BLOCKSIZE); /* Set delta to zero */

    /* Padding of A */
    memcpy(AD, ad, adlen);

    /* Pad A if it is incomplete OR if it is empty and there is no message either*/
    if (ad_incomplete)
        nbABlocks++;

    AD[adlen] = 0x80;

    for (i = adlen+1; i < nbABlocks*CRYPTO_BLOCKSIZE; i++)
        AD[i] = 0x00;

    /* Message was padded */
    if (c_incomplete)
        nbMBlocks++; 

    /* Construct baseline tweakey: key part remains unchanged throughout the execution. Initialize the flag part of the tweakey state to zero. */
    
    // Key
    memcpy(tweakey, k, CRYPTO_KEYBYTES);
    
    // Flags and counter to zero
    memset(&tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES], 0, CRYPTO_TWEAKEYSIZE-CRYPTO_KEYBYTES-CRYPTO_NPUBBYTES);

    // For ForkSkinny-128-192, the tweakey state needs to be zero-padded.
    for (i = CRYPTO_TWEAKEYSIZE; i < TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE; i++)
        tweakey[i] = 0; 

    /* Processing associated data */
    
    for (j = 1; j <= nbABlocks; j++) {

        /* Load next block */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            A_j[i] = AD[(j-1)*CRYPTO_BLOCKSIZE+i] ^ delta[i]; // Add delta too

        /* Build tweakey */
        if (j == 1) {
        	memcpy(&tweakey[CRYPTO_KEYBYTES], npub, CRYPTO_NPUBBYTES); // First invocation: T = N | 1000
            tweakey[CRYPTO_TWEAKEYSIZE-1] = 0x08;
        } 
        else {
        	memset(&tweakey[CRYPTO_KEYBYTES], 0, CRYPTO_NPUBBYTES); // T = 0* | flags (no nonce)
            tweakey[CRYPTO_TWEAKEYSIZE-1] = 0x00;
        }
        if ((j==nbABlocks) & ad_incomplete) {
            if (clen - CRYPTO_BLOCKSIZE == 0) // noM == 1
                tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x07; // Flag 111
            else
                tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x03; // Flag 011
        }
        else if (j==nbABlocks){
            if (clen - CRYPTO_BLOCKSIZE == 0) // noM == 1
                tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x06; // Flag 110
            else
                tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x02; // Flag 010
        }
        else 
            tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x00; // Flag 000
            
        /* ForkEncrypt */
        forkEncrypt(C0, delta, A_j, tweakey, ENC_C1);
    }
    
    if (clen == CRYPTO_BLOCKSIZE) /* If message is empty, copy tag to output buffer */
        memcpy(C1, delta, CRYPTO_BLOCKSIZE);

    /* Process ciphertext */
    
    for (j = 1; j <= nbMBlocks; j++) {

        /* Load next block */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++) 
            C_j[i] = c[(j-1)*CRYPTO_BLOCKSIZE+i] ^ delta[i];
        
        /* Build tweakey */
        if ((j == 1) & (adlen == 0)) {
        	memcpy(&tweakey[CRYPTO_KEYBYTES], npub, CRYPTO_NPUBBYTES); // If there was no associated data, first invocation: T = N | 1000
            tweakey[CRYPTO_TWEAKEYSIZE-1] = 0x08;
        } 
        else {
        	memset(&tweakey[CRYPTO_KEYBYTES], 0, CRYPTO_NPUBBYTES); // T = 0* | flags (no nonce)
            tweakey[CRYPTO_TWEAKEYSIZE-1] = 0x00;
        }

        if ((j==nbMBlocks) & c_incomplete)
            tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x05; // Flag 101
        else if (j==nbMBlocks)
            tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x04; // Flag 100
        else 
            tweakey[CRYPTO_TWEAKEYSIZE-1] ^= 0x01; // Flag 001

        /* ForkInvert */
        forkInvert(P, C1, C_j, tweakey, 0, INV_BOTH);

        
        /* Final incomplete block */
        if ((j==nbMBlocks) & c_incomplete) {
            for (i = 0; i < last_c_block_size; i++) /* Move partial P block to plaintext output */
                m[(j-1)*CRYPTO_BLOCKSIZE+i] = P[i] ^ delta[i];
            for (i = 0; i < CRYPTO_BLOCKSIZE-last_c_block_size; i++)
                redundancy[i] = P[last_c_block_size+i] ^ delta[last_c_block_size+i];
        }
        /* Full block */
        else{
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) /* Move full P block to plaintext output */
                m[(j-1)*CRYPTO_BLOCKSIZE+i] = P[i] ^ delta[i];
        }
        
        /* C1 is the new delta */
        memcpy(delta, C1, CRYPTO_BLOCKSIZE);
    }

    /* Check if the tag (C1) is correct, if incorrect output error (denoted by -1) */

    /* Does the tag part match? */
    if (c_incomplete){
    	if(memcmp(delta, &c[clen-last_c_block_size], last_c_block_size) != 0)
    		res = -1;
    }
    else{
    	if( memcmp(delta, &c[clen-CRYPTO_BLOCKSIZE], CRYPTO_BLOCKSIZE)!=0)
    		res = -1;
    }

    /* If incomplete: does the plaintext redundancy match? */
    if (c_incomplete){
        if (redundancy[0] != 0x80)
            res = -1;
        for (i = 1; i < CRYPTO_BLOCKSIZE-last_c_block_size; i++) 
            if (redundancy[i] != 0x00)
                res = -1;
    }

    return res;
}
#endif
