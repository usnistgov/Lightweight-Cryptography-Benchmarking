#include "paef.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "api.h"
#include "forkskinny.h"

#ifdef PAEF
#define MAX_COUNTER_BITS ((((CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES) << 3) - 3))

int paef_encrypt(
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
    unsigned char running_tag[CRYPTO_BLOCKSIZE];

    uint64_t nbABlocks = adlen / CRYPTO_BLOCKSIZE;
    uint64_t nbMBlocks = mlen / CRYPTO_BLOCKSIZE;

    unsigned char AD[(nbABlocks+1)*CRYPTO_BLOCKSIZE], M[(nbMBlocks+1)*CRYPTO_BLOCKSIZE]; /* Allocate one more block in case padding is needed */

    
    int last_m_block_size = mlen % CRYPTO_BLOCKSIZE;
    uint8_t ad_incomplete = (adlen != nbABlocks*CRYPTO_BLOCKSIZE) | ((adlen == 0) & (mlen == 0));  /* Boolean flag to indicate whether the final block is complete */
    uint8_t m_incomplete = (last_m_block_size != 0);  /* Boolean flag to indicate whether the final block is complete */

    /* Check if ad length not too large */
    if (nbABlocks > ((uint64_t)1 << MAX_COUNTER_BITS)){
        printf("Error: AD too long! Terminating. \n");
        return -1;
    }

    /* Check if message length not too large */
    if (nbMBlocks > ((uint64_t)1 << MAX_COUNTER_BITS)){
        printf("Error: M too long! Terminating. \n");
        return -1;
    }

    memset(running_tag, 0, CRYPTO_BLOCKSIZE); /* Set running tag to zero */

    /* Padding of A */
    memcpy(AD,ad,adlen);

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


    /* Construct baseline tweakey: key and nonce part remains unchanged throughout the execution. Initialize the remainder of the tweakey state to zero. */
    
    // Key
    memcpy(tweakey,k,CRYPTO_KEYBYTES);

    // Nonce
    memcpy(&tweakey[CRYPTO_KEYBYTES],npub,CRYPTO_NPUBBYTES);

    // Flags and counter to zero
    memset(&tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES], 0,  CRYPTO_TWEAKEYSIZE-CRYPTO_KEYBYTES-CRYPTO_NPUBBYTES);

    // For ForkSkinny-128-192 and ForkSkinny-128-288, the tweakey state needs to be zero-padded.
    for (i = CRYPTO_TWEAKEYSIZE; i < TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE; i++)
        tweakey[i] = 0; 

    /* Processing associated data */
    
    for (j = 1; j <= nbABlocks; j++) {

        /* Load next block */
    	memcpy(A_j, &AD[(j-1)*CRYPTO_BLOCKSIZE], CRYPTO_BLOCKSIZE);

        /* Tweakey flags */
        if ((j==nbABlocks) & ad_incomplete)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x60; // Flag 011

        else if (j==nbABlocks)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x20; // Flag 001

        else
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x00; // Flag 000
            
        /* Counter */
        for (i = 1; i < CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES; i++)
            tweakey[CRYPTO_TWEAKEYSIZE-i] = (j >> 8*(i-1)) & 0xff;
        
        /* Special treatment for the tweak byte that is shared between the counter and the flags */
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= ((uint64_t) j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        /* ForkEncrypt */
        forkEncrypt(C0, C1, A_j, tweakey, ENC_C1);

        /* Update running tag */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            running_tag[i] ^= C1[i];
    }

    if (mlen == 0) /* If message is empty, copy tag to output buffer */
    	memcpy(c,running_tag,CRYPTO_BLOCKSIZE);

    /* Processing message */
    
    for (j = 1; j <= nbMBlocks; j++) {

        /* Load next block */
    	memcpy(M_j,&M[(j-1)*CRYPTO_BLOCKSIZE],CRYPTO_BLOCKSIZE);

        /* Tweakey flags */
        if ((j==nbMBlocks) & m_incomplete)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0xE0; // Flag 111
        
        else if (j==nbMBlocks)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0xA0; // Flag 101

        else
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x80; // Flag 100
            
        /* Counter */
        for (i = 1; i < CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES; i++)
            tweakey[CRYPTO_TWEAKEYSIZE-i] = (j >> 8*(i-1)) & 0xff;
        
        /* Special treatment for the tweak byte that is shared between the counter and the flags */
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= ((uint64_t) j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        /* ForkEncrypt */
        forkEncrypt(C0, C1, M_j, tweakey, ENC_BOTH);

        /* Final incomplete block */
        if ((j==nbMBlocks) & m_incomplete){
            /* Add running tag to C0 and move to ciphertext output */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) 
                c[(j-1)*CRYPTO_BLOCKSIZE+i] = C0[i] ^ running_tag[i];

            /* C1 now contains the tag. Move it to ciphertext output */
            memcpy(&c[mlen+CRYPTO_BLOCKSIZE-last_m_block_size], C1, last_m_block_size);
        }

        /* Final complete block */
        else if (j==nbMBlocks){
            /* Add running tag to C0 and move to ciphertext output */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) 
                c[(j-1)*CRYPTO_BLOCKSIZE+i] = C0[i] ^ running_tag[i];

            /* C1 now contains the tag. Move it to ciphertext output */
            memcpy(&c[mlen],C1,CRYPTO_BLOCKSIZE);
        }

        /* Non-final block */
        else{
            /* C0 contains ciphertext block. Move it to ciphertext output */
        	memcpy(&c[(j-1)*CRYPTO_BLOCKSIZE],C0,CRYPTO_BLOCKSIZE);

            /* Update running tag with C1 value */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
                running_tag[i] ^= C1[i];
        }

    }

    return 0; // all is well
}


int paef_decrypt(
	unsigned char *m,
	const unsigned char *c,unsigned long long clen,
	const unsigned char *ad,unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k){


    /* Declarations */
    int i,j;
    uint8_t res = 0;
    unsigned char running_tag[CRYPTO_BLOCKSIZE];
    unsigned char tweakey[TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE];
    unsigned char P[CRYPTO_BLOCKSIZE], C0[CRYPTO_BLOCKSIZE], C1[CRYPTO_BLOCKSIZE];

    uint64_t nbABlocks = adlen / CRYPTO_BLOCKSIZE;
    uint64_t nbMBlocks = clen / CRYPTO_BLOCKSIZE - 1;
    
    unsigned char A_j[CRYPTO_BLOCKSIZE], C_j[CRYPTO_BLOCKSIZE];
    unsigned char AD[(nbABlocks+1) * CRYPTO_BLOCKSIZE]; /* Allocate one more block in case padding is needed */

    uint8_t ad_incomplete = (adlen != nbABlocks*CRYPTO_BLOCKSIZE) | ((adlen == 0) & (clen == CRYPTO_BLOCKSIZE));  /* Boolean flag to indicate whether the final block is complete */
    uint8_t c_incomplete = (clen % CRYPTO_BLOCKSIZE != 0);  /* Boolean flags to indicate whether the final block is complete */
    int last_c_block_size = clen % CRYPTO_BLOCKSIZE;


    /* Check if ad length not too large */
    if (nbABlocks >((uint64_t)1 << MAX_COUNTER_BITS)){
        printf("Error: AD too long! Terminating. \n");
        return -1;
    }

    /* Check if message length not too large */
    if (nbMBlocks > ((uint64_t)1 << MAX_COUNTER_BITS)){
        printf("Error: M too long! Terminating. \n");
        return -1;
    }

    memset(running_tag, 0, CRYPTO_BLOCKSIZE); /* Set running tag to zero */

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

    /* Construct baseline tweakey: key and nonce part remains unchanged throughout the execution. Initialize the remainder of the tweakey state to zero. */
    
    // Key
    memcpy(tweakey, k, CRYPTO_KEYBYTES);
    
    // Nonce
    memcpy(&tweakey[CRYPTO_KEYBYTES],npub, CRYPTO_NPUBBYTES);

    // Flags and counter to zero
 	memset(&tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES], 0,  CRYPTO_TWEAKEYSIZE-CRYPTO_KEYBYTES-CRYPTO_NPUBBYTES);

    // For ForkSkinny-128-192 and ForkSkinny-128-288, the tweakey state needs to be zero-padded.
    for (i = CRYPTO_TWEAKEYSIZE; i < TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE; i++)
        tweakey[i] = 0; 

    /* Processing associated data */
    
    for (j = 1; j <= nbABlocks; j++) {

        /* Load next block */
    	memcpy(A_j,&AD[(j-1)*CRYPTO_BLOCKSIZE],CRYPTO_BLOCKSIZE);

        /* Tweakey flags */
        if ((j==nbABlocks) & ad_incomplete)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x60; // Flag 011

        else if (j==nbABlocks)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x20; // Flag 001
        
        else
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x00; // Flag 000
        
        /* Counter */
        for (i = 1; i < CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES; i++) 
            tweakey[CRYPTO_TWEAKEYSIZE-i] = (j >> 8*(i-1)) & 0xff;
        
        
        /* Special treatment for the tweak byte that is shared between the counter and the flags */
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= ((uint64_t) j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        /* ForkEncrypt */
        forkEncrypt(C0, C1, A_j, tweakey, ENC_C1);

        /* Update running tag */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            running_tag[i] ^= C1[i];
    }

    if (clen == CRYPTO_BLOCKSIZE) /* If message is empty, copy tag to output buffer */
    	memcpy(C1,running_tag,CRYPTO_BLOCKSIZE);

    /* Process ciphertext */
    
    for (j = 1; j <= nbMBlocks; j++) {
        
        /* Final ciphertext block: XOR with running tag*/
        if (j==nbMBlocks)
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
                C_j[i] = c[(j-1)*CRYPTO_BLOCKSIZE+i] ^ running_tag[i]; // C0 is running tag xor C*
        
        /* Non-final ciphertext block*/
        else 
        	memcpy(C_j,&c[(j-1)*CRYPTO_BLOCKSIZE],CRYPTO_BLOCKSIZE);

        /* Tweakey flags */
        if ((j==nbMBlocks) & c_incomplete)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0xE0; // Flag 111
        
        else if (j==nbMBlocks)
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0xA0; // Flag 101
        
        else 
            tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] = 0x80; // Flag 100
        
            
        /* Counter */
        for (i = 1; i < CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES; i++)
            tweakey[CRYPTO_TWEAKEYSIZE-i] = (j >> 8*(i-1)) & 0xff;
        
        /* Special treatment for the tweak byte that is shared between the counter and the flags */
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= ((uint64_t) j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        /* ForkInvert */
        forkInvert(P, C1, C_j, tweakey, 0, INV_BOTH);


        /* Final incomplete block */
        if ((j==nbMBlocks) & c_incomplete)
        	memcpy(&m[(j-1)*CRYPTO_BLOCKSIZE],P,last_c_block_size);

        /* Final block */
        else if (j==nbMBlocks)
        	memcpy(&m[(j-1)*CRYPTO_BLOCKSIZE],P,CRYPTO_BLOCKSIZE);

        else{
        	memcpy(&m[(j-1)*CRYPTO_BLOCKSIZE],P,CRYPTO_BLOCKSIZE);

            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) // Add C1 to running tag
                running_tag[i] ^= C1[i];
        }
    }
 
    /* Check if the tag (C1) is correct, if incorrect output error (denoted by -1) */

    /* Does the tag part match? */
    if (c_incomplete){
    	if( memcmp(C1, &c[clen-last_c_block_size], last_c_block_size) != 0)
    		res = -1;
    }
    else{
    	if( memcmp(C1, &c[clen-CRYPTO_BLOCKSIZE], CRYPTO_BLOCKSIZE) != 0)
    		res = -1;
    }
    /* If incomplete: does the plaintext redundancy match? */
    if (c_incomplete){
        if (P[last_c_block_size] != 0x80){
            res = -1;
        }
        for (i = 1; i < CRYPTO_BLOCKSIZE-last_c_block_size; i++)
            if (P[last_c_block_size+i] != 0x00){
                res = -1;
            }
        }
            
    return res;
}
#endif
