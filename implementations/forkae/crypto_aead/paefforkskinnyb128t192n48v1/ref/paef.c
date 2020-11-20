#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "paef.h"
#include "extra_api.h"
#include "forkskinny.h"

//#define DEBUG_PAEF
#define MAX_COUNTER_BITS ((((CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES) << 3) - 3))

void print_tweakey(unsigned char* tweakey, int i){
    #ifdef DEBUG_PAEF
    int j;
    printf("\nTweakey at block %i: ", i);
    for (j = 0; j < CRYPTO_TWEAKEYSIZE; j++)
            printf("%02x ", tweakey[j]);
    printf("\n");
    #endif
}

void print_running_tag(unsigned char* running_tag, int i){
    #ifdef DEBUG_PAEF
    int j;
    printf("\nRunning tag after block %i: ", i);
    for (j = 0; j < CRYPTO_BLOCKSIZE; j++)
            printf("%02x ", running_tag[j]);
    printf("\n");
    #endif
}

void print_plain_cipher(unsigned char* state, int i){
    #ifdef DEBUG_PAEF
    int j;
    printf("\nBlock %i of plaintext/ciphertext: ", i);
    for (j = 0; j < CRYPTO_BLOCKSIZE; j++)
            printf("%02x ", state[j]);
    printf("\n");
    #endif
}

int paef_encrypt(
    unsigned char *c,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub, // nonce, of which the length is specified in api.h
    const unsigned char *k) { // key, of which the length is specified in api.h

    /* Declarations */
    uint64_t i, j;
    unsigned char A_j[CRYPTO_BLOCKSIZE], M_j[CRYPTO_BLOCKSIZE];
    unsigned char C0[CRYPTO_BLOCKSIZE], C1[CRYPTO_BLOCKSIZE];
    unsigned char tweakey[TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE];
    unsigned char running_tag[CRYPTO_BLOCKSIZE];

    uint64_t nbABlocks = adlen / CRYPTO_BLOCKSIZE;
    uint64_t nbMBlocks = mlen / CRYPTO_BLOCKSIZE;

    unsigned char AD[(nbABlocks+1)*CRYPTO_BLOCKSIZE], M[(nbMBlocks+1)*CRYPTO_BLOCKSIZE]; /* Allocate one more block in case padding is needed */

    
    uint64_t last_m_block_size = mlen % CRYPTO_BLOCKSIZE;
    uint8_t ad_incomplete = (adlen != nbABlocks*CRYPTO_BLOCKSIZE) | ((adlen == 0) & (mlen == 0));  /* Boolean flag to indicate whether the final block is complete */
    uint8_t m_incomplete = (last_m_block_size != 0);  /* Boolean flag to indicate whether the final block is complete */

    /* Check if ad length not too large */
    if ((uint64_t)(adlen / (uint64_t) CRYPTO_BLOCKSIZE) > (uint64_t) ((uint64_t)1 << MAX_COUNTER_BITS)){
        printf("Error: AD too long! Terminating. \n");
        return -1;
    }

    /* Check if message length not too large */
    if ((uint64_t)(mlen / (uint64_t) CRYPTO_BLOCKSIZE) > (uint64_t) ((uint64_t)1 << MAX_COUNTER_BITS)){
        printf("Error: M too long! Terminating. \n");
        return -1;
    }

    memset(running_tag, 0, CRYPTO_BLOCKSIZE); /* Set running tag to zero */

    /* Padding of A */
    for (i = 0; i < adlen; i++)
        AD[i] = ad[i]; 

    /* Pad A if it is incomplete OR if it is empty and there is no message either*/
    if (ad_incomplete)
        nbABlocks++;

    AD[adlen] = 0x80;

    for (i = adlen+1; i < nbABlocks*CRYPTO_BLOCKSIZE; i++) 
        AD[i] = 0x00; 

    /* Pad M if it is incomplete */
    if (last_m_block_size != 0)
        nbMBlocks++;

    for (i = 0; i < mlen; i++)
        M[i] = m[i]; 

    M[mlen] = 0x80;

    for (i = mlen+1; i < nbMBlocks*CRYPTO_BLOCKSIZE; i++)
        M[i] = 0x00;


    /* Construct baseline tweakey: key and nonce part remains unchanged throughout the execution. Initialize the remainder of the tweakey state to zero. */
    
    // Key
    for (i = 0; i < CRYPTO_KEYBYTES; i++)
        tweakey[i] = k[i]; 
    
    // Nonce
    for (i = 0; i < CRYPTO_NPUBBYTES; i++)
        tweakey[CRYPTO_KEYBYTES+i] = npub[i]; 

    // Flags and counter to zero
    for (i = 0; i < CRYPTO_TWEAKEYSIZE-CRYPTO_KEYBYTES-CRYPTO_NPUBBYTES; i++) {
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES+i] = 0; 
    }

    // For ForkSkinny-128-192 and ForkSkinny-128-288, the tweakey state needs to be zero-padded.
    for (i = CRYPTO_TWEAKEYSIZE; i < TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE; i++)
        tweakey[i] = 0; 

    /* Processing associated data */
    #ifdef DEBUG_PAEF
    printf("\n/* Processing associated data */ \n");
    #endif
    
    for (j = 1; j <= nbABlocks; j++) {

        /* Load next block */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            A_j[i] = AD[(j-1)*CRYPTO_BLOCKSIZE+i];

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
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= (j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        print_tweakey(tweakey, j);

        /* ForkEncrypt */
        forkEncrypt(C0, C1, A_j, tweakey, ENC_C1);

        /* Update running tag */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            running_tag[i] ^= C1[i];

        print_running_tag(running_tag, j);
    }

    if (mlen == 0) /* If message is empty, copy tag to output buffer */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            c[i] = running_tag[i];

    /* Processing message */
    #ifdef DEBUG_PAEF
        printf("\n/* Processing message */\n");
    #endif
    
    for (j = 1; j <= nbMBlocks; j++) {

        /* Load next block */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            M_j[i] = M[(j-1)*CRYPTO_BLOCKSIZE+i];

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
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= (j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        print_tweakey(tweakey, j);

        /* ForkEncrypt */
        forkEncrypt(C0, C1, M_j, tweakey, ENC_BOTH);

        /* Final incomplete block */
        if ((j==nbMBlocks) & m_incomplete){
            /* Add running tag to C0 and move to ciphertext output */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) 
                c[(j-1)*CRYPTO_BLOCKSIZE+i] = C0[i] ^ running_tag[i];

            /* C1 now contains the tag. Move it to ciphertext output */
            for (i = 0; i < last_m_block_size; i++)
                c[mlen+CRYPTO_BLOCKSIZE-last_m_block_size+i] = C1[i];

            print_plain_cipher(c, j);
            print_running_tag(C1, j);
        }

        /* Final complete block */
        else if (j==nbMBlocks){
            /* Add running tag to C0 and move to ciphertext output */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) 
                c[(j-1)*CRYPTO_BLOCKSIZE+i] = C0[i] ^ running_tag[i];

            /* C1 now contains the tag. Move it to ciphertext output */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) 
                c[mlen+i] = C1[i];

            print_plain_cipher(c, j);
            print_running_tag(C1, j);
        }

        /* Non-final block */
        else{
            /* C0 contains ciphertext block. Move it to ciphertext output */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
                c[(j-1)*CRYPTO_BLOCKSIZE+i] = C0[i];

            /* Update running tag with C1 value */
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
                running_tag[i] ^= C1[i];

            print_plain_cipher(C0, j);
            print_running_tag(running_tag, j);
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
    uint64_t i,j;
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
    uint64_t last_c_block_size = clen % CRYPTO_BLOCKSIZE;


    /* Check if ad length not too large */
    if ((uint64_t)(adlen / (uint64_t) CRYPTO_BLOCKSIZE) > (uint64_t) ((uint64_t)1 << MAX_COUNTER_BITS)){
        printf("Error: AD too long! Terminating. \n");
        return -1;
    }

    /* Check if message length not too large */
    if ((uint64_t)((uint64_t)(clen - (uint64_t) CRYPTO_BLOCKSIZE) / (uint64_t) CRYPTO_BLOCKSIZE) > (uint64_t) ((uint64_t)1 << MAX_COUNTER_BITS)){
        printf("Error: M too long! Terminating. \n");
        return -1;
    }

    memset(running_tag, 0, CRYPTO_BLOCKSIZE); /* Set running tag to zero */

    /* Padding of A */
    for (i = 0; i < adlen; i++)
        AD[i] = ad[i]; 
    
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
    for (i = 0; i < CRYPTO_KEYBYTES; i++)
        tweakey[i] = k[i]; 
    
    // Nonce
    for (i = 0; i < CRYPTO_NPUBBYTES; i++)
        tweakey[CRYPTO_KEYBYTES+i] = npub[i]; 

    // Flags and counter to zero
    for (i = 0; i < CRYPTO_TWEAKEYSIZE-CRYPTO_KEYBYTES-CRYPTO_NPUBBYTES; i++)
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES+i] = 0; 

    // For ForkSkinny-128-192 and ForkSkinny-128-288, the tweakey state needs to be zero-padded.
    for (i = CRYPTO_TWEAKEYSIZE; i < TWEAKEY_BLOCKSIZE_RATIO*CRYPTO_BLOCKSIZE; i++)
        tweakey[i] = 0; 

    /* Processing associated data */
    #ifdef DEBUG_PAEF
    printf("\n/* Processing associated data */\n");
    #endif
    
    for (j = 1; j <= nbABlocks; j++) {

        /* Load next block */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            A_j[i] = AD[(j-1)*CRYPTO_BLOCKSIZE+i];

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
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= (j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        print_tweakey(tweakey, j);

        /* ForkEncrypt */
        forkEncrypt(C0, C1, A_j, tweakey, ENC_C1);

        /* Update running tag */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            running_tag[i] ^= C1[i];

        print_running_tag(running_tag, j);
    }

    if (clen == CRYPTO_BLOCKSIZE) /* If message is empty, copy tag to output buffer */
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            C1[i] = running_tag[i];

    /* Process ciphertext */
    #ifdef DEBUG_PAEF
        printf("\n/* Processing ciphertext */\n");
    #endif
    
    for (j = 1; j <= nbMBlocks; j++) {
        
        /* Final ciphertext block: XOR with running tag*/
        if (j==nbMBlocks)
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
                C_j[i] = c[(j-1)*CRYPTO_BLOCKSIZE+i] ^ running_tag[i]; // C0 is running tag xor C*
        
        /* Non-final ciphertext block*/
        else 
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
                C_j[i] = c[(j-1)*CRYPTO_BLOCKSIZE+i];

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
        tweakey[CRYPTO_KEYBYTES+CRYPTO_NPUBBYTES] ^= (j >> 8*(CRYPTO_TWEAKSIZE-CRYPTO_NPUBBYTES-1)) & 0xff;

        print_tweakey(tweakey, j);

        /* ForkInvert */
        forkInvert(P, C1, C_j, tweakey, 0, INV_BOTH);

        /* Final incomplete block */
        if ((j==nbMBlocks) & c_incomplete)
            for (i = 0; i < last_c_block_size; i++) // Move incomplete P to plaintext output
                m[(j-1)*CRYPTO_BLOCKSIZE+i] = P[i];
        
        /* Final block */
        else if (j==nbMBlocks)
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) // Move complete P to plaintext output
                m[(j-1)*CRYPTO_BLOCKSIZE+i] = P[i];
        
        else{
            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) // Move complete P to plaintext output
                m[(j-1)*CRYPTO_BLOCKSIZE+i] = P[i];

            for (i = 0; i < CRYPTO_BLOCKSIZE; i++) // Add C1 to running tag
                running_tag[i] ^= C1[i];
        }

        print_plain_cipher(P, j);
        print_running_tag(running_tag, j);
    }
 
    /* Check if the tag (C1) is correct, if incorrect output error (denoted by -1) */

    /* Does the tag part match? */
    if (c_incomplete){
        for (i = 0; i < last_c_block_size; i++)
            if (C1[i] != c[clen-last_c_block_size+i]){
                res = -1;
            }
    }
    else{
        for (i = 0; i < CRYPTO_BLOCKSIZE; i++)
            if (C1[i] != c[clen-CRYPTO_BLOCKSIZE+i]){
                res = -1;
            }
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

