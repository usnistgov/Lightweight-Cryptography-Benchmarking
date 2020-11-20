#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#include "forkskinny.h"
#include "extra_api.h"
#include "skinny_round.h"
#include "helpers.h"

//#define DEBUG_FORK


/* === Print intermediate results for debugging purposes === */
void print_fork(unsigned char s[4][4]){
    #ifdef DEBUG_FORK
    int j,k;
    printf("\n === At the fork: ");
    for (j = 0; j < 4; j++)
        for (k = 0; k < 4; k++)
            printf("%02x ", s[j][k]);
    printf(" ===");
    #endif
}

void AddBranchConstant(unsigned char state[4][4]){
	int i, j;
    #ifdef CRYPTO_BLOCKSIZE_8
    const unsigned char BC[16] = {0x01,0x02,0x04,0x09,0x03,0x06,0x0d,0x0a,0x05,0x0b,0x07,0x0f,0x0e,0x0c,0x08,0x01};
    #else
    const unsigned char BC[16] = {0x01,0x02,0x04,0x08,0x10,0x20,0x41,0x82,0x05,0x0a,0x14,0x28,0x51,0xa2,0x44,0x88};
    #endif

    for(i = 0; i < 4; i++)
        for(j = 0; j < 4; j++){
            state[i][j] ^= BC[4*i+j];
        }
}

void loadStateAndKey(unsigned char state[4][4], unsigned char keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4], unsigned char* input, const unsigned char* userkey){

    int i;

	for(i = 0; i < 16; i++) {
        #ifdef CRYPTO_BLOCKSIZE_8
            // For BS = 64, cells are only half-bytes so every input byte needs to be spread over two cells
            if(i&1){
                state[i>>2][i&0x3] = input[i>>1]&0xF;
                keyCells[0][i>>2][i&0x3] = userkey[i>>1]&0xF;
                if (TWEAKEY_BLOCKSIZE_RATIO >= 2)
                    keyCells[1][i>>2][i&0x3] = userkey[(i+16)>>1]&0xF;
                if (TWEAKEY_BLOCKSIZE_RATIO >= 3)
                    keyCells[2][i>>2][i&0x3] = userkey[(i+32)>>1]&0xF;
            }
            else {
                state[i>>2][i&0x3] = (input[i>>1]>>4)&0xF;
                keyCells[0][i>>2][i&0x3] = (userkey[i>>1]>>4)&0xF;
                if (TWEAKEY_BLOCKSIZE_RATIO >= 2)
                    keyCells[1][i>>2][i&0x3] = (userkey[(i+16)>>1]>>4)&0xF;
                if (TWEAKEY_BLOCKSIZE_RATIO >= 3)
                    keyCells[2][i>>2][i&0x3] = (userkey[(i+32)>>1]>>4)&0xF;
            }
        #else
            state[i>>2][i&0x3] = input[i]&0xFF;
            keyCells[0][i>>2][i&0x3] = userkey[i]&0xFF;
            if (TWEAKEY_BLOCKSIZE_RATIO >= 2)
                keyCells[1][i>>2][i&0x3] = userkey[i+16]&0xFF;
            if (TWEAKEY_BLOCKSIZE_RATIO >= 3)
                keyCells[2][i>>2][i&0x3] = userkey[i+32]&0xFF;
        #endif
    }
}

void forkEncrypt(unsigned char* C0, unsigned char* C1, unsigned char* input, const unsigned char* userkey, const enum encrypt_selector s){

	unsigned char state[4][4], L[4][4], keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4]; 
    int i;

    loadStateAndKey(state, keyCells, input, userkey);

    /* Before fork */
	for(i = 0; i < CRYPTO_NBROUNDS_BEFORE; i++)
        skinny_round(state, keyCells, i);

    /* Save fork if both output blocks are needed */
    if (s == ENC_BOTH)
        stateCopy(L, state);

    print_fork(state);

    /* Right branch (C1) */
    if ((s == ENC_C1) | (s == ENC_BOTH)){
        for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++) 
            skinny_round(state, keyCells, i);

        /* Move result to output buffer*/
        stateToCharArray(C1, state);
    }

    /* Reinstall L as state if necessary */
    if (s == ENC_BOTH)
        stateCopy(state, L);

    /* Advance the key schedule for C0 */
    if (s == ENC_C0)
        for(i = 0; i < CRYPTO_NBROUNDS_AFTER; i++)
            advanceKeySchedule(keyCells);

    /* Left branch (C0) */
    if ((s == ENC_C0) | (s == ENC_BOTH)){

        /* Add branch constant */
        AddBranchConstant(state);

        for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++) 
            skinny_round(state, keyCells, i);

        /* Move result to output buffer */
        stateToCharArray(C0, state);
    }

    /* Null pointer for invalid outputs */
    if (s == ENC_C0) 
        C1 = NULL;
    else if (s == ENC_C1) 
        C0 = NULL;

}


void forkInvert(unsigned char* inverse, unsigned char* C_other, unsigned char* input, const unsigned char* userkey, uint8_t b, const enum inversion_selector s){

	unsigned char state[4][4], L[4][4], keyCells[TWEAKEY_BLOCKSIZE_RATIO][4][4];
	int i;

    loadStateAndKey(state, keyCells, input, userkey);

    if (b == 1){

        /* Advance the key schedule in order to decrypt */
        for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++)
            advanceKeySchedule(keyCells);

        /* From C1 to fork*/
        for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE; i--)
            skinny_round_inv(state, keyCells, i);

        /* Save fork if both blocks are needed */
        if (s == INV_BOTH) 
            stateCopy(L, state);

        print_fork(state);

        if ((s == INV_INVERSE) | (s == INV_BOTH)) {
            /* From fork to M */
            for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
                skinny_round_inv(state, keyCells, i);

            /* Move result to output buffer */
            stateToCharArray(inverse, state);
        }

        /* Reinstall fork if necessary */
        if (s == INV_BOTH) {
            stateCopy(state, L);

            for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
                advanceKeySchedule(keyCells);
        }

        if ((s == INV_OTHER) | (s == INV_BOTH)) {
            /* Set correct keyschedule */
            for (i=0; i<CRYPTO_NBROUNDS_AFTER; i++)
                advanceKeySchedule(keyCells);

            /* Add branch constant */
            AddBranchConstant(state);

            /* From fork to C0 */
            for(i = CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++) 
                skinny_round(state, keyCells, i);

            /* Move result to output buffer */
            stateToCharArray(C_other, state);
        }
    }
    else {
        /* Advance the key schedule in order to decrypt */
        for(i = 0; i < CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER; i++)
            advanceKeySchedule(keyCells);

        /* From C0 to fork */
        for(i = CRYPTO_NBROUNDS_BEFORE+2*CRYPTO_NBROUNDS_AFTER-1; i >= CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i--)
            skinny_round_inv(state, keyCells, i);

        /* Add branch constant */
        AddBranchConstant(state);

        /* Save fork if both blocks are needed */
        if (s == INV_BOTH) 
            stateCopy(L, state);

        print_fork(state);

        /* Set correct keyschedule */
        for(i = 0; i < CRYPTO_NBROUNDS_AFTER; i++)
            reverseKeySchedule(keyCells);

        if ((s == INV_BOTH) | (s == INV_INVERSE)) {
            /* From fork to M */
            for(i = CRYPTO_NBROUNDS_BEFORE-1; i >= 0; i--)
                skinny_round_inv(state, keyCells, i);

            /* Move result into output buffer */
            stateToCharArray(inverse, state);

        }

        /* Reinstall fork and correct key schedule if necessary */
        if (s == INV_BOTH) {
            stateCopy(state, L);

            for (i=0; i<CRYPTO_NBROUNDS_BEFORE; i++)
                advanceKeySchedule(keyCells);
        }

        if ((s == INV_BOTH) | (s == INV_OTHER)) {
            /* From fork to C1 */
            for(i = CRYPTO_NBROUNDS_BEFORE; i < CRYPTO_NBROUNDS_BEFORE+CRYPTO_NBROUNDS_AFTER; i++) // for i in range(nbRounds)
                skinny_round(state, keyCells, i);

            /* Move result to output buffer */
            stateToCharArray(C_other, state);
        }
    }
    
    /* Null pointer for invalid outputs */
    if (s == INV_INVERSE) 
        C_other = NULL;
    else if (s == INV_OTHER) 
        inverse = NULL;
}

