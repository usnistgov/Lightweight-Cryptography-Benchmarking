#include <stdio.h>

#include "helpers.h" 
#include "extra_api.h" 

void stateCopy(unsigned char a[4][4], unsigned char b[4][4]){
    int i, j;

    for(i = 0; i < 4; i++)
        for(j = 0; j <  4; j++)
            a[i][j] = b[i][j];
}

void tweakeyCopy(unsigned char tweakey[TWEAKEY_BLOCKSIZE_RATIO][4][4], unsigned char input[TWEAKEY_BLOCKSIZE_RATIO][4][4]){
    int i, j, k;

    for(k = 0; k < TWEAKEY_BLOCKSIZE_RATIO; k++)
        for(i = 0; i < 4; i++)
            for(j = 0; j < 4; j++)
                tweakey[k][i][j]=input[k][i][j];
}

void stateToCharArray(unsigned char* array, unsigned char state[4][4]){

    int i;

    #ifdef CRYPTO_BLOCKSIZE_8
    for(i = 0; i < 8; i++)
        array[i] = ((state[(2*i)>>2][(2*i)&0x3] & 0xF) << 4) | (state[(2*i+1)>>2][(2*i+1)&0x3] & 0xF);
    #endif
    #ifdef CRYPTO_BLOCKSIZE_16
    for(i = 0; i < 16; i++)
        array[i] = state[i>>2][i&0x3] & 0xFF;
    #endif

}

