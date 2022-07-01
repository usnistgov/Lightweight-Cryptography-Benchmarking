/*
 * Date: 11 December 2015
 * Contact: Thomas Peyrin - thomas.peyrin@gmail.com
 * Modified on 04 May 2021 by Mustafa Khairallah - Modified the code
 * to implement only the SKINNY-128-384+ encryption version of Skinny for
 * Romulus v1.3, the NIST LwC finalist.
 * mustafa.khairallah@ntu.edu.sg
 */

/* 
 * This file includes only the encryption function of SKINNY-128-384+ as required by Romulus-v1.3
 */


#include "skinny.h"

//#define DEBUG 1

#ifdef DEBUG
#include<stdio.h>
#include <time.h>
#include <string.h>
#endif

// Skinny-128-384+ parameters: 128-bit block, 384-bit tweakey and 40 rounds
int BLOCK_SIZE = 128;
int TWEAKEY_SIZE = 384;
int N_RNDS = 40;

// Packing of data is done as follows (state[i][j] stands for row i and column j):
// 0  1  2  3
// 4  5  6  7
// 8  9 10 11
//12 13 14 15

// 8-bit Sbox
const unsigned char sbox_8[256] = {0x65 , 0x4c , 0x6a , 0x42 , 0x4b , 0x63 , 0x43 , 0x6b , 0x55 , 0x75 , 0x5a , 0x7a , 0x53 , 0x73 , 0x5b , 0x7b ,0x35 , 0x8c , 0x3a , 0x81 , 0x89 , 0x33 , 0x80 , 0x3b , 0x95 , 0x25 , 0x98 , 0x2a , 0x90 , 0x23 , 0x99 , 0x2b ,0xe5 , 0xcc , 0xe8 , 0xc1 , 0xc9 , 0xe0 , 0xc0 , 0xe9 , 0xd5 , 0xf5 , 0xd8 , 0xf8 , 0xd0 , 0xf0 , 0xd9 , 0xf9 ,0xa5 , 0x1c , 0xa8 , 0x12 , 0x1b , 0xa0 , 0x13 , 0xa9 , 0x05 , 0xb5 , 0x0a , 0xb8 , 0x03 , 0xb0 , 0x0b , 0xb9 ,0x32 , 0x88 , 0x3c , 0x85 , 0x8d , 0x34 , 0x84 , 0x3d , 0x91 , 0x22 , 0x9c , 0x2c , 0x94 , 0x24 , 0x9d , 0x2d ,0x62 , 0x4a , 0x6c , 0x45 , 0x4d , 0x64 , 0x44 , 0x6d , 0x52 , 0x72 , 0x5c , 0x7c , 0x54 , 0x74 , 0x5d , 0x7d ,0xa1 , 0x1a , 0xac , 0x15 , 0x1d , 0xa4 , 0x14 , 0xad , 0x02 , 0xb1 , 0x0c , 0xbc , 0x04 , 0xb4 , 0x0d , 0xbd ,0xe1 , 0xc8 , 0xec , 0xc5 , 0xcd , 0xe4 , 0xc4 , 0xed , 0xd1 , 0xf1 , 0xdc , 0xfc , 0xd4 , 0xf4 , 0xdd , 0xfd ,0x36 , 0x8e , 0x38 , 0x82 , 0x8b , 0x30 , 0x83 , 0x39 , 0x96 , 0x26 , 0x9a , 0x28 , 0x93 , 0x20 , 0x9b , 0x29 ,0x66 , 0x4e , 0x68 , 0x41 , 0x49 , 0x60 , 0x40 , 0x69 , 0x56 , 0x76 , 0x58 , 0x78 , 0x50 , 0x70 , 0x59 , 0x79 ,0xa6 , 0x1e , 0xaa , 0x11 , 0x19 , 0xa3 , 0x10 , 0xab , 0x06 , 0xb6 , 0x08 , 0xba , 0x00 , 0xb3 , 0x09 , 0xbb ,0xe6 , 0xce , 0xea , 0xc2 , 0xcb , 0xe3 , 0xc3 , 0xeb , 0xd6 , 0xf6 , 0xda , 0xfa , 0xd3 , 0xf3 , 0xdb , 0xfb ,0x31 , 0x8a , 0x3e , 0x86 , 0x8f , 0x37 , 0x87 , 0x3f , 0x92 , 0x21 , 0x9e , 0x2e , 0x97 , 0x27 , 0x9f , 0x2f ,0x61 , 0x48 , 0x6e , 0x46 , 0x4f , 0x67 , 0x47 , 0x6f , 0x51 , 0x71 , 0x5e , 0x7e , 0x57 , 0x77 , 0x5f , 0x7f ,0xa2 , 0x18 , 0xae , 0x16 , 0x1f , 0xa7 , 0x17 , 0xaf , 0x01 , 0xb2 , 0x0e , 0xbe , 0x07 , 0xb7 , 0x0f , 0xbf ,0xe2 , 0xca , 0xee , 0xc6 , 0xcf ,0xe7 , 0xc7 , 0xef , 0xd2 , 0xf2 , 0xde , 0xfe , 0xd7 , 0xf7 , 0xdf , 0xff};

// ShiftAndSwitchRows permutation
const unsigned char P[16] = {0,1,2,3,7,4,5,6,10,11,8,9,13,14,15,12};

// Tweakey permutation
const unsigned char TWEAKEY_P[16] = {9,15,8,13,10,14,12,11,0,1,2,3,4,5,6,7};

// round constants
const unsigned char RC[40] = {
		0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F,
		0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E, 0x1D, 0x3A, 0x35, 0x2B,
		0x16, 0x2C, 0x18, 0x30, 0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E,
		0x1C, 0x38, 0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A};

#ifdef DEBUG
void display_matrix(unsigned char state[4][4])
{
    int i;
    unsigned char input[16];

    for(i = 0; i < 16; i++) input[i] = state[i>>2][i&0x3] & 0xFF;
    for(i = 0; i < 16; i++) printf("%02x", input[i]);

}

void display_cipher_state(unsigned char state[4][4], unsigned char keyCells[3][4][4])
{
    int k;

    printf("S = ");display_matrix(state);
    for(k = 0; k <(int)(TWEAKEY_SIZE/BLOCK_SIZE); k++)
    {
        printf(" - TK%i = ",k+1); display_matrix(keyCells[k]);
    }
}
#endif

// Extract and apply the subtweakey to the internal state (must be the two top rows XORed together), then update the tweakey state
void AddKey(unsigned char state[4][4], unsigned char keyCells[3][4][4])
{
	int i, j, k;
	unsigned char pos;
	unsigned char keyCells_tmp[3][4][4];

    // apply the subtweakey to the internal state
    for(i = 0; i <= 1; i++)
    {
        for(j = 0; j < 4; j++)
        {
            state[i][j] ^= keyCells[0][i][j] ^ keyCells[1][i][j] ^ keyCells[2][i][j];            
        }
    }

    // update the subtweakey states with the permutation
    for(k = 0; k <(int)(TWEAKEY_SIZE/BLOCK_SIZE); k++){
        for(i = 0; i < 4; i++){
            for(j = 0; j < 4; j++){
                //application of the TWEAKEY permutation
                pos=TWEAKEY_P[j+4*i];
                keyCells_tmp[k][i][j]=keyCells[k][pos>>2][pos&0x3];
            }
        }
    }

    // update the subtweakey states with the LFSRs
    for(k = 0; k <(int)(TWEAKEY_SIZE/BLOCK_SIZE); k++){
        for(i = 0; i <= 1; i++){
            for(j = 0; j < 4; j++){
                //application of LFSRs for TK updates
                if (k==1)
                {
		  			keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]<<1)&0xFE)^((keyCells_tmp[k][i][j]>>7)&0x01)^((keyCells_tmp[k][i][j]>>5)&0x01);
                }
                else if (k==2)
                {
		  			keyCells_tmp[k][i][j]=((keyCells_tmp[k][i][j]>>1)&0x7F)^((keyCells_tmp[k][i][j]<<7)&0x80)^((keyCells_tmp[k][i][j]<<1)&0x80);
                }
            }
        }
    }

    for(k = 0; k <(int)(TWEAKEY_SIZE/BLOCK_SIZE); k++){
        for(i = 0; i < 4; i++){
            for(j = 0; j < 4; j++){
                keyCells[k][i][j]=keyCells_tmp[k][i][j];
            }
        }
    }
}

// Apply the constants: using a LFSR counter on 6 bits, we XOR the 6 bits to the first 6 bits of the internal state
void AddConstants(unsigned char state[4][4], int r)
{
	state[0][0] ^= (RC[r] & 0xf);
	state[1][0] ^= ((RC[r]>>4) & 0x3);
	state[2][0] ^= 0x2;
}

// apply the 8-bit Sbox
void SubCell8(unsigned char state[4][4])
{
	int i,j;
	for(i = 0; i < 4; i++){
		for(j = 0; j <  4; j++){
			state[i][j] = sbox_8[state[i][j]];
		}
	}
}

// Apply the ShiftRows function
void ShiftRows(unsigned char state[4][4])
{
    unsigned char tmp;
    tmp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = tmp;
 
    tmp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = tmp;
    tmp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = tmp;
 
    tmp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = tmp;
}
// Apply the linear diffusion matrix
//M =
//1 0 1 1
//1 0 0 0
//0 1 1 0
//1 0 1 0
void MixColumn(unsigned char state[4][4])
{
	int j;
    unsigned char temp;

	for(j = 0; j < 4; j++){
        state[1][j]^=state[2][j];
        state[2][j]^=state[0][j];
        state[3][j]^=state[2][j];

        temp=state[3][j];
        state[3][j]=state[2][j];
        state[2][j]=state[1][j];
        state[1][j]=state[0][j];
        state[0][j]=temp;
	}
}

// encryption function of Skinny-128-384+
void enc(unsigned char* input, const unsigned char* userkey)
{
	unsigned char state[4][4];
	unsigned char keyCells[3][4][4];
	int i;
	
	//memset(keyCells, 0, 48);	
	for(i = 0; i < 16; i++) {
        state[i>>2][i&0x3] = input[i]&0xFF;
        keyCells[0][i>>2][i&0x3] = userkey[i]&0xFF;
	    keyCells[1][i>>2][i&0x3] = userkey[i+16]&0xFF;
	    keyCells[2][i>>2][i&0x3] = userkey[i+32]&0xFF;
	}

    #ifdef DEBUG
        printf("ENC - initial state:                 ");display_cipher_state(state,keyCells);printf("\n");
    #endif
	for(i = 0; i < N_RNDS; i++){
        SubCell8(state);
            #ifdef DEBUG
            printf("ENC - round %.2i - after SubCell:      ",i);display_cipher_state(state,keyCells);printf("\n");
            #endif
	    AddConstants(state, i);
            #ifdef DEBUG
            printf("ENC - round %.2i - after AddConstants: ",i);display_cipher_state(state,keyCells);printf("\n");
            #endif
	    AddKey(state, keyCells);
            #ifdef DEBUG
            printf("ENC - round %.2i - after AddKey:       ",i);display_cipher_state(state,keyCells);printf("\n");
            #endif
	    ShiftRows(state);
            #ifdef DEBUG
            printf("ENC - round %.2i - after ShiftRows:    ",i);display_cipher_state(state,keyCells);printf("\n");
            #endif
	    MixColumn(state);
            #ifdef DEBUG
            printf("ENC - round %.2i - after MixColumn:    ",i);display_cipher_state(state,keyCells);printf("\n");
            #endif
	}  //The last subtweakey should not be added

	#ifdef DEBUG
        printf("ENC - final state:                   ");display_cipher_state(state,keyCells);printf("\n");
    #endif
	
    for(i = 0; i < 16; i++)
		input[i] = state[i>>2][i&0x3] & 0xFF;
}

void skinny_128_384_plus_enc (unsigned char* input, const unsigned char* userkey) {
 	enc(input,userkey); 
}

