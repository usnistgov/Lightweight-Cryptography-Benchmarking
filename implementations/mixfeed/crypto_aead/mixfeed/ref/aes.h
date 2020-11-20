//
//  aes.c
//  MixFeed
//
//  Created by Bishwajit Chakraborty on 08/02/19.
//  Copyright © 2019 Bishwajit Chakraborty. All rights reserved.
//


#include "api.h"
typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long ul;



/*#################################################################################################################
 
 aes Sbox, and RCon Box. Same As AES-128. aes Subbytes.
 
 ###############################################################################################################*/

u8 aes_rcon[11]= {0x01  ,  0x02 ,   0x04 ,   0x08 ,   0x10 ,   0x20 ,   0x40 ,   0x80 ,   0x1B  ,  0x36,0x6c};
u8 aes_sbox[256]=
{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

int aes_subbytes(u8 * plain_text)
{
    for(int k = 0; k < 16; k++)
        plain_text[k]= aes_sbox[plain_text[k]];
    return 0;
}
/*###############################################################################################################
 
 aes Shift Row. Same as AES 128
 
 ################################################################################################################*/


int aes_shiftrow(u8 * plain_text)
{
    for(int k = 1; k < 4; k++)
    {
        u8 row[4];
        for (int l = 0; l < 4; l++)
            row[l] = plain_text[4 * l + k];
        u8 temp[k];
        for(int j=0;j<k;j++)
            temp[j]= row[j];
        for(int j=0; j<4-k;j++)
            row[j] = row[j+k];
        for(int j=0;j<k;j++)
            row[4-k+j] = temp[j];
        for (int l = 0; l < 4; l++)
            plain_text[4 * l + k] = row[l];
    }
    return 0;
}


/*###############################################################################################################
 
 aes Mix Column. Same as AES 128
 
 ################################################################################################################*/
int gmix_column(u8 *r) {
    unsigned char a[4]={0};
    unsigned char b[4]={0};
    unsigned char c=0;
    unsigned char h=0;
    for (c = 0; c < 4; c++) {
        a[c] = r[c];
        h = (unsigned char)((signed char)r[c] >> 7);
        b[c] = r[c] << 1;
        b[c] ^= 0x1B & h;
    }
    r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
    r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    
    return 0;
}

int aes_mixcolumn(u8 * plain_text)
{
    u8  column[4];
    for (int k =0; k<4; k++)
    {
        for (int l=0 ; l<4 ; l++)
            column[l] = plain_text[4*k+l];
        gmix_column(column);
        for (int l=0 ; l<4 ; l++)
            plain_text[4*k+l] = column[l];
    }
    return 0;
}

/*################################################################################################################
 
 aes Key Schedule. Modified AES 128
 
 ################################################################################################################*/
int aes_key_schedule(u8 * round_key , int round)
{
    if(round==0)
        return 0;
    else{
        round_key[0] = round_key[0]^aes_sbox[round_key[13]]^aes_rcon[round-1];
        round_key[1] = round_key[1]^aes_sbox[round_key[14]];
        round_key[2] = round_key[2]^aes_sbox[round_key[15]];
        round_key[3] = round_key[3]^aes_sbox[round_key[12]];
        for(int i=4;i<16;i++)
            round_key[i]= round_key[i]^round_key[i-4];
    }
    
    
    return 0;
}

int aes_add_round_key(u8 * round_key,int round, u8 * input_text)
{
    aes_key_schedule(round_key,round);
    for(int j=0; j<16;j++)
        input_text[j]=input_text[j]^round_key[j];
    return 0;
}
/*################################################################################################################
 
 aes Encryption scheme. Modified AES-128
 
 ################################################################################################################*/



int aes_enc( u8 * aes_key, u8 * aes_input_text, u8 * aes_output_text)
{
    u8 last_round_key[16]={0}, plain[16] ={0};
    for (int j=0; j<16; j++){
        last_round_key[j]=aes_key[j];
        plain[j]=aes_input_text[j];
    }
    
   aes_add_round_key(last_round_key,0,plain);
    for(int j = 1; j <11; j++)
    {
        aes_subbytes(plain);
        aes_shiftrow(plain);
        aes_mixcolumn(plain);
        
        aes_add_round_key(last_round_key, j, plain );
    }
    aes_key_schedule(last_round_key,11);
    for(int j=0;j<16;j++)
    {
        aes_key[j] = last_round_key[j];
        aes_output_text[j] = plain[j];
        
    }
    return 0;
}



