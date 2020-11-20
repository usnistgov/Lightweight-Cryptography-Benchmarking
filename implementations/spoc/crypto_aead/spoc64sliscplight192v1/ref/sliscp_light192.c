/* Reference implementation of the sliscp_light192 permutation of width 192 bits.
   Written by:
   Kalikinkar Mandal <kmandal@uwaterloo.ca>
*/

#include<stdio.h>
#include<math.h>
#include<stdlib.h>
#include<stdint.h>
#include "sliscp_light192.h"

/*
   *SC1_192: step constants, applied on S_0
   *SC2_192: step constants, applied on S_2
*/
const uint8_t SC1_192[18]={0x8, 0xc, 0xa, 0x2f, 0x38, 0x24, 0x36, 0xd, 0x2b, 0x3e, 0x1, 0x21, 0x11, 0x39, 0x5, 0x27, 0x34, 0x2e}; // Step constants (SC_{2i})
const uint8_t SC2_192[18]={0x29, 0x1d, 0x33, 0x2a, 0x1f, 0x10, 0x18, 0x14, 0x1e, 0x31, 0x9, 0x2d, 0x1b, 0x16, 0x3d, 0x3, 0x2, 0x23};// Step constants (SC_{2i+1})
/*
   *RC1_192: round constants of simeck box applied on S_1
   *RC2_192: round constants of simeck box applied on S_3
*/
const uint8_t RC1_192[18]={0x7, 0x4, 0x6, 0x25, 0x17, 0x1c, 0x12, 0x3b, 0x26, 0x15, 0x3f, 0x20, 0x30, 0x28, 0x3c, 0x22, 0x13, 0x1a};// Round constants (RC_{2i})
const uint8_t RC2_192[18]={0x27, 0x34, 0x2e, 0x19, 0x35, 0xf, 0x8, 0xc, 0xa, 0x2f, 0x38, 0x24, 0x36, 0xd, 0x2b, 0x3e, 0x1, 0x21};// Round constants (RC_{2i+1})

uint8_t rotl8 ( const uint8_t x, const uint8_t y, const uint8_t shift )
{
	return ((x<<shift)|(y>>(8-shift)));
}

/***********************************************************
  *******sLiSCP-LIGHT192 permutation implementation*********
  *********************************************************/

void sliscp_print_state192( const uint8_t *state )
{
	uint8_t i;
	for ( i = 0; i < STATEBYTES; i++ )
		printf("%.2x ", state[i]);
	printf("\n");
}

/*
   *simeck48_box: 48-bit simeck sbox
   *rc: 6-bit round constant
   *input: 48-bit input
   *output: 48-bit output
*/
void simeck48_box( uint8_t *output, const uint8_t *input, const uint8_t rc )
{
        uint8_t i, t;
        uint8_t *tmp_shift_1, *tmp_shift_5, *tmp_pt;
        
        tmp_shift_1 = (uint8_t *)malloc(3*sizeof(uint8_t));
        tmp_shift_5 = (uint8_t *)malloc(3*sizeof(uint8_t));
        tmp_pt = (uint8_t *)malloc(SIMECKBYTES*sizeof(uint8_t));
        
        for ( i = 0; i < SIMECKBYTES; i++ )
                tmp_pt[i] = input[i];
        
        for ( i = 0; i < SIMECKROUND; i++ )
        {
                tmp_shift_1[0] = rotl8(tmp_pt[0], tmp_pt[1],1);
                tmp_shift_1[1] = rotl8(tmp_pt[1], tmp_pt[2],1);
                tmp_shift_1[2] = rotl8(tmp_pt[2], tmp_pt[0],1);
                
                tmp_shift_5[0] = rotl8(tmp_pt[0], tmp_pt[1],5);
                tmp_shift_5[1] = rotl8(tmp_pt[1], tmp_pt[2],5);
                tmp_shift_5[2] = rotl8(tmp_pt[2], tmp_pt[0],5);
                
                tmp_shift_5[0] = tmp_shift_5[0]&tmp_pt[0];
                tmp_shift_5[1] = tmp_shift_5[1]&tmp_pt[1];
                tmp_shift_5[2] = tmp_shift_5[2]&tmp_pt[2];
                
                tmp_shift_1[0] = tmp_shift_1[0]^tmp_shift_5[0];
                tmp_shift_1[1] = tmp_shift_1[1]^tmp_shift_5[1];
                tmp_shift_1[2] = tmp_shift_1[2]^tmp_shift_5[2];
                
                tmp_shift_1[0] = tmp_shift_1[0]^tmp_pt[3]^(0xff);
                tmp_shift_1[1] = tmp_shift_1[1]^tmp_pt[4]^(0xff);
                tmp_shift_1[2] = tmp_shift_1[2]^tmp_pt[5]^(0xfe);
                
                t = (rc >> i)&1;
                tmp_shift_1[2] = tmp_shift_1[2]^t;
                //printf("%d ", t);
                
                tmp_pt[3] = tmp_pt[0];
                tmp_pt[4] = tmp_pt[1];
                tmp_pt[5] = tmp_pt[2];
                
                tmp_pt[0] = tmp_shift_1[0];
                tmp_pt[1] = tmp_shift_1[1];
                tmp_pt[2] = tmp_shift_1[2];
                //simeck_print_data(tmp_pt, 6);
                
        }
        for ( i = 0; i < SIMECKBYTES; i++ )
                output[i] = tmp_pt[i];
        
free(tmp_shift_1);
free(tmp_shift_5);
free(tmp_pt);
return;
}

/*
   *sliscp_permutation192r18: 18-round sliscp-light permutation of width 192 bits
   *input: 192-bit input, and output is stored in input (inplace).  
*/
void sliscp_permutation192r18 ( uint8_t *input )
{
        uint8_t i, j;
        uint8_t *tmp_pt, *tmp_block, *simeck_inp;
        
        tmp_pt = (uint8_t *)malloc(STATEBYTES*sizeof(uint8_t));
        tmp_block = (uint8_t *)malloc(SIMECKBYTES*sizeof(uint8_t));
        simeck_inp = (uint8_t *)malloc(SIMECKBYTES*sizeof(uint8_t));
        
        for ( i = 0; i < STATEBYTES; i++ )
                tmp_pt[i] = input[i];
        
        for ( i = 0; i < NUMSTEPSFULL; i++ )
        {
                for ( j = 0; j < SIMECKBYTES; j++ )
                        tmp_block[j] = tmp_pt[j];
                
                for ( j = 0; j < SIMECKBYTES; j++ )
                        simeck_inp[j] = tmp_pt[SIMECKBYTES+j];
                
                simeck48_box( simeck_inp, simeck_inp, RC1_192[i] );
                
                for ( j = 0; j < SIMECKBYTES; j++ )
                        tmp_block[j] = tmp_block[j]^simeck_inp[j]; //x0^F(x1)
                
                // Add round constant: SC[0]^x0^F(x1)
                for ( j = 0; j < SIMECKBYTES-1; j++ )
                        tmp_block[j] = tmp_block[j]^(0xff);
                tmp_block[SIMECKBYTES-1] = tmp_block[SIMECKBYTES-1]^SC1_192[i];
                
                
                for ( j = 0; j < SIMECKBYTES; j++ )
                        tmp_pt[j] = simeck_inp[j]; // x0' = F(x1)
                
                for ( j = 0; j < SIMECKBYTES; j++ )
                        simeck_inp[j] = tmp_pt[3*SIMECKBYTES + j];
                
                simeck48_box ( simeck_inp, simeck_inp, RC2_192[i] );
                
                for ( j = 0; j < SIMECKBYTES; j++ )
                        tmp_pt[SIMECKBYTES+j] = tmp_pt[2*SIMECKBYTES+j]^simeck_inp[j]; //x2^F(x3)
                
                // Add round constant: SC[1]^x2^F(x3)
                for ( j = 0; j < SIMECKBYTES-1; j++ )
                        tmp_pt[SIMECKBYTES+j] = tmp_pt[SIMECKBYTES+j]^(0xff);
                tmp_pt[2*SIMECKBYTES-1] = tmp_pt[2*SIMECKBYTES-1]^SC2_192[i]; // x1' = SC[1]^x2^F(x3)//
                
                for ( j = 0; j < SIMECKBYTES; j++ )
                        tmp_pt[2*SIMECKBYTES + j ] = simeck_inp[j]; // x2' = F(x3)//
                
                for ( j = 0; j < SIMECKBYTES; j++ )
                        tmp_pt[3*SIMECKBYTES + j ] = tmp_block[j]; // x3' = RC[0]^x0^F(x1)//
                
                //sliscp_print_state192(tmp_pt); // Printing intermediate state
        }
        for ( i = 0; i < STATEBYTES; i++ )
                input[i] = tmp_pt[i];
        
        free(tmp_pt);
        free(tmp_block);
        free(simeck_inp);
        return;
}

/*
  *sliscp_permutation192r18_ALLZERO: print output on input all-zero (0^192)
  *state: output
*/
void sliscp_permutation192r18_ALLZERO ( uint8_t *state )
{
        uint8_t i;
        
        for ( i = 0; i < STATEBYTES; i++ )
                state[i] = 0x0;
        sliscp_print_state192( state );
        sliscp_permutation192r18(state);
        sliscp_print_state192( state );
        return;
}

/*
  *sliscp_permutation192r18_ALLONE: print output on input all-one (1^192)
  *state: output
*/
void sliscp_permutation192r18_ALLONE ( uint8_t *state )
{
        uint8_t i;
        
        for ( i = 0; i < STATEBYTES; i++ )
                state[i] = 0xff;
        sliscp_print_state192(state);
        sliscp_permutation192r18(state);
        return;
}
