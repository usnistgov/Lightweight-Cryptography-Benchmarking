/* Reference implementation of the ACE permutation
   Written by:
   Kalikinkar Mandal <kmandal@uwaterloo.ca>
*/

#include<stdio.h>
#include<math.h>
#include<stdlib.h>
#include<stdint.h>
#include "ace.h"

/*
   *SC0: step constants, applied on B
   *SC1: step constants, applied on D
   *SC2: step constants, applied on E
*/
static const unsigned char SC0[16]={0x50,0x5c,0x91,0x8d,0x53,0x60,0x68,0xe1,0xf6,0x9d,0x40,0x4f,0xbe,0x5b,0xe9,0x7f}; //Step constants (SC_{2i})
static const unsigned char SC1[16]={0x28,0xae,0x48,0xc6,0xa9,0x30,0x34,0x70,0x7b,0xce,0x20,0x27,0x5f,0xad,0x74,0x3f}; //Step constants (SC_{2i+1})
static const unsigned char SC2[16]={0x14,0x57,0x24,0x63,0x54,0x18,0x9a,0x38,0xbd,0x67,0x10,0x13,0x2f,0xd6,0xba,0x1f}; //Step constants (SC_{2i+2})

/*
   *RC0: round constants of simeck box applied on A
   *RC1: round constants of simeck box applied on C
   *RC2: round constants of simeck box applied on E
*/
static const unsigned char RC0[16]={0x07,0x0a,0x9b,0xe0,0xd1,0x1a,0x22,0xf7,0x62,0x96,0x71,0xaa,0x2b,0xe9,0xcf,0xb7};//Round constants (RC_{2i})
static const unsigned char RC1[16]={0x53,0x5d,0x49,0x7f,0xbe,0x1d,0x28,0x6c,0x82,0x47,0x6b,0x88,0xdc,0x8b,0x59,0xc6};//Round constants (RC_{2i+1})
static const unsigned char RC2[16]={0x43,0xe4,0x5e,0xcc,0x32,0x4e,0x75,0x25,0xfd,0xf9,0x76,0xa0,0xb0,0x09,0x1e,0xad};//Round constants (RC_{2i+2})

unsigned char rotl8 ( const unsigned char x, const unsigned char y, const unsigned char shift )
{
	return ((x<<shift)|(y>>(8-shift)));
}

/***********************************************************
  ******* ACE permutation implementation********************
  *********************************************************/

void ace_print_state( const unsigned char *state )
{
	unsigned char i;
	for ( i = 0; i < STATEBYTES; i++ )
		printf("%.2x ", state[i]);
	printf("\n");
}

void  ace_print_data(const uint8_t *x, const uint32_t xlen )
{
		uint32_t j;
			for ( j = 0; j < xlen; j++ )
						printf("%.2x ", x[j]);
				printf("\n");
				return;
}

/*
   *simeck64_box: 64-bit simeck sbox
   *rc: 8-bit round constant
   *input: 64-bit input
   *output: 64-bit output
*/
void simeck64_box( unsigned char *output, const unsigned char *input, const unsigned char rc )
{
	unsigned char i, t;
	unsigned char *tmp_shift_1, *tmp_shift_5, *tmp_pt;

	tmp_shift_1 = (unsigned char *)malloc(4*sizeof(unsigned char));
	tmp_shift_5 = (unsigned char *)malloc(4*sizeof(unsigned char));
	tmp_pt = (unsigned char *)malloc(SIMECKBYTES*sizeof(unsigned char));

	for ( i = 0; i < SIMECKBYTES; i++ )
		tmp_pt[i] = input[i];

	for ( i = 0; i < SIMECKROUND; i++ )
	{
		tmp_shift_1[0] = rotl8(tmp_pt[0], tmp_pt[1],1);
		tmp_shift_1[1] = rotl8(tmp_pt[1], tmp_pt[2],1);
		tmp_shift_1[2] = rotl8(tmp_pt[2], tmp_pt[3],1);
		tmp_shift_1[3] = rotl8(tmp_pt[3], tmp_pt[0],1);

		tmp_shift_5[0] = rotl8(tmp_pt[0], tmp_pt[1],5);
		tmp_shift_5[1] = rotl8(tmp_pt[1], tmp_pt[2],5);
		tmp_shift_5[2] = rotl8(tmp_pt[2], tmp_pt[3],5);
		tmp_shift_5[3] = rotl8(tmp_pt[3], tmp_pt[0],5);

		tmp_shift_5[0] = tmp_shift_5[0]&tmp_pt[0];
		tmp_shift_5[1] = tmp_shift_5[1]&tmp_pt[1];
		tmp_shift_5[2] = tmp_shift_5[2]&tmp_pt[2];
		tmp_shift_5[3] = tmp_shift_5[3]&tmp_pt[3];

		tmp_shift_1[0] = tmp_shift_1[0]^tmp_shift_5[0];
		tmp_shift_1[1] = tmp_shift_1[1]^tmp_shift_5[1];
		tmp_shift_1[2] = tmp_shift_1[2]^tmp_shift_5[2];
		tmp_shift_1[3] = tmp_shift_1[3]^tmp_shift_5[3];
		
		tmp_shift_1[0] = tmp_shift_1[0]^tmp_pt[4]^(0xff);
		tmp_shift_1[1] = tmp_shift_1[1]^tmp_pt[5]^(0xff);
		tmp_shift_1[2] = tmp_shift_1[2]^tmp_pt[6]^(0xff);
		tmp_shift_1[3] = tmp_shift_1[3]^tmp_pt[7]^(0xfe);

		t = (rc >> i)&1;
		tmp_shift_1[3] = tmp_shift_1[3]^t;

		tmp_pt[4] = tmp_pt[0];
		tmp_pt[5] = tmp_pt[1];
		tmp_pt[6] = tmp_pt[2];
		tmp_pt[7] = tmp_pt[3];

		tmp_pt[0] = tmp_shift_1[0];
		tmp_pt[1] = tmp_shift_1[1];
		tmp_pt[2] = tmp_shift_1[2];
		tmp_pt[3] = tmp_shift_1[3];

		//simeck_print_data(tmp_pt, 8);
	}
	for ( i = 0; i < SIMECKBYTES; i++ )
		output[i] = tmp_pt[i];
free(tmp_shift_1);
free(tmp_shift_5);
free(tmp_pt);
return;
}

/*
   *ace_permutation: 16-round ACE permutation of width 320 bits
   *input: 320-bit input, and output is stored in input (inplace) 
*/
void ace_permutation( unsigned char *input )
{
	unsigned char i, j;
	unsigned char *tmp_inp, *tmp_a, *tmp_c, *tmp_e;

	tmp_inp = (unsigned char *)malloc(STATEBYTES*sizeof(unsigned char));
	tmp_a = (unsigned char *)malloc(SIMECKBYTES*sizeof(unsigned char));
	tmp_c = (unsigned char *)malloc(SIMECKBYTES*sizeof(unsigned char));
	tmp_e = (unsigned char *)malloc(SIMECKBYTES*sizeof(unsigned char));

	for ( i = 0; i < STATEBYTES; i++ )
		tmp_inp[i] = input[i];

	for ( i = 0; i < NUMSTEPS; i++ )
	{
		//A block
		for ( j = 0; j < SIMECKBYTES; j++ )
			tmp_a[j] = tmp_inp[j];
		simeck64_box( tmp_a, tmp_a, RC0[i] );

		//C block
		for ( j = 0; j < SIMECKBYTES; j++ )
			tmp_c[j] = tmp_inp[2*SIMECKBYTES+j];
		simeck64_box( tmp_c, tmp_c, RC1[i] );
		
		//E block
		for ( j = 0; j < SIMECKBYTES; j++ )
			tmp_e[j] = tmp_inp[4*SIMECKBYTES+j];
		simeck64_box( tmp_e, tmp_e, RC2[i] );

		// Update A: A <= SC_{3i+1}+D+F(E)
		for ( j = 0; j < SIMECKBYTES-1; j++ )
			tmp_inp[j] = tmp_inp[3*SIMECKBYTES+j]^tmp_e[j]^(0xff);
		tmp_inp[SIMECKBYTES-1] = tmp_inp[4*SIMECKBYTES-1]^tmp_e[SIMECKBYTES-1]^SC1[i];
		
		// Update E: E <= SC_{3i}+B+F(C)
		for ( j = 0; j < SIMECKBYTES-1; j++ )
			tmp_inp[4*SIMECKBYTES+j] = tmp_inp[SIMECKBYTES+j]^tmp_c[j]^(0xff);
		tmp_inp[5*SIMECKBYTES-1] = tmp_inp[2*SIMECKBYTES-1]^tmp_c[SIMECKBYTES-1]^SC0[i];

		// Update B: B <= F(C)
		for ( j = 0; j < SIMECKBYTES; j++ )
			tmp_inp[SIMECKBYTES+j] = tmp_c[j];
		
		// Update C: C <= F(A)
		for ( j = 0; j < SIMECKBYTES; j++ )
			tmp_inp[2*SIMECKBYTES+j] = tmp_a[j];
		
		// Update D: D <= SC_{3i+2}+F(A)+F(E)
		for ( j = 0; j < SIMECKBYTES-1; j++ )
			tmp_inp[3*SIMECKBYTES+j] = tmp_a[j]^tmp_e[j]^(0xff);
		tmp_inp[4*SIMECKBYTES-1] = tmp_a[SIMECKBYTES-1]^tmp_e[SIMECKBYTES-1]^SC2[i];
		//ace_print_state256(tmp_pt); // Printing intermediate state
	}
	for ( i = 0; i < STATEBYTES; i++ )
		input[i] = tmp_inp[i];

free(tmp_a);
free(tmp_c);
free(tmp_e);
free(tmp_inp);
return;
}

/*
  *ace_permutation_ALLZERO: compute output on input all-zero (0^320)
  *state: output
*/
void ace_permutation_ALLZERO ( unsigned char *state )
{
	unsigned char i;
	
	for ( i = 0; i < STATEBYTES; i++ )
		state[i] = 0x0;
	ace_print_state(state);
	ace_permutation(state);
return;
}

/*
  *ace_permutation_ALLONE: compute output on input all-one (1^320)
  *state: output
*/
void ace_permutation_ALLONE ( unsigned char *state )
{
	unsigned char i;
	
	for ( i = 0; i < STATEBYTES; i++ )
		state[i] = 0xff;
	//ace_print_state( state );
	ace_permutation(state);
return;
}

