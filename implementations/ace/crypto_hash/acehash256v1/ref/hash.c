/* Reference Implementation of ACE-Hash256
 Written by:
 Kalikinkar Mandal <kmandal@uwaterloo.ca>
 */

#include<stdio.h>
#include<math.h>
#include<stdlib.h>
#include<stdint.h>

#include "ace.h"
#include "crypto_hash.h" 
#include "api.h" 

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

/*
 *rate_bytes: positions of rate bytes in state
*/
const unsigned char rate_bytes[8] = {0,1,2,3,16,17,18,19};

/*
   *acehash_init: initialize with IV
   *state: output state after initialization
*/
int acehash_init( unsigned char *state )
{
	unsigned char i;

	//Initialize the state to all-ZERO 
	for ( i = 0; i < STATEBYTES; i++ )
		state[i] = 0x0;
	if ( CRYPTO_BYTES == 32 )
	{
		//Initialize state with IV 0x804040
                //According to specification: B[7] = 0x80; B[6] = 0x40; B[5] = 0x40;
		state[8] = 0x80;
		state[9] = 0x40;
		state[10] = 0x40;
		ace_permutation(state);
	}
	else
	{
		return KAT_CRYPTO_FAILURE;
	}
return KAT_SUCCESS;
}

/*
   *crypto_hash: compute hash/message digest on "in"
   *inlen: input length
   *in: input
*/
int crypto_hash(
	unsigned char *out,
	const unsigned char *in,
	unsigned long long inlen
	)
{
	unsigned char *state;
	unsigned char i, lblen;
	//int func_ret;
	u64 j, in64len;

	in64len = inlen/8;
	lblen = (unsigned char)(inlen%8);

	state = (unsigned char *)malloc(sizeof(unsigned char)*STATEBYTES);

	//Initialize state with predefined IV.
	if ( acehash_init(state)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);

	//Absorbing phase: Rate Bytes A[0],A[1],A[2],A[3],C[0],C[1],C[2],C[3]
	if ( inlen != 0 )
	{

		for ( j = 0; j < in64len; j++ )
		{
			for ( i = 0; i < 8; i++ )
				state[rate_bytes[i]]^=in[8*j+((u64)i)];
			ace_permutation(state);
		}

		if ( lblen != 0 )
		{
			//Encrypting the padded 64-bit block when "mlen" is not a multiple of 8
			for ( i = 0; i < lblen; i++ )
				state[rate_bytes[i]]^= in[in64len*8+(u64)i];
			
			state[rate_bytes[lblen]]^=(0x80); //Padding: 10*
			ace_permutation(state);
		}
		else
		{
			state[rate_bytes[0]]^=(0x80); //Padding: 10*
			ace_permutation(state);
		}
	}
	else
	{
		state[rate_bytes[0]]^=(0x80); //Padding: 10*
		ace_permutation(state);
	}
	//Squeezing phase
	if ( CRYPTO_BYTES == 32 )
	{
		for ( i = 0; i < 8; i++ )
			out[i] = state[rate_bytes[i]];
		ace_permutation(state);
		for ( i = 0; i < 8; i++ )
			out[i+8] = state[rate_bytes[i]];
		ace_permutation(state);
		for ( i = 0; i < 8; i++ )
			out[i+16] = state[rate_bytes[i]];
		ace_permutation(state);
		for ( i = 0; i < 8; i++ )
			out[i+24] = state[rate_bytes[i]];
	}
	else
		out=NULL;
free(state);

return KAT_SUCCESS;
}
