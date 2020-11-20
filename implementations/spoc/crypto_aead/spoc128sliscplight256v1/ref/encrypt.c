/* Reference Implementation of SpoC128-128 AEAD
   Written by:
   Kalikinkar Mandal <kmandal@uwaterloo.ca>
*/

#include<stdio.h>
#include<math.h>
#include<stdlib.h>
#include<stdint.h>

#include "sliscp_light256.h"
#include "crypto_aead.h" 
#include "api.h" 

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

/*
   *rate_bytes256: positions of rate bytes in state
*/
const unsigned char rate_bytes256[16] = {0,1,2,3,4,5,6,7,16,17,18,19,20,21,22,23};
/*
   *masking_bytes256: positions of masked capacity bytes in state
*/
const unsigned char masking_bytes256[16] = {8,9,10,11,12,13,14,15,24,25,26,27,28,29,30,31};

/*
   *spoc128_init: initialization with key and nonce
   *k: key 
   *npub: nonce
   *state: state after initialization
*/
int spoc128_init(
			unsigned char *state, 
			const unsigned char *npub,
			const unsigned char *k
			)
{
	unsigned char i;

	// Initialize the state to all-ZERO 
	for ( i = 0; i < STATEBYTES; i++ )
		state[i] = 0x0;
		
	if ( CRYPTO_KEYBYTES == 16 && CRYPTO_NPUBBYTES == 16 )
	{
		//Assigning nonce
		for ( i = 0; i < 16; i++ )
			state[rate_bytes256[i]] = npub[i];

		//Initial assignment of Key
		for ( i = 0; i < 16; i++ )
			state[masking_bytes256[i]] = k[i];
		
	}
	else
	{
		return KAT_CRYPTO_FAILURE;
	}
return KAT_SUCCESS;
}

/*
   *spoc128_ad: processing associated data
   *adlen: byte-length of ad
   *ad: associated data
   *state: state after initialization, 
           and output state is stored 
	   in "state" (inplace) 
*/
int spoc128_ad(
			unsigned char *state,
			const unsigned char *ad, 
			const u64 adlen
		     )
{
	unsigned char i, lblen;
	u64 j, ad128len = adlen/16;
	lblen = (unsigned char)(adlen%16);

	if ( adlen == 0 )
		return(KAT_SUCCESS);
	
	//Absorbing associated data
	for ( j = 0; j < ad128len; j++ )
	{
                sliscp_permutation256r18(state);
		for ( i = 0; i < 16; i++ )
			state[masking_bytes256[i]]^=ad[16*j+((u64)i)];
		//ctrl_ad_full
                state[0] = state[0]^0x20;
	}

	//Process the padded 64-bit block.
	if ( lblen != 0 )
	{
                sliscp_permutation256r18(state );
		for ( i = 0; i < lblen; i++ )
			state[masking_bytes256[i]]^=ad[ad128len*16+(u64)i];
		state[masking_bytes256[lblen]]^=(0x80);
                //ctrl_ad_par
                state[0] = state[0]^0x30;
                
	}

return (KAT_SUCCESS);
}

/*
   *spoc128_gentag: generate tag
   *k: key
   *state: state before tag generation
   *tlen: length of tag in byte
   *tag: tag
*/
int spoc128_gentag(
			unsigned char *tag, 
			const unsigned char tlen,
			unsigned char *state 
		        )
{
	unsigned char i;
	if ( CRYPTO_KEYBYTES == 16 && tlen == 16 )
	{
                //ctrl_tag
                state[0] = state[0]^(0x80);
                
		sliscp_permutation256r18(state);
		//Extracting 128-bit tag from X1 and X3
		for ( i = 0; i < 8; i++ )
		{
			tag[i] = state[8+i];
			tag[8+i] = state[24+i];
		}
	}
	else
	{
		printf("Invalid key and tag length pair.\n");
		return KAT_CRYPTO_FAILURE;
	}
return KAT_SUCCESS;
}

/*
   *crypto_aead_encrypt: encrypt message and produce tag
   *k: key 
   *npub: nonce
   *nsec: NULL
   *adlen: length of ad
   *ad: associated data
   *mlen: length of message
   *m: message to be encrypted
   *clen: ciphertext length + tag length
   *c: ciphertext, followed by tag
*/
int crypto_aead_encrypt(
			unsigned char *c,unsigned long long *clen,
			const unsigned char *m,unsigned long long mlen,
			const unsigned char *ad,unsigned long long adlen,
			const unsigned char *nsec,
			const unsigned char *npub,
			const unsigned char *k
			)
{
	//avoiding unused parameter warning
	nsec=nsec;

	unsigned char *state;
	unsigned char *tag;
	unsigned char i, lblen;
	//int func_ret;
	u64 j, m128len;
	
	m128len = mlen/16;
	lblen = (unsigned char)(mlen%16);

	state = (unsigned char *)malloc(sizeof(unsigned char)*STATEBYTES);
	tag = (unsigned char *)malloc(sizeof(unsigned char)*CRYPTO_ABYTES);

	//Initialize state with "key" and "nonce" and then absorbe "key" again
	if ( spoc128_init(state, npub, k)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);

	//Absorbing "ad"
	if ( adlen != 0 )
	{
		if ( spoc128_ad( state, ad, adlen) != KAT_SUCCESS)
			return(KAT_CRYPTO_FAILURE);
	}
	
	//Encrypting "message(m)" and producing "ciphertext (c)"
	if ( mlen != 0 )
	{
		for ( j = 0; j < m128len; j++ )
		{
                        sliscp_permutation256r18(state);
			for ( i = 0; i < 16; i++ )
			{
				c[16*j+((u64)i)] = m[16*j+((u64)i)]^state[rate_bytes256[i]];
				state[masking_bytes256[i]]^=m[16*j+((u64)i)];
			}
			//ctrl_pt
                        state[0] = state[0]^(0x40);
		}

		if ( lblen != 0 )
		{
                        sliscp_permutation256r18(state);
			for ( i = 0; i < lblen; i++ )
			{
				c[16*m128len+((u64)i)] = m[m128len*16+(u64)i]^state[rate_bytes256[i]];
				state[masking_bytes256[i]]^=m[m128len*16+(u64)i];
			}
			state[masking_bytes256[i]]^=(0x80); //Padding: 10*
                	//ctrl_pt_par
                        state[0] = state[0]^(0x50);
		}
	}

        //Appending tag to the end of ciphertext
	if ( spoc128_gentag( tag, CRYPTO_ABYTES, state ) != KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);
        else
        {
                for ( i = 0; i < CRYPTO_ABYTES; i++ )
                        c[mlen+(u64)i] = tag[i];
        }
	*clen = mlen+CRYPTO_ABYTES;

	/*printf("Print tag:\n");
	for ( i = 0; i < 16; i++ )
		printf("%.2x ", tag[i]);
	printf("\n");*/

	free(state);
	free(tag);
return KAT_SUCCESS;
}

/*
   *crypto_aead_decrypt: decrypt ciphertext and verify tag
   *k: key 
   *npub: nonce
   *nsec: NULL
   *adlen: length of ad
   *ad: associated data
   *clen: ciphertext length + tag length
   *c: ciphertext, followed by tag
   *mlen: length of message
   *m: message
*/
int crypto_aead_decrypt(
			unsigned char *m,unsigned long long *mlen,
			unsigned char *nsec,
			const unsigned char *c,unsigned long long clen,
			const unsigned char *ad,unsigned long long adlen,
			const unsigned char *npub,
			const unsigned char *k
			)
{
	//avoiding unused parameter warning
	nsec=nsec;
	
	unsigned char i, lblen;
	u64 j, clen1, c128len;
        clen1 = (clen-CRYPTO_ABYTES);
        c128len = clen1/16;
	lblen = (unsigned char)(clen1%16);
	
	unsigned char *state;
	unsigned char *tag;

	state = (unsigned char *)malloc(sizeof(unsigned char)*STATEBYTES);
	tag = (unsigned char *)malloc(sizeof(unsigned char)*CRYPTO_ABYTES);

	//Initialize state with "key" and "nonce" and then absorbe "key" again
	if ( spoc128_init(state, npub, k)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);

	//Absorbing "ad"
	
	if ( adlen != 0 )
	{
		if ( spoc128_ad( state, ad, adlen) != KAT_SUCCESS)
			return(KAT_CRYPTO_FAILURE);
	}

	if ( clen1 != 0 )
	{
		for ( j = 0; j < c128len; j++ )
		{
                        sliscp_permutation256r18(state);
			for ( i = 0; i < 16; i++ )
			{
				m[16*j+((u64)i)] = c[16*j+((u64)i)]^state[rate_bytes256[i]];
				state[masking_bytes256[i]]^=m[16*j+((u64)i)];
                        }
			//ctrl_pt
                        state[0] = state[0]^(0x40);
		}
		//Decrypting last 64-bit block
		if ( lblen != 0 )
		{
                        sliscp_permutation256r18(state);
			for ( i = 0; i < lblen; i++ )
			{
				m[16*c128len +((u64)i)] = c[16*c128len +((u64)i)]^state[rate_bytes256[i]];
				state[masking_bytes256[i]]^= m[16*c128len +((u64)i)];
			}
			state[masking_bytes256[lblen]]^=(0x80); //Padding: 10*
                        //ctrl_pt_par
                        state[0] = state[0]^(0x50);
		}
	}

	//Generating and verifying the tag
	if ( spoc128_gentag( tag, CRYPTO_ABYTES, state ) != KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);
        else
        {
                for ( i = 0; i < CRYPTO_ABYTES; i++ )
                {
                        if ( c[clen1 + (u64)i] != tag[i] )
                                return -1; // authentication failure should result in return code -1.
                }
        }
	*mlen = clen-CRYPTO_ABYTES;

	/*printf("Print tag:\n");
	for ( i = 0; i < 16; i++ )
		printf("%.2x ", tag[i]);
	printf("\n");*/

	free(state);
	free(tag);
	
return KAT_SUCCESS;
}
