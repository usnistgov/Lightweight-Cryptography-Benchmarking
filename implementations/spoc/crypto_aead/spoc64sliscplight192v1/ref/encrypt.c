

/* Reference implementation of SpoC64-128, AEAD
   Written by:
   Kalikinkar Mandal <kmandal@uwaterloo.ca>
*/

#include<stdio.h>
#include<math.h>
#include<stdlib.h>
#include<stdint.h>

#include "sliscp_light192.h"
#include "crypto_aead.h" 
#include "api.h" 

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

/*
   *rate_bytes192: positions of rate bytes in state
*/
const unsigned char rate_bytes192[8] = {0,1,2,3,12,13,14,15};
/*
   *masking_bytes192: positions of masked capacity bytes in state
*/
const unsigned char masking_bytes192[8] = {6,7,8,9,18,19,20,21};

/*
   *spoc64_init: initialization with key and nonce
   *k: key 
   *npub: nonce
   *state: state after initialization
*/
int spoc64_init(
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
		//load-SpoC-64(N,K):
		//Assigning nonce
		for ( i = 0; i < 4; i++ )
			state[i] = npub[i];
		for ( i = 0; i < 4; i++ )
			state[12+i] = npub[4+i];

		//Assigning key
		for ( i = 0; i < 6; i++ )
			state[6+i] = k[i];
		state[4] = k[6]; 
		state[5] = k[7];
		for ( i = 0; i < 6; i++ )
			state[18+i] = k[8+i];
		state[16] = k[14]; 
		state[17] = k[15];
		
		sliscp_permutation192r18(state );

		for ( i = 0; i < 8; i++ )
			state[masking_bytes192[i]]^=npub[i+8];
	}
	else
	{
		return KAT_CRYPTO_FAILURE;
	}
return KAT_SUCCESS;
}

/*
   *spoc64_ad: processing associated data
   *adlen: byte-length of ad
   *ad: associated data
   *state: state after initialization, 
           and output state is stored 
	   in "state" (inplace) 
*/
int spoc64_ad(
			unsigned char *state,
			const unsigned char *ad, 
			const u64 adlen
		     )
{
	unsigned char i, lblen;
	u64 j, ad64len = adlen/8;
	lblen = (unsigned char)(adlen%8);

	if ( adlen == 0 )
		return(KAT_SUCCESS);
	
	//Absorbing associated data
	for ( j = 0; j < ad64len; j++ )
	{
                sliscp_permutation192r18(state);
		for ( i = 0; i < 8; i++ )
			state[masking_bytes192[i]]^=ad[8*j+((u64)i)];
		//ctrl_ad_full
                state[0] = state[0]^(0x20);
	}

	//Processing the last 64-bit block if "adlen" is not a multiple of 8
	if ( lblen != 0 )
	{
                sliscp_permutation192r18(state);
		for ( i = 0; i < lblen; i++ )
			state[masking_bytes192[i]]^=ad[ad64len*8+(u64)i];

                state[masking_bytes192[lblen]]^=0x80; //Padding: 10*
                //ctrl_ad_par
                state[0] = state[0]^(0x30);
	}

return (KAT_SUCCESS);
}

/*
   *spoc64_gentag: generate tag
   *k: key
   *state: state before tag generation
   *tlen: length of tag in byte
   *tag: tag
*/
int spoc64_gentag(
			unsigned char *tag, 
			const unsigned char tlen,
			unsigned char *state 
		        )
{
	unsigned char i;
	if ( CRYPTO_KEYBYTES == 16 && tlen == 8 )
	{
		//ctrl_tag
		state[0] = state[0]^(0x80);
		sliscp_permutation192r18(state );
		//Extracting 64-bit tag from X1 and X3
		for ( i = 0; i < 4; i++ )
		{
			tag[i] = state[6+i];
			tag[4+i] = state[18+i];
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
	u64 j, m64len;

	m64len = mlen/8;
	lblen = (unsigned char)(mlen%8);

	state = (unsigned char *)malloc(sizeof(unsigned char)*STATEBYTES);
	tag = (unsigned char *)malloc(sizeof(unsigned char)*CRYPTO_ABYTES);

	//Initialize state with "key" and "nonce" and then absorbe "nonce" again
	if ( spoc64_init(state, npub, k)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);
	//Absorbing "ad" if non-empty
	if ( adlen != 0 )
	{
		if ( spoc64_ad( state, ad, adlen) != KAT_SUCCESS)
			return(KAT_CRYPTO_FAILURE);
	}
	
	if ( mlen != 0 )
	{
		//Encrypting "message(m)" and producing "ciphertext (c)"
		for ( j = 0; j < m64len; j++ )
		{
                        sliscp_permutation192r18(state);
			for ( i = 0; i < 8; i++ )
			{
				c[8*j+((u64)i)] = m[8*j+((u64)i)]^state[rate_bytes192[i]];
				state[masking_bytes192[i]]^=m[8*j+((u64)i)];
			}
			//ctrl_pt
                        state[0] = state[0]^(0x40);
		}

		if ( lblen != 0 )
		{
                        sliscp_permutation192r18(state);
			for ( i = 0; i < lblen; i++ )
			{
				c[8*m64len+((u64)i)] = m[m64len*8+(u64)i]^state[rate_bytes192[i]];
				state[masking_bytes192[i]]^=m[8*m64len+((u64)i)];
			}
			state[masking_bytes192[lblen]]^=(0x80); //Padding: 10*
                        //ctrl_pt_par
                        state[0] = state[0]^(0x50);
		}
	}
	*clen = mlen+CRYPTO_ABYTES;

        //Appending tag to the end of ciphertext
	if ( spoc64_gentag( tag, CRYPTO_ABYTES, state ) != KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);
        else
        {
                for ( i = 0; i < CRYPTO_ABYTES; i++ )
                        c[mlen+(u64)i] = tag[i];
        }
	
	/*printf("Print tag:\n");
	for ( i = 0; i < 8; i++ )
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
	u64 j, clen1, c64len;
        clen1 = clen-CRYPTO_ABYTES;
        c64len = clen1/8;
        lblen = (unsigned char)(clen1%8);
        
        //If clen < the tag length, return error.
        if ( clen < CRYPTO_ABYTES)
                return(KAT_CRYPTO_FAILURE);
	
	unsigned char *state;
	unsigned char *tag;

	state = (unsigned char *)malloc(sizeof(unsigned char)*STATEBYTES);
	tag = (unsigned char *)malloc(sizeof(unsigned char)*CRYPTO_ABYTES);

	//Initialize state with "key" and "nonce" and then absorbe "key" again
	if ( spoc64_init(state, npub, k)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);

	//Absorbing "ad"
	if (adlen != 0 )
	{
		if ( spoc64_ad( state, ad, adlen) != KAT_SUCCESS)
			return(KAT_CRYPTO_FAILURE);
	}

	if ( clen1 != 0 )
	{
		for ( j = 0; j < c64len; j++ )
		{
                        sliscp_permutation192r18(state);
			for ( i = 0; i < 8; i++ )
			{
				m[8*j+((u64)i)] = c[8*j+((u64)i)]^state[rate_bytes192[i]];
				state[masking_bytes192[i]]^=m[8*j+((u64)i)];
			}
                        //ctrl_pt
                        state[0] = state[0]^(0x40);
		}

		if ( lblen != 0 )
		{
                        sliscp_permutation192r18(state);
			for ( i = 0; i < lblen; i++ )
			{
				m[8*c64len +((u64)i)] = c[8*c64len +((u64)i)]^state[rate_bytes192[i]];
				state[masking_bytes192[i]]^=m[8*c64len +((u64)i)];
			}
			state[masking_bytes192[lblen]]^=(0x80); //Padding 10*
			//ctrl_pt_par
                        state[0] = state[0]^(0x50);
		}
	}
        
	//Generating and verifying the tag
	if ( spoc64_gentag( tag, CRYPTO_ABYTES, state ) != KAT_SUCCESS )
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
	for ( i = 0; i < 8; i++ )
		printf("%.2x ", tag[i]);
	printf("\n");*/

	free(state);
	free(tag);
	
return KAT_SUCCESS;
}
