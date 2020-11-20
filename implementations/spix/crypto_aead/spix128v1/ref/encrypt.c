
/* Reference implementation of SPIX-128 AEAD
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
const unsigned char rate_bytes256[8] = {8,9,10,11,24,25,26,27};

/*
   *spix_init: initialization with key and nonce
   *k: key 
   *npub: nonce
   *state: state after initialization
*/
int spix_init(
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
		for ( i = 0; i < 8; i++ )
			state[i] = npub[i];
		for ( i = 0; i < 8; i++ )
			state[16+i] = npub[8+i];

		//Initial assignment of Key
		for ( i = 0; i < 8; i++ )
			state[8+i] = k[i];
		for ( i = 0; i < 8; i++ )
			state[24+i] = k[8+i];
		
		sliscp_permutation256r18(state );

		//Absorbing first 64-bit key again
		for ( i = 0; i < 8; i++ )
			state[rate_bytes256[i]]^=k[i];

		sliscp_permutation256r18(state);

		//Absorbing last 64-bit key again
		for ( i = 0; i < 8; i++ )
			state[rate_bytes256[i]]^=k[8+i];

		sliscp_permutation256r18(state);
	}
	else
	{
		return KAT_CRYPTO_FAILURE;
	}
return KAT_SUCCESS;
}

/*
   *spix_ad: processing associated data
   *adlen: byte-length of ad
   *ad: associated data
   *state: state after initialization, 
           and output state is stored 
	   in "state" (inplace) 
*/
int spix_ad(
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
        if ( adlen != 0 )
        {
                for ( j = 0; j < ad64len; j++ )
                {
                        for ( i = 0; i < 8; i++ )
                                state[rate_bytes256[i]]^=ad[8*j+((u64)i)];
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x01);
                        sliscp_permutation256r9(state);
                }

                //Process the last 64-bit block if "adlen" is not a multiple of 8 bytes
                if ( lblen != 0 )
                {
                        for ( i = 0; i < lblen; i++ )
                                state[rate_bytes256[i]]^=ad[ad64len*8+(u64)i];
                        state[rate_bytes256[lblen]]^=(0x80); // Padding: 10*
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x01);
                        sliscp_permutation256r9(state );
                }
		else
		{
			state[rate_bytes256[0]]^=(0x80); //Padding: 10*
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x01);
                        sliscp_permutation256r9(state );
		}
        }

return (KAT_SUCCESS);
}

/*
   *spix_gentag: generate tag
   *k: key
   *state: state before tag generation
   *tlen: length of tag in byte
   *tag: tag
*/
int spix_gentag(
                unsigned char *tag,
                const unsigned char tlen,
                unsigned char *state,
                const unsigned char *k
                )
{
        unsigned char i;
        if ( CRYPTO_KEYBYTES == 16 && tlen == 16 )
        {
		//Absorbing first 64-bit (8 bytes) key
                for ( i = 0; i < 8; i++ )
                        state[rate_bytes256[i]]^=k[i];
                sliscp_permutation256r18(state );
                
		//Absorbing last 64-bit key
                for ( i = 0; i < 8; i++ )
                        state[rate_bytes256[i]]^=k[8+i];
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
	unsigned char *state;
	unsigned char *tag;
	unsigned char i, lblen;
	u64 j, m64len;

	m64len = mlen/8;
	lblen = (unsigned char)(mlen%8);

	nsec=nsec;

	state = (unsigned char *)malloc(sizeof(unsigned char)*STATEBYTES);
	tag = (unsigned char *)malloc(sizeof(unsigned char)*CRYPTO_ABYTES);

	//Initialize state with "key" and "nonce" and then absorbe "key" again
	if ( spix_init (state, npub, k)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);

	//Absorbing "ad"
        if ( adlen != 0 )
        {
                if ( spix_ad( state, ad, adlen) != KAT_SUCCESS)
                        return(KAT_CRYPTO_FAILURE);
        }

	//Encrypting "message(m)" and producing "ciphertext (c)"
        if ( mlen != 0 )
        {
                for ( j = 0; j < m64len; j++ )
                {
                        for ( i = 0; i < 8; i++ )
                        {
                                c[8*j+((u64)i)] = m[8*j+((u64)i)]^state[rate_bytes256[i]];
                                state[rate_bytes256[i]] = c[8*j+((u64)i)];
                        }
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
                        sliscp_permutation256r9(state);
                }
                if ( lblen != 0 )
                {
                        //Encrypting the padded 64-bit block when "mlen" is not a multiple of 8
                        for ( i = 0; i < lblen; i++ )
                        {
                                c[8*m64len+((u64)i)]=m[8*m64len+((u64)i)]^state[rate_bytes256[i]];
                                state[rate_bytes256[i]]=c[8*m64len+((u64)i)];
                        }
                        state[rate_bytes256[lblen]]^=(0x80);// Padding: 10*
                       
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
                        sliscp_permutation256r9(state);
                }
                else
                {
                        state[rate_bytes256[0]]^=(0x80);// Padding: 10*
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
                        sliscp_permutation256r9(state);
                }
        }
        else
        {
                state[rate_bytes256[0]]^=(0x80);// Padding: 10*
                //Domain seperator
                state[STATEBYTES-1]^=(0x02);
                sliscp_permutation256r9(state);
        }
        
        //Appending tag to the end of ciphertext
	if ( spix_gentag ( tag, CRYPTO_ABYTES, state, k ) != KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);
        else
        {
                for ( i = 0; i < CRYPTO_ABYTES; i++ )
                        c[mlen+(u64)i] = tag[i];
        }
	*clen = mlen+CRYPTO_ABYTES;

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
	unsigned char i, lblen;
	u64 j, clen1, c64len;
        clen1 = clen - CRYPTO_ABYTES;
        c64len = clen1/8;
	lblen = (unsigned char)(clen1%8);
	nsec=nsec;
	
	unsigned char *state;
	unsigned char *tag;

	state = (unsigned char *)malloc(sizeof(unsigned char)*STATEBYTES);
	tag = (unsigned char *)malloc(sizeof(unsigned char)*CRYPTO_ABYTES);

	//Initialize state with "key" and "nonce" and then absorbe "key" again
	if ( spix_init (state, npub, k)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);

	//Absorbing "ad"
        if ( adlen != 0 )
        {
                if ( spix_ad( state, ad, adlen) != KAT_SUCCESS)
                        return(KAT_CRYPTO_FAILURE);
        }

        if ( clen1 != 0 )
        {
                for ( j = 0; j < c64len; j++ )
                {
                        for ( i = 0; i < 8; i++ )
                        {
                                m[8*j+((u64)i)] = c[8*j+((u64)i)]^state[rate_bytes256[i]];
                                state[rate_bytes256[i]] = c[8*j+((u64)i)];
                        }
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
                        sliscp_permutation256r9(state);
                }

                if ( lblen != 0 )
                {
                        //Decrypting last 64-bit block
                        for ( i = 0; i < lblen; i++ )
                        {
                                m[8*c64len +((u64)i)]=c[8*c64len +((u64)i)]^state[rate_bytes256[i]];
                                state[rate_bytes256[i]]=c[8*c64len +((u64)i)];
                        }
                        state[rate_bytes256[lblen]]^=(0x80); //Padding: 10*

                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
                        sliscp_permutation256r9(state);
                }
                else
                {
                        state[rate_bytes256[0]]^=(0x80); //Padding: 10*
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
                        sliscp_permutation256r9(state);
                }
        }
        else
        {
                state[rate_bytes256[0]]^=(0x80); //Padding: 10*
                //Domain seperator
                state[STATEBYTES-1]^=(0x02);
                sliscp_permutation256r9(state);
        }
	
        //Generating and verifying the tag
	if ( spix_gentag ( tag, CRYPTO_ABYTES, state, k ) != KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);
        else
        {
                for ( i = 0; i < CRYPTO_ABYTES; i++ )
                {
                        if ( c[clen1 + (u64)i] != tag[i] )
                                return(KAT_CRYPTO_FAILURE);
                }
        }
	*mlen = clen-CRYPTO_ABYTES;

	free(state);
	free(tag);
	
return KAT_SUCCESS;
}
