/* Reference implementation of ACE-128 AEAD
   Written by:
   Kalikinkar Mandal <kmandal@uwaterloo.ca>
*/

#include<stdio.h>
#include<math.h>
#include<stdlib.h>
#include<stdint.h>

#include "ace.h"
#include "crypto_aead.h" 
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
   *ace_init: initialization with key and nonce
   *k: key 
   *npub: nonce
   *state: state after initialization
*/
int ace_init(
		unsigned char *state, 
		const unsigned char *npub,
		const unsigned char *k
	    )
{
	unsigned char i;

	//Initialize the state to all-ZERO 
	for ( i = 0; i < STATEBYTES; i++ )
		state[i] = 0x0;
		
	if ( CRYPTO_KEYBYTES == 16 && CRYPTO_NPUBBYTES == 16 )
	{
		//Assigning key at A[0..7] & C[0..7]
		for ( i = 0; i < 8; i++ )
			state[i] = k[i];
		for ( i = 0; i < 8; i++ )
			state[16+i] = k[8+i];

		//Assigning nonce at B[0..7] & E[0..7]
		for ( i = 0; i < 8; i++ )
			state[8+i] = npub[i];
		for ( i = 0; i < 8; i++ )
			state[32+i] = npub[8+i];
		
		ace_permutation(state);
		
		//Absorbing first 64-bit key
		for ( i = 0; i < 8; i++ )
			state[rate_bytes[i]]^=k[i];

		ace_permutation(state);
		
		//Absorbing last 64-bit key
		for ( i = 0; i < 8; i++ )
			state[rate_bytes[i]]^=k[8+i];

		ace_permutation(state);
	}
	else
	{
		return KAT_CRYPTO_FAILURE;
	}
return KAT_SUCCESS;
}

/*
   *ace_ad: processing associated data
   *adlen: byte-length of ad
   *ad: associated data
   *state: state after initialization, 
           and output state is stored 
	   in "state" (inplace) 
*/
int ace_ad(
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
		for ( i = 0; i < 8; i++ )
			state[rate_bytes[i]]^=ad[8*j+((u64)i)];
		//Domain seperator
                state[STATEBYTES-1]^=(0x01);
                
		ace_permutation(state);
	}

	//Process the last 64-bit block.
	if ( lblen != 0 )
	{
		for ( i = 0; i < lblen; i++ )
			state[rate_bytes[i]]^=ad[ad64len*8+(u64)i];

		state[rate_bytes[lblen]]^=(0x80); //Padding: 10*
		//Domain seperator 
		state[STATEBYTES-1]^=(0x01);
		ace_permutation(state );
	}
	else
	{
		state[rate_bytes[0]]^=(0x80); //Padding: 10*
                //Domain seperator
                state[STATEBYTES-1]^=(0x01);
		ace_permutation(state );
	}

return (KAT_SUCCESS);
}

/*
   *ace_gentag: generate tag
   *k: key
   *state: state before tag generation
   *tlen: length of tag in byte
   *tag: tag
*/
int ace_gentag(
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
                        state[rate_bytes[i]]^=k[i];
                
                ace_permutation(state);
                
                //Absorbing last 64-bit key
                for ( i = 0; i < 8; i++ )
                        state[rate_bytes[i]]^=k[8+i];
                
                ace_permutation(state);
                //Extracting 128-bit tag from A and C
                for ( i = 0; i < 8; i++ )
                {
                        tag[i] = state[i];
                        tag[8+i] = state[16+i];
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
	if ( ace_init(state, npub, k)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);
		
	//Absorbing "ad"
        if ( adlen != 0 )
        {
                if ( ace_ad( state, ad, adlen) != KAT_SUCCESS)
                        return(KAT_CRYPTO_FAILURE);
        }

	//Encrypting "message(m)" and producing "ciphertext (c)"
        if ( mlen != 0 )
        {
                for ( j = 0; j < m64len; j++ )
                {
                        for ( i = 0; i < 8; i++ )
                        {
                                c[8*j+((u64)i)] = m[8*j+((u64)i)]^state[rate_bytes[i]];
                                state[rate_bytes[i]] = c[8*j+((u64)i)];
                        }
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
                
                        ace_permutation(state);
                }

                if ( lblen != 0 )
                {
                        //Encrypting the padded 64-bit block when "mlen" is not a multiple of 8
                        for ( i = 0; i < lblen; i++ )
                        {
                                c[8*m64len+((u64)i)] = m[m64len*8+(u64)i]^state[rate_bytes[i]];
                                state[rate_bytes[i]] = c[8*m64len+((u64)i)];
                        }
			state[rate_bytes[lblen]]^=(0x80); //Padding: 10*

                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
                        ace_permutation(state);
                }
		else
		{
			state[rate_bytes[0]]^=(0x80); //Padding: 10*
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
			ace_permutation(state );
		}
        }
        else
	{
		state[rate_bytes[0]]^=(0x80); //Padding: 10*
                //Domain seperator
                state[STATEBYTES-1]^=(0x02);
		ace_permutation(state );
	}
	
        //Appending tag to the end of ciphertext
	if ( ace_gentag( tag, CRYPTO_ABYTES, state, k ) != KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);
        else
        {
                for ( i = 0; i < CRYPTO_ABYTES; i++ )
                        c[mlen+(u64)i] = tag[i];
        }
	*clen = mlen+CRYPTO_ABYTES;

        /*printf("Print tag after enc.:\n");
	for ( i = 0; i < 16; i++ )
		printf("%.2X", tag[i]);
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
	unsigned char i, lblen;
	u64 j, clen1, c64len;
        clen1 = clen-CRYPTO_ABYTES;
        c64len = clen1/8;
	lblen = (unsigned char)(clen1%8);
	nsec = nsec;
	
	unsigned char *state;
	unsigned char *tag;

	state = (unsigned char *)malloc(sizeof(unsigned char)*STATEBYTES);
	tag = (unsigned char *)malloc(sizeof(unsigned char)*CRYPTO_ABYTES);

	//Initialize state with "key" and "nonce" and then absorbe "key" again
	if ( ace_init(state, npub, k)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);

	//Absorbing "ad"
        if ( adlen != 0 )
        {
                if ( ace_ad( state, ad, adlen) != KAT_SUCCESS)
                        return(KAT_CRYPTO_FAILURE);
        }

        if ( clen1 != 0 )
        {
                for ( j = 0; j < c64len; j++ )
                {
                        for ( i = 0; i < 8; i++ )
                        {
                                m[8*j+((u64)i)] = c[8*j+((u64)i)]^state[rate_bytes[i]];
                                state[rate_bytes[i]] = c[8*j+((u64)i)];
                        }
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
                        ace_permutation(state);
                }

                if ( lblen != 0 )
                {
                        //Decrypting last 64-bit block
                        for ( i = 0; i < lblen; i++ )
                        {
                                m[8*c64len +((u64)i)] = c[8*c64len +((u64)i)]^state[rate_bytes[i]];
                                state[rate_bytes[i]] = c[8*c64len +((u64)i)];
                        }
			state[rate_bytes[i]]^=(0x80); //Padding: 10*

                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
                        ace_permutation(state);
                }
		else
		{
			state[rate_bytes[0]]^=(0x80); //Padding: 10*
                        //Domain seperator
                        state[STATEBYTES-1]^=(0x02);
			ace_permutation(state );
		}
        }
        else
        {
                state[rate_bytes[0]]^=(0x80); //Padding: 10*
                //Domain seperator
                state[STATEBYTES-1]^=(0x02);
                ace_permutation(state );
        }
        
	//Generating and verifying the tag
	if ( ace_gentag( tag, CRYPTO_ABYTES, state, k ) != KAT_SUCCESS )
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

        /*printf("Print tag after dec.:\n");
	for ( i = 0; i < 16; i++ )
		printf("%.2X", tag[i]);
	printf("\n");*/

	free(state);
	free(tag);
	
return KAT_SUCCESS;
}
