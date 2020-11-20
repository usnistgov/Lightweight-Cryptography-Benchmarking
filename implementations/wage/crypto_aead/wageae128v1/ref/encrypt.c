
/* Reference implementation of WAGE-128, AEAD
   Written by:
   Kalikinkar Mandal <kmandal@uwaterloo.ca>
*/

#include<stdio.h>
#include<math.h>
#include<stdlib.h>
#include<stdint.h>

#include "wage.h"
#include "crypto_aead.h" 
#include "api.h" 

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

/*
 *rate_bytes: positions of rate bytes in state
 */
const unsigned char rate_bytes[10] = {8,9,15,16,18,27,28,34,35,36};

/*
 *wage_init: initialization with key and nonce
 *k: key
 *npub: nonce
 *state: state after initialization
 */
int wage_init(
		unsigned char *state, 
		const unsigned char *npub,
		const unsigned char *k
	     )
{
	unsigned char i;
	unsigned char *key, *nonce;
	key = (unsigned char*)malloc(19*sizeof(unsigned char));
	nonce = (unsigned char*)malloc(19*sizeof(unsigned char));
        
        //Convert 128-bit key and nonce arrays into 7-bit word arrays
	convert_bytekey_to_wordkey(key, k);
	convert_bytekey_to_wordkey(nonce, npub);

	//Initialize the state to all-ZERO 
	for ( i = 0; i < STATEBYTES; i++ )
		state[i] = 0x0;
		
	if ( CRYPTO_KEYBYTES == 16 && CRYPTO_NPUBBYTES == 16 )
	{
		for ( i = 0; i < 9; i++ )
			state[i] = key[2*i];
		
		for ( i = 0; i < 7; i++ )
			state[i+9] = nonce[2*i+1];
		state[16] = nonce[17];

		key[18]=(key[18]^(nonce[18]>>2));
		
		state[17] = nonce[15];
		state[18] = key[18];
                
		for ( i = 0; i < 9; i++ )
			state[i+19] = key[2*i+1];
		
		for ( i = 0; i < 9; i++ )
			state[i+28] = nonce[2*i];
		
		wage_permutation(state);
                
                //Absorbing first 64-bit key
		for ( i = 0; i < 9; i++ )
			state[rate_bytes[i]]^=key[i];
		state[rate_bytes[9]]^=(key[18]&(0x40));

		wage_permutation(state);

		//Absorbing last 64-bit key
		for ( i = 0; i < 9; i++ )
			state[rate_bytes[i]]^=key[i+9];
		state[rate_bytes[9]]^=((key[18]<<1)&(0x40));

		wage_permutation(state);
	}
	else
	{
		return KAT_CRYPTO_FAILURE;
	}
	free(key);
	free(nonce);
return KAT_SUCCESS;
}

/*
 *wage_ad: processing associated data
 *adlen: byte-length of ad
 *ad: associated data
 *state: state after initialization,
 and output state is stored
 in "state" (inplace)
 */
int wage_ad(
			unsigned char *state,
			const unsigned char *ad, 
			const u64 adlen
		     )
{
	unsigned char i, lastblock[8], lblen;
        unsigned char mword[10];
	u64 j, ad64len = adlen/8;
	lblen = (unsigned char)(adlen%8);

	if ( adlen == 0 )
		return(KAT_SUCCESS);

	//Absorbing associated data
        if ( adlen != 0 )
        {
                for ( j = 0; j < ad64len; j++ )
                {
                        convert_8bytes_to_7bitwords(mword, ad, 8*j);
                        for ( i = 0; i < 10; i++ )
                                state[rate_bytes[i]]^=mword[i];
                        //Domain seperator
                        state[0]^=(0x40);
                        wage_permutation(state);
                }
                //Process the last 64-bit block if "adlen" is not a multiple of 8
                if ( lblen != 0 )
                {
                        //Padding rule 10*
                        for ( i = 0; i < lblen; i++ )
                                lastblock[i] = ad[ad64len*8+(u64)i];
                        lastblock[lblen] = 0x80;
                        for ( i = lblen+1; i < 8; i++ )
                                lastblock[i] = 0x0;
                        
                        convert_8bytes_to_7bitwords(mword, lastblock, 0);
                        for ( i = 0; i < 10; i++ )
                                state[rate_bytes[i]]^=mword[i];
                        
                        //Domain seperator
                        state[0]^=(0x40);
                        wage_permutation(state );
                }
                else
                {
                        state[rate_bytes[0]]^=(0x40); //Padding: 10*
                        //Domain seperator
                        state[0]^=(0x40);
                        wage_permutation(state );
                }
        }

return (KAT_SUCCESS);
}

/*
 *wage_gentag: generate tag
 *k: key
 *state: state before tag generation
 *tlen: length of tag in byte
 *tag: tag (in byte)
 */
int wage_gentag(
                unsigned char *tag,
                const unsigned char tlen,
                unsigned char *state,
                const unsigned char *k
                )
{
        unsigned char i;
        unsigned char key[19], tmp_tag[19];
        if ( CRYPTO_KEYBYTES == 16 && tlen == 16 )
        {
                //Convert 16-byte key into 7-bit words before absorbing
                convert_bytekey_to_wordkey(key, k);
                
                //Absorbing first 64-bit key
                for ( i = 0; i < 9; i++ )
                        state[rate_bytes[i]]^=key[i];
                state[rate_bytes[9]]^=(key[18]&(0x40));
                
                wage_permutation(state);
                
                //Absorbing last 64-bit key
                for ( i = 0; i < 9; i++ )
                        state[rate_bytes[i]]^=key[i+9];
                state[rate_bytes[9]]^=((key[18]<<1)&(0x40));
                
                wage_permutation(state);
                
                //Extracting 128-bit tag
                for ( i = 0; i < 9; i++ )
                {
                        tmp_tag[2*i] = state[28+i];
                        tmp_tag[2*i+1] = state[9+i];
                }
         
                tmp_tag[18] = ((state[18]<<2)&(0x60));
                
                //Return tag in byte
                convert_tag_word_to_byte(tag, tmp_tag);
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
	unsigned char i, lastblock[8], lblen;
        unsigned char mword[10], cword[10], tmp_c[8];
	u64 j, m64len;


	m64len = mlen/8;
	lblen = (unsigned char)(mlen%8);
	nsec = nsec;

	state = (unsigned char *)malloc(sizeof(unsigned char)*STATEBYTES);
	tag = (unsigned char *)malloc(sizeof(unsigned char)*CRYPTO_ABYTES);

	//Initialize state with "key" and "nonce" and then absorbe "key" again
	if ( wage_init(state, npub, k)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);
        
        
	//Absorbing "ad"
        if ( adlen != 0 )
        {
                if ( wage_ad( state, ad, adlen) != KAT_SUCCESS)
                        return(KAT_CRYPTO_FAILURE);
        }

	//Encrypting "message(m)" and producing "ciphertext (c)"
        if ( mlen != 0 )
        {
                for ( j = 0; j < m64len; j++ )
                {
                        convert_8bytes_to_7bitwords(mword, m, 8*j);
                        
                        for ( i = 0; i < 10; i++ )
                        {
                                cword[i] = mword[i]^state[rate_bytes[i]];
                                state[rate_bytes[i]] = cword[i];
                        }
                        convert_7bitwords_to_8bytes(tmp_c, cword, 0);
                        for ( i = 0; i < 8; i++ )
                              c[8*j+((u64)i)] = tmp_c[i];

                        //Domain seperator
                        state[0]^=(0x20);
                        wage_permutation(state);
                }

                if ( lblen != 0 )
                {
                        //Padding the last block
                        for ( i = 0; i < lblen; i++ )
                                lastblock[i] = m[m64len*8+(u64)i];

                        lastblock[lblen] = 0x80; //Padding: 10*
                        for ( i = lblen+1; i < 8; i++ )
                                lastblock[i] = 0x0;
                        
                        //Encrypting the padded 64-bit block when "mlen" is not a multiple of 8
                        convert_8bytes_to_7bitwords (mword, lastblock, 0);
                        
                        for ( i = 0; i < 10; i++ )
                        {
                                cword[i] = mword[i]^state[rate_bytes[i]];
                                state[rate_bytes[i]] = cword[i];
                        }
                        convert_7bitwords_to_8bytes(tmp_c, cword, 0);
                        for ( i = 0; i < lblen; i++ )
                                c[8*m64len+((u64)i)] = tmp_c[i];

                        //Domain seperator
                        state[0]^=(0x20);
                        wage_permutation(state);
                }
                else
                {
                        state[rate_bytes[0]]^=(0x40); //Padding: 10*
                        //Domain seperator
                        state[0]^=(0x20);
                        wage_permutation(state );
                }
        }
        else
        {
                state[rate_bytes[0]]^=(0x40); //Padding: 10*
                //Domain seperator
                state[0]^=(0x20);
                wage_permutation(state );
        }
        //Appending tag to the end of ciphertext
	if ( wage_gentag( tag, CRYPTO_ABYTES, state, k ) != KAT_SUCCESS )
        {
		return(KAT_CRYPTO_FAILURE);
        }
        else
        {
                for ( i = 0; i < CRYPTO_ABYTES; i++ )
                        c[mlen+(u64)i] = tag[i];
        }
	*clen = mlen+CRYPTO_ABYTES;


	/*printf("Print tag after enc.:\n");
	for ( i = 0; i < tlen; i++ )
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
	unsigned char i, lblen, lastblock[8];
	u64 j, clen1, c64len = clen/8;
        unsigned char mword[10], cword[10], tmp_m[8];
        clen1 = clen - CRYPTO_ABYTES;
        c64len = clen1/8;
	lblen = (unsigned char)(clen1%8);
	nsec = nsec;
	
	unsigned char *state;
	unsigned char *tag, tlen = 16;

	state = (unsigned char *)malloc(sizeof(unsigned char)*STATEBYTES);
	tag = (unsigned char *)malloc(sizeof(unsigned char)*CRYPTO_ABYTES);

	//Initialize state with "key" and "nonce" and then absorbe "key" again
	if ( wage_init(state, npub, k)!= KAT_SUCCESS )
		return(KAT_CRYPTO_FAILURE);

	//Absorbing "ad"
        if ( adlen != 0 )
        {
                if ( wage_ad( state, ad, adlen) != KAT_SUCCESS)
                        return(KAT_CRYPTO_FAILURE);
        }

        if ( clen1 != 0 )
        {
                for ( j = 0; j < c64len; j++ )
                {
                        convert_8bytes_to_7bitwords(cword, c, 8*j);
                        for ( i = 0; i < 9; i++ )
                        {
                                mword[i] = cword[i]^state[rate_bytes[i]];
                                state[rate_bytes[i]] = cword[i];
                        }
			mword[9] = (cword[9]^state[rate_bytes[9]])&(0x40);
			state[rate_bytes[9]]^=mword[9];

			//for ( i = 0; i < 10; i++ )
			//	mword[i] = reverse1(mword[i]);
                        convert_7bitwords_to_8bytes(tmp_m, mword, 0);

                        for ( i = 0; i < 8; i++ )
                                m[8*j+((u64)i)] = tmp_m[i];

                        //Domain seperator
                        state[0]^=(0x20);
                        wage_permutation(state);
                }

                if ( lblen != 0 )
                {
                        //Decrypting last 64-bit block
                        for ( i = 0; i < lblen; i++ )
                                lastblock[i] = c[8*c64len +((u64)i)];
                        for ( i = lblen; i < 8; i++ )
                                lastblock[i] = 0x0;
                        convert_8bytes_to_7bitwords(cword, lastblock, 0);
                        for ( i = 0; i < 10; i++ )
                        {
                                mword[i] = cword[i]^state[rate_bytes[i]];
                        }
                        convert_7bitwords_to_8bytes (tmp_m, mword, 0);

                        for ( i = 0; i < lblen; i++ )
                                m[8*c64len+((u64)i)] = tmp_m[i];

                        for ( i = 0; i < lblen; i++ )
                                lastblock[i] = m[8*c64len+((u64)i)];
                        lastblock[lblen] = 0x80; //Padding: 10*
                        for ( i = lblen+1; i < 8; i++ )
                                lastblock[i] = 0x0;
                        convert_8bytes_to_7bitwords(mword, lastblock, 0);

                        for ( i = 0; i < 10; i++ )
                                state[rate_bytes[i]] = state[rate_bytes[i]]^mword[i];

                        //Domain seperator
                        state[0]^=0x20;
                        wage_permutation(state);
                }
                else
                {
                        state[rate_bytes[0]]^=(0x40); //Padding: 10*
                        //Domain seperator
                        state[0]^=(0x20);
                        wage_permutation(state );
                }
        }
        else
        {
                m=NULL;
                state[rate_bytes[0]]^=(0x40); //Padding: 10*
                //Domain seperator
                state[0]^=(0x20);
                wage_permutation(state );
        }
        
        //Generating and verifying the tag
	if ( wage_gentag( tag, tlen, state, k ) != KAT_SUCCESS )
        {
		return(KAT_CRYPTO_FAILURE);
        }
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
	for ( i = 0; i < tlen; i++ )
		printf("%.2X", tag[i]);
	printf("\n");*/

	free(state);
	free(tag);
	
return KAT_SUCCESS;
}
