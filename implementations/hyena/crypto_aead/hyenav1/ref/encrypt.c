/*
 * HYENA_GIFT-128
 * 
 * 
 * HYENA_GIFT-128 is a nonce-based AEAD based on Hybrid Feedback mode of
 * operation and GIFT-128 block cipher.
 * 
 * Test Vector (in little endian format):
 * Key	: 0f 0e 0d 0c 0b 0a 09 08 07 06 05 04 03 02 01 00
 * PT 	:
 * AD	: 
 * CT	: 
 * 
 */

#include "crypto_aead.h"
#include "api.h"
#include "hyena.h"

u64 load64(u8 *Bytes)
{
    int i; u64 Block;
 
    Block=0;
 
    Block = (u64)(Bytes[0]);
     
    for(i = 1; i < 8; i++) {Block <<= 8; Block = (Block)^(u64)(Bytes[i]);}
 
    return Block;
}

void store64(u8 *Bytes, u64 Block)
{ 
    int i; 
     
    for (i = 7; i >= 0 ; i--) {Bytes[i] = (u8)Block; Block >>= 8; }
}



/**********************************************************************
 * 
 * @name	:	mult_by_alpha
 * 
 * @note	:	Multiplies given field element in "src" with \alpha,
 * 				the primitive element corresponding to the primitive
 * 				polynomial p(x) as defined in PRIM_POLY_MOD_128, and
 * 				stores the result in "dest".
 * 
 **********************************************************************/	
void mult_by_alpha(u8 *dest, u8 *src)
{
	u64 b;
	b =  load64(src);

        if(((b>>63)&1)==1) b = (b<<1)^(0x000000000000001B); 
                         else b = b<<1;

	store64(dest, b);	
		
}


/**********************************************************************
 * 
 * @name	:	memcpy_and_zero_one_pad
 * 
 * @note	:	Copies src bytes to dest and pads with 10* to create
 * 				CRYPTO_BLOCKBYTES-oriented data.
 * 
 **********************************************************************/
void memcpy_and_zero_one_pad(u8* dest, const u8 *src, u8 len)
{
	memset(dest, 0, 16);
	memcpy(dest, src, len);
	dest[len] ^= 0x01;
}



/**********************************************************************
 * 
 * @name	:	Feedback_TXT_Enc
 * 
 * @note	:	The FB+ module
 * 
 **********************************************************************/
void Feedback_TXT_Enc(u8 *State, u8 *output, const u8 *Delta, const u8 *input, const u64 inputlen)
{
	u32 i;
	u8 pad1[16], pad2[16], feedback[16];

	for(i = 0 ; i < inputlen;i++)  output[i] = input[i]^State[i];


	if(inputlen < 16) 
	{
		memcpy_and_zero_one_pad(&pad1[0], input, inputlen);
		memcpy_and_zero_one_pad(&pad2[0], output, inputlen);
	}
	else 
	{
		for(i = 0 ; i < 16 ; i++)
		{
		pad1[i] = input[i];
		pad2[i] = output[i];
		}
	}

     for(i=0; i<8 ;i++)
     { 
		feedback[i] = pad1[i];
           feedback[i+8] = pad2[i+8];

     }
     for(i=8; i<15 ;i++)
     { 
		feedback[i] ^= Delta[i-8];
     }


     
	for(i = 0 ; i < 16 ; i++) State[i] ^= feedback[i];
      
}		

/**********************************************************************
 * 
 * @name	:	Feedback_TXT_Dec
 * 
 * @note	:	The FB- module
 * 
 **********************************************************************/
void Feedback_TXT_Dec(u8 *State, u8 *output, const u8 *Delta, const u8 *input, const u64 inputlen)
{
	u32 i;
	u8 pad1[16], pad2[16], feedback[16];
	for(i = 0 ; i < inputlen;i++)   output[i] = input[i]^State[i];

	if(inputlen < 16) 
	{
		memcpy_and_zero_one_pad(&pad1[0], output, inputlen);
		memcpy_and_zero_one_pad(&pad2[0], input, inputlen);
	}
	else 
	{
		for(i = 0 ; i < 16 ; i++)
		{
		pad1[i] = output[i];
		pad2[i] = input[i];
		}
	}
     	for(i=0; i<8 ;i++)
     	{ 
		feedback[i] = pad1[i];
        	feedback[i+8] = pad2[i+8];
        }
    	for(i=8; i<15 ;i++)
     	{ 
		feedback[i] ^= Delta[i-8];
     	}
     
	for(i = 0 ; i < 16 ; i++) State[i] ^= feedback[i];
      
}



/**********************************************************************
 * 
 * @name	:	INIT
 * 
 * @note	:	Derives nonce-dependent initial state and mask.
 * 
 **********************************************************************/
void INIT(u8 *State, u8 * Delta, const u8 *npub, const u32 cntrl, const u8 (*round_keys)[32])
{
	u32 i;
	for(i = 4 ; i < 16 ; i++) 
		State[i] = npub[i-4];
	for(i = 0 ; i < 4 ; i++)
		State[i] = 0;
	State[0] ^= (u8)cntrl;		
	gift_enc(State, &round_keys[0], State);	
	for(i = 0 ; i < 8 ; i++)
		Delta[i] = State[i+8];
}

/**********************************************************************
 * 
 * @name	:	PROC_AD
 * 
 * @note	:	Processes associated data.
 * 
 **********************************************************************/
void PROC_AD(u8 *State, u8 * Delta,  const u8 *input,  u64 inputlen, const u8 (*round_keys)[32])
{
      u8 output[16] = { 0 };
      u64 outputlen = 0;

	while(inputlen > 16)
	{
		mult_by_alpha(Delta, Delta);
		Feedback_TXT_Enc(State, output, Delta, input+outputlen, 16);
		gift_enc(State, &round_keys[0], State);	
		inputlen -= 16; outputlen += 16;
	}		
	mult_by_alpha(Delta, Delta);
	
	if(inputlen < 16)
	{
		mult_by_alpha(Delta, Delta); 
		mult_by_alpha(Delta, Delta);
	}
	else
	{
		mult_by_alpha(Delta, Delta);
	}

	Feedback_TXT_Enc(State, output, Delta, input+outputlen, inputlen);			
	//gift_enc(State, &round_keys[0], State);			
}

/**********************************************************************
 * 
 * @name	:	Proc_TXT
 * 
 * @note	:	Generates ciphertext/plaintext by encrypting/decrypting
 * 				plaintext/ciphertext.
 * 
 **********************************************************************/
void Proc_TXT(u8 *State, u8 *Delta,  u8 *output, u64 *outputlen, const u8 *input, u64 inputlen,  const u8 (*round_keys)[32], const u32 direction)
{
	if(inputlen != 0)
	{
		while(inputlen > 16)
		{		
			mult_by_alpha(Delta, Delta);
			gift_enc(State, &round_keys[0], State);	
			if(direction==0)
				Feedback_TXT_Enc(State, output + *outputlen, Delta, input + *outputlen, 16);
                 	else 
				Feedback_TXT_Dec(State, output + *outputlen, Delta, input + *outputlen, 16);
			inputlen -= 16; *outputlen += 16; 
		}
		mult_by_alpha(Delta, Delta);
		if(inputlen < 16)
		{
			mult_by_alpha(Delta, Delta); mult_by_alpha(Delta, Delta); 	 
		}
		else
		{
			mult_by_alpha(Delta, Delta);
		}
		gift_enc(State, &round_keys[0], State);			
		if(direction==0)
			Feedback_TXT_Enc(State, output + *outputlen, Delta, input + *outputlen, inputlen);
                else 
			Feedback_TXT_Dec(State, output + *outputlen, Delta, input + *outputlen, inputlen);
		*outputlen = *outputlen + inputlen; 		
	}
}

void swap(u8 *a, u8 *b)
{
	*a = *a ^ *b;
	*b = *a ^ *b;
	*a = *a ^ *b;
}

/**********************************************************************
 * 
 * @name	:	Tag_Gen
 * 
 * @note	:	Tag generator.
 * 
 **********************************************************************/
void Tag_Gen(u8 *State, const u8 (*round_keys)[32])
{ 	
	u32 i;
	for(i = 0 ; i < 8 ; i++)
		swap(&State[i], &State[i+8]);	
	gift_enc(State, &round_keys[0], State);
}

/**********************************************************************
 * 
 * @name	:	crypto_aead_encrypt
 * 
 * @note	:	Main encryption function.
 * 
 **********************************************************************/
int crypto_aead_encrypt(
	unsigned char *ct, unsigned long long *ctlen,
	const unsigned char *pt, unsigned long long ptlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
)
{
	// to bypass unused warning on nsec
	nsec = nsec;
	
	u32 i;

	u32 cntrl;

	*ctlen = 0;
	cntrl = 0;

	u8  HYENA_State[16], Delta[8], round_keys[CRYPTO_BC_NUM_ROUNDS][32];

      

	for(i = 0 ; i < 16 ; i++) HYENA_State[i] = 0;
        for(i = 0 ; i < 8 ; i++) Delta[i] = 0;

	if(adlen == 0 && ptlen == 0) cntrl = 0x03;
	if(adlen == 0 && ptlen > 0) cntrl = 0x01;

	_GIFT_ENC_ROUND_KEY_GEN(&round_keys[0], k);

	INIT(&HYENA_State[0], &Delta[0], npub, cntrl, &round_keys[0]);
	


      PROC_AD(&HYENA_State[0], &Delta[0], ad, adlen, &round_keys[0]);
	if(ptlen != 0)
	{				
  		Proc_TXT(&HYENA_State[0], &Delta[0], ct, ctlen, pt, ptlen, &round_keys[0], 0);
                

	}


	Tag_Gen(&HYENA_State[0], &round_keys[0]);

     

	for(i = 0 ; i< CRYPTO_ABYTES ; i++) ct[*ctlen + i] = HYENA_State[i];
      
        *ctlen  += CRYPTO_ABYTES;


	return 0;
}

/**********************************************************************
 * 
 * @name	:	crypto_aead_decrypt
 * 
 * @note	:	Main decryption function.
 * 
 **********************************************************************/
int crypto_aead_decrypt(
	unsigned char *pt, unsigned long long *ptlen,
	unsigned char *nsec,
	const unsigned char *ct, unsigned long long ctlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
)
{
	// to bypass unused warning on nsec
	nsec = nsec;
	
	int pass;
	u32 i;
	u8  tag[16], HYENA_State[16], Delta[8], cntrl, round_keys[CRYPTO_BC_NUM_ROUNDS][32];

      cntrl = 0;
      *ptlen = 0;
	for(i = 0 ; i < 16 ; i++) HYENA_State[i] = 0;
      for(i = 0 ; i < 8 ; i++) Delta[i] = 0;

	if(adlen == 0 && ctlen == 16) cntrl = 0x03;

	if(adlen == 0 && ctlen != 16) cntrl = 0x01;
	_GIFT_ENC_ROUND_KEY_GEN(&round_keys[0], k);

	INIT(&HYENA_State[0], &Delta[0], npub, cntrl, &round_keys[0]);


        PROC_AD(&HYENA_State[0], &Delta[0], ad, adlen, &round_keys[0]);

	if(ctlen != 16)
	{
  		Proc_TXT(&HYENA_State[0], &Delta[0], pt, ptlen, ct, ctlen-16, &round_keys[0], 1);
        }


	Tag_Gen(&HYENA_State[0], &round_keys[0]);
	pass = 0;

	for(i = 0 ; i< CRYPTO_ABYTES ; i++) 
	{
		tag[i] = HYENA_State[i];
		if(tag[i]!=ct[*ptlen + i]) pass = -1;
	}
	
	return pass;
}

