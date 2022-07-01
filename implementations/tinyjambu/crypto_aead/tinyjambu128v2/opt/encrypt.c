/*   
     TinyJAMBU-128: 128-bit key, 96-bit IV
     Optimized implementation 
     The state consists of four 32-bit registers       
     state[3] || state[2] || state[1] || state[0] 

     Implemented by: Hongjun Wu
*/   
   

#include "crypto_aead.h"
  
#define FrameBitsIV  0x10  
#define FrameBitsAD  0x30  
#define FrameBitsPC  0x50  //Framebits for plaintext/ciphertext      
#define FrameBitsFinalization 0x70       

#define NROUND1 128*5 
#define NROUND2 128*8

/*optimized state update function*/    
void state_update(unsigned int *state, const unsigned char *key, unsigned int number_of_steps)
{
        unsigned int i;
        unsigned int t1, t2, t3, t4;

        //in each iteration, we compute 128 rounds of the state update function. 
        for (i = 0; i < number_of_steps; i = i + 128)
        {
                t1 = (state[1] >> 15) | (state[2] << 17);  // 47 = 1*32+15 
                t2 = (state[2] >> 6)  | (state[3] << 26);  // 47 + 23 = 70 = 2*32 + 6 
                t3 = (state[2] >> 21) | (state[3] << 11);  // 47 + 23 + 15 = 85 = 2*32 + 21      
                t4 = (state[2] >> 27) | (state[3] << 5);   // 47 + 23 + 15 + 6 = 91 = 2*32 + 27 
                state[0] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[0]; 
        
                t1 = (state[2] >> 15) | (state[3] << 17);   
                t2 = (state[3] >> 6)  | (state[0] << 26);   
                t3 = (state[3] >> 21) | (state[0] << 11);        
                t4 = (state[3] >> 27) | (state[0] << 5);    
                state[1] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[1];

                t1 = (state[3] >> 15) | (state[0] << 17);
                t2 = (state[0] >> 6)  | (state[1] << 26);
                t3 = (state[0] >> 21) | (state[1] << 11);
                t4 = (state[0] >> 27) | (state[1] << 5);
                state[2] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[2];  

                t1 = (state[0] >> 15) | (state[1] << 17);
                t2 = (state[1] >> 6)  | (state[2] << 26);
                t3 = (state[1] >> 21) | (state[2] << 11);
                t4 = (state[1] >> 27) | (state[2] << 5);
                state[3] ^= t1 ^ (~(t2 & t3)) ^ t4 ^ ((unsigned int*)key)[3];
        }
}
  
// The initialization  
/* The input to initialization is the 128-bit key; 96-bit IV;*/
void initialization(const unsigned char *key, const unsigned char *iv, unsigned int *state)
{
        int i;

        //initialize the state as 0  
        for (i = 0; i < 4; i++) state[i] = 0;     

        //update the state with the key  
        state_update(state, key, NROUND2);  

        //introduce IV into the state  
        for (i = 0;  i < 3; i++)  
        {
                state[1] ^= FrameBitsIV;   
                state_update(state, key, NROUND1); 
                state[3] ^= ((unsigned int*)iv)[i]; 
        }   
}

//process the associated data   
void process_ad(const unsigned char *k, const unsigned char *ad, unsigned long long adlen, unsigned int *state)
{
        unsigned long long i; 
        unsigned int j; 

        for (i = 0; i < (adlen >> 2); i++)
        {
                state[1] ^= FrameBitsAD;
                state_update(state, k, NROUND1);
                state[3] ^= ((unsigned int*)ad)[i];
        }

        // if adlen is not a multiple of 4, we process the remaining bytes
        if ((adlen & 3) > 0)
        {
                state[1] ^= FrameBitsAD;
                state_update(state, k, NROUND1);
                for (j = 0; j < (adlen & 3); j++)  ((unsigned char*)state)[12 + j] ^= ad[(i << 2) + j];
                state[1] ^= adlen & 3;
        }   
}     

//encrypt plaintext   
int crypto_aead_encrypt(
	unsigned char *c, unsigned long long *clen,
	const unsigned char *m, unsigned long long mlen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *nsec,
	const unsigned char *npub,
	const unsigned char *k
)
{
        unsigned long long i;
        unsigned int j;
        unsigned char mac[8];
        unsigned int state[4];

        //initialization stage
        initialization(k, npub, state);

        //process the associated data   
        process_ad(k, ad, adlen, state);

        //process the plaintext    
        for (i = 0; i < (mlen >> 2); i++)
        {
                state[1] ^= FrameBitsPC;
                state_update(state, k, NROUND2);
                state[3] ^= ((unsigned int*)m)[i];
                ((unsigned int*)c)[i] = state[2] ^ ((unsigned int*)m)[i];
        }
        // if mlen is not a multiple of 4, we process the remaining bytes
        if ((mlen & 3) > 0)
        {
                state[1] ^= FrameBitsPC;
                state_update(state, k, NROUND2);
                for (j = 0; j < (mlen & 3); j++)
                {
                        ((unsigned char*)state)[12 + j] ^= m[(i << 2) + j];
                        c[(i << 2) + j] = ((unsigned char*)state)[8 + j] ^ m[(i << 2) + j];
                }
                state[1] ^= mlen & 3;
        }

        //finalization stage, we assume that the tag length is 8 bytes
        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND2);
        ((unsigned int*)mac)[0] = state[2];

        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND1);
        ((unsigned int*)mac)[1] = state[2];

        *clen = mlen + 8;
        for (j = 0; j < 8; j++) c[mlen+j] = mac[j];  

        return 0;
}

//decrypt a message
int crypto_aead_decrypt(
	unsigned char *m, unsigned long long *mlen,
	unsigned char *nsec,
	const unsigned char *c, unsigned long long clen,
	const unsigned char *ad, unsigned long long adlen,
	const unsigned char *npub,
	const unsigned char *k
)
{
        unsigned long long i;
        unsigned int j, check = 0;
        unsigned char mac[8];
        unsigned int state[4];

        *mlen = clen - 8;

        //initialization stage
        initialization(k, npub, state);

        //process the associated data   
        process_ad(k, ad, adlen, state);

        //process the ciphertext    
        for (i = 0; i < (*mlen >> 2); i++)
        {
                state[1] ^= FrameBitsPC;
                state_update(state, k, NROUND2);
                ((unsigned int*)m)[i] = state[2] ^ ((unsigned int*)c)[i];
                state[3] ^= ((unsigned int*)m)[i];
        }
        // if mlen is not a multiple of 4, we process the remaining bytes
        if ((*mlen & 3) > 0)
        {
                state[1] ^= FrameBitsPC;
                state_update(state, k, NROUND2);
                for (j = 0; j < (*mlen & 3); j++)
                {
                        m[(i << 2) + j] = c[(i << 2) + j] ^ ((unsigned char*)state)[8 + j];
                        ((unsigned char*)state)[12 + j] ^= m[(i << 2) + j];
                }
                state[1] ^= *mlen & 3;
        }

        //finalization stage, we assume that the tag length is 8 bytes
        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND2);
        ((unsigned int*)mac)[0] = state[2];

        state[1] ^= FrameBitsFinalization;
        state_update(state, k, NROUND1);
        ((unsigned int*)mac)[1] = state[2];

        //verification of the authentication tag   
        for (j = 0; j < 8; j++) { check |= (mac[j] ^ c[clen - 8 + j]); }
        if (check == 0) return 0;
        else return -1;
}

