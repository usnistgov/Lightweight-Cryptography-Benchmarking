#include <stdlib.h>

#include "subterranean_ref.h"

const unsigned int subterranean_pi_permutation[257] = {0, 12, 24, 36, 48, 60, 72, 84, 96, 108, 120, 132, 144, 156, 168, 180, 192, 204, 216, 228, 240, 252, 7, 19, 31, 43, 55, 67, 79, 91, 103, 115, 127, 139, 151, 163, 175, 187, 199, 211, 223, 235, 247, 2, 14, 26, 38, 50, 62, 74, 86, 98, 110, 122, 134, 146, 158, 170, 182, 194, 206, 218, 230, 242, 254, 9, 21, 33, 45, 57, 69, 81, 93, 105, 117, 129, 141, 153, 165, 177, 189, 201, 213, 225, 237, 249, 4, 16, 28, 40, 52, 64, 76, 88, 100, 112, 124, 136, 148, 160, 172, 184, 196, 208, 220, 232, 244, 256, 11, 23, 35, 47, 59, 71, 83, 95, 107, 119, 131, 143, 155, 167, 179, 191, 203, 215, 227, 239, 251, 6, 18, 30, 42, 54, 66, 78, 90, 102, 114, 126, 138, 150, 162, 174, 186, 198, 210, 222, 234, 246, 1, 13, 25, 37, 49, 61, 73, 85, 97, 109, 121, 133, 145, 157, 169, 181, 193, 205, 217, 229, 241, 253, 8, 20, 32, 44, 56, 68, 80, 92, 104, 116, 128, 140, 152, 164, 176, 188, 200, 212, 224, 236, 248, 3, 15, 27, 39, 51, 63, 75, 87, 99, 111, 123, 135, 147, 159, 171, 183, 195, 207, 219, 231, 243, 255, 10, 22, 34, 46, 58, 70, 82, 94, 106, 118, 130, 142, 154, 166, 178, 190, 202, 214, 226, 238, 250, 5, 17, 29, 41, 53, 65, 77, 89, 101, 113, 125, 137, 149, 161, 173, 185, 197, 209, 221, 233, 245};
const unsigned int subterranean_io_bits_0[33] = {1, 176, 136, 35, 249, 134, 197, 234, 64, 213, 223, 184, 2, 95, 15, 70, 241, 11, 137, 211, 128, 169, 189, 111, 4, 190, 30, 140, 225, 22, 17, 165, 256};
const unsigned int subterranean_io_bits_1[32] = {256, 81, 121, 222, 8, 123, 60, 23, 193, 44, 34, 73, 255, 162, 242, 187, 16, 246, 120, 46, 129, 88, 68, 146, 253, 67, 227, 117, 32, 235, 240, 92};

//#define DEBUG_MODE

#ifdef DEBUG_MODE
#include "subterranean_ref_debug.h"
#endif

/**
* Transforms a byte array into a bit array.
* Each bit takes one byte, thus the memory consumption multiply by a factor 8
*/
void byte_array_to_bit_array(unsigned char * o, const unsigned char * a, const unsigned char alen){
    unsigned char temp;
    unsigned char i, j;
    i = 0;
    j = 0;
    while(j < alen){
        temp = a[i++];
        do {
            o[j++] = temp & 1;
            temp >>= 1;
        } while((j < alen) && ((j & 7) != 0));
    }
}

/**
* Compacts the bit array into a byte array.
*/
void bit_array_to_byte_array(unsigned char * o, const unsigned char * a, const unsigned char alen){
    unsigned char temp;
    unsigned char i, j;
    i = 0;
    j = 0;
    while(i < alen){
        temp = 0;
        do {
            temp |= (a[i] & 1) << (i & 7);
            i++;
        } while((i < alen) && ((i & 7) != 0));
        o[j++] = temp;
    }
}
/**
* Subterranean round function
* The input state is updated with the new state.
*/
void subterranean_round(unsigned char state[SUBTERRANEAN_SIZE]){
    unsigned int i;
    unsigned char temp_0, temp_1, temp_2, temp_3, temp_4, temp_5, temp_6, temp_7;
    unsigned char temp_state[SUBTERRANEAN_SIZE];
    
    /* Chi step*/
    for(i = 0; i < (SUBTERRANEAN_SIZE-2); i++){
        temp_state[i] = state[i] ^ ((1 ^ state[i+1]) & state[i+2]);
    }
    temp_state[i] = state[i] ^ ((1 ^ state[i+1]) & state[0]);
    i++;
    temp_state[i] = state[i] ^ ((1 ^ state[0]) & state[1]);
    
    /* Iota step*/
    temp_state[0] ^= 1;
    
    /* Theta step*/
    temp_0 = temp_state[0] ^ temp_state[3]  ^ temp_state[8];
    temp_1 = temp_state[1] ^ temp_state[4]  ^ temp_state[9];
    temp_2 = temp_state[2] ^ temp_state[5]  ^ temp_state[10];
    temp_3 = temp_state[3] ^ temp_state[6]  ^ temp_state[11];
    temp_4 = temp_state[4] ^ temp_state[7]  ^ temp_state[12];
    temp_5 = temp_state[5] ^ temp_state[8]  ^ temp_state[13];
    temp_6 = temp_state[6] ^ temp_state[9]  ^ temp_state[14];
    temp_7 = temp_state[7] ^ temp_state[10] ^ temp_state[15];
    for(i = 8; i < (SUBTERRANEAN_SIZE-8); i++){
        temp_state[i] = temp_state[i] ^ temp_state[i+3] ^ temp_state[i+8];
    }
    temp_state[i] = temp_state[i] ^ temp_state[i+3] ^ temp_state[0];
    i++;
    temp_state[i] = temp_state[i] ^ temp_state[i+3] ^ temp_state[1];
    i++;
    temp_state[i] = temp_state[i] ^ temp_state[i+3] ^ temp_state[2];
    i++;
    temp_state[i] = temp_state[i] ^ temp_state[i+3] ^ temp_state[3];
    i++;
    temp_state[i] = temp_state[i] ^ temp_state[i+3] ^ temp_state[4];
    i++;
    temp_state[i] = temp_state[i] ^ temp_state[0] ^ temp_state[5];
    i++;
    temp_state[i] = temp_state[i] ^ temp_state[1] ^ temp_state[6];
    i++;
    temp_state[i] = temp_state[i] ^ temp_state[2] ^ temp_state[7];
    temp_state[0] = temp_0;
    temp_state[1] = temp_1;
    temp_state[2] = temp_2;
    temp_state[3] = temp_3;
    temp_state[4] = temp_4;
    temp_state[5] = temp_5;
    temp_state[6] = temp_6;
    temp_state[7] = temp_7;
    
    
    /* Pi step*/
    for(i = 0; i < (SUBTERRANEAN_SIZE); i++){
        state[i] = temp_state[subterranean_pi_permutation[i]];
    }
    
    
}

/**
* Fills Subterranean with 0's
*/
void subterranean_init(unsigned char state[SUBTERRANEAN_SIZE]){
    unsigned int i;
    for(i = 0; i < SUBTERRANEAN_SIZE; i++){
        state[i] = 0;
    }
}


/**
* Perform a duplex
*/
void subterranean_duplex(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * sigma, const unsigned char size){
    unsigned char j;
    /* s <= R(s) */
    subterranean_round(state);
    /* sbar <= sbar + sigma */
    for(j = 0; j < size; j++){
        state[subterranean_io_bits_0[j]] ^= sigma[j];
    }
    /* sbar <= sbar + (1||0*) */
    state[subterranean_io_bits_0[j]] ^= 1;
}

/**
* Perform an extract
*/
void subterranean_extract(unsigned char state[SUBTERRANEAN_SIZE], unsigned char value_out[32]){
    unsigned char j;
    /* value_out <= extract */
    for(j = 0; j < 32; j++){
        value_out[j] = state[subterranean_io_bits_0[j]] ^ state[subterranean_io_bits_1[j]];
    }
}

/**
* Perform a blank into the state
*/
void subterranean_blank(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char r_calls){
    unsigned char i;
    /* for r times do duplex() */
    for(i = 0; i < r_calls; i++){
        subterranean_duplex(state, NULL, 0);
    }
    
}

/**
* Perform a squeeze
*/
void subterranean_squeeze(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * value_out, const unsigned long long value_out_length){
    unsigned char temp[32];
    unsigned long long i;
    
    /*
     * while |Z| < l do
     *     temp <= extract(s)
     *     Z <= Z||temp
     */
    i = 0;
    if(value_out_length > 32){
        while(i < (value_out_length-32)){
            subterranean_extract(state, temp);
            subterranean_duplex(state, NULL, 0);
            bit_array_to_byte_array(&value_out[i>>3], temp, 32);
            i += 32;
        }
    }
    subterranean_extract(state, temp);
    bit_array_to_byte_array(&value_out[i>>3], temp, value_out_length-i);
}

/**
* Perform a simple absorb unkeyed
*
*/
void subterranean_absorb_unkeyed(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * value_in, const unsigned long long value_in_length){
    unsigned long long i;
    unsigned char temp[32];
    
    /* Let x[n] be X split in 8-bit blocks, with last block strictly shorter */
    i = 0;
    /*
    * for all blocks of x[n] do
    *     duplex(x[i])
    *     duplex()
    */
    if(value_in_length >= 8){
        while(i <= value_in_length - 8){
            byte_array_to_bit_array(temp, &value_in[i>>3], 8);
            subterranean_duplex(state, temp, 8);
            subterranean_duplex(state, NULL, 0);
            i += 8;
        }
    }
    byte_array_to_bit_array(temp, &value_in[i>>3], value_in_length-i);
    subterranean_duplex(state, temp, value_in_length-i);
    subterranean_duplex(state, NULL, 0);
}

/**
* Perform a simple absorb keyed
*
*/
void subterranean_absorb_keyed(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * value_in, const unsigned long long value_in_length){
    unsigned long long i;
    unsigned char temp[32];
    
    /* Let x[n] be X split in 32-bit blocks, with last block strictly shorter */
    i = 0;
    /*
    * for all blocks of x[n] do
    *     duplex(x[i])
    */
    if(value_in_length >= 32){
        while(i <= value_in_length - 32){
            byte_array_to_bit_array(temp, &value_in[i>>3], 32);
            subterranean_duplex(state, temp, 32);
            i += 32;
        }
    }
    byte_array_to_bit_array(temp, &value_in[i>>3], value_in_length-i);
    subterranean_duplex(state, temp, value_in_length-i);
}

/**
* Perform a simple absorb encrypt
*
*/
void subterranean_absorb_encrypt(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * value_out, const unsigned char * value_in, const unsigned long long value_in_length){
    unsigned long long i;
    unsigned char temp_0[32];
    unsigned char temp_1[32];
    unsigned char j;
    
    /* Let x[n] be X split in 32-bit blocks, with last block strictly shorter */
    i = 0;
    /*
    * for all blocks of x[n] do
    *     temp <= x[i] + (extract(s) truncated to |x[i]|)
    *     Y <= Y || temp
    *     duplex(x[i])
    *     
    */
    if(value_in_length >= 32){
        while(i <= value_in_length - 32){
            byte_array_to_bit_array(temp_0, &value_in[i>>3], 32);
            subterranean_extract(state, temp_1);
            for(j = 0; j < 32; j++){
                temp_1[j] ^= temp_0[j];
            }
            subterranean_duplex(state, temp_0, 32);
            bit_array_to_byte_array(&value_out[i>>3], temp_1, 32);
            i += 32;
        }
    }
    byte_array_to_bit_array(temp_0, &value_in[i>>3], value_in_length-i);
    subterranean_extract(state, temp_1);
    for(j = 0; j < value_in_length-i; j++){
        temp_1[j] ^= temp_0[j];
    }
    subterranean_duplex(state, temp_0, value_in_length-i);
    bit_array_to_byte_array(&value_out[i>>3], temp_1, value_in_length-i);
}

/**
* Perform a simple absorb decrypt
*
*/
void subterranean_absorb_decrypt(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * value_out, const unsigned char * value_in, const unsigned long long value_in_length){
    unsigned long long i;
    unsigned char temp_0[32];
    unsigned char temp_1[32];
    unsigned char j;
    
    /* Let x[n] be X split in 32-bit blocks, with last block strictly shorter */
    i = 0;
    /*
    * for all blocks of x[n] do
    *     temp <= x[i] + (extract(s) truncated to |x[i]|)
    *     Y <= Y || temp
    *     duplex(temp)
    */
    if(value_in_length >= 32){
        while(i <= value_in_length - 32){
            byte_array_to_bit_array(temp_0, &value_in[i>>3], 32);
            subterranean_extract(state, temp_1);
            for(j = 0; j < 32; j++){
                temp_1[j] ^= temp_0[j];
            }
            subterranean_duplex(state, temp_1, 32);
            bit_array_to_byte_array(&value_out[i>>3], temp_1, 32);
            i += 32;
        }
    }
    byte_array_to_bit_array(temp_0, &value_in[i>>3], value_in_length-i);
    subterranean_extract(state, temp_1);
    for(j = 0; j < value_in_length-i; j++){
        temp_1[j] ^= temp_0[j];
    }
    subterranean_duplex(state, temp_1, value_in_length-i);
    bit_array_to_byte_array(&value_out[i>>3], temp_1, value_in_length-i);
}

/**
* Perform the XOF initialization
*
*/
void subterranean_xof_init(unsigned char state[SUBTERRANEAN_SIZE]){
    /* S <= Subterranean() */
    subterranean_init(state);
}

/**
* Perform the XOF update
*
*/
void subterranean_xof_update(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * m, const unsigned long long m_length){
    subterranean_absorb_unkeyed(state, m, m_length);
}

/**
* Perform the XOF finalization
*
*/
void subterranean_xof_finalize(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * z, const unsigned long long z_length){
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* Z <= S.squeeze(l) */
    subterranean_squeeze(state, z, z_length);
}

/**
* Apply the XOF directly to only one message
*
*/
void subterranean_xof_direct(unsigned char * z, unsigned long long z_length, const unsigned char * m, const unsigned long long m_length){
    unsigned char state[SUBTERRANEAN_SIZE];
    /* S <= Subterranean() */
    subterranean_init(state);
    
    subterranean_absorb_unkeyed(state, m, m_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* Z <= S.squeeze(l) */
    subterranean_squeeze(state, z, z_length);
}

/**
* Perform the deck function initialization
* 
*/
void subterranean_deck_init(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * k, const unsigned long long k_length){
    /* S <= Subterranean() */
    subterranean_init(state);
    /* S.absorb(K,MAC) */
    subterranean_absorb_keyed(state, k, k_length);
}

/**
* Perform the deck function update
* 
*/
void subterranean_deck_update(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * m, const unsigned long long m_length){
    subterranean_absorb_keyed(state, m, m_length);
}

/**
* Perform the deck function finalization
* 
*/
void subterranean_deck_finalize(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * z, const unsigned long long z_length){
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* Z <= S.squeeze(l) */
    subterranean_squeeze(state, z, z_length);
}

/**
* Apply the deck directly to only one message and key
*
*/
void subterranean_deck_direct(unsigned char * z, const unsigned long long z_length, const unsigned char * k, const unsigned long long k_length, const unsigned char * m, const unsigned long long m_length){
    unsigned char state[SUBTERRANEAN_SIZE];
    /* S <= Subterranean() */
    subterranean_init(state);
    /* S.absorb(K,MAC) */
    subterranean_absorb_keyed(state, k, k_length);
    
    subterranean_absorb_keyed(state, m, m_length);
    
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* Z <= S.squeeze(l) */
    subterranean_squeeze(state, z, z_length);
}

/**
* Apply the SAE initialization
*
*/
void subterranean_SAE_start(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length){
    /* S <= Subterranean() */
    subterranean_init(state);
    /* S.absorb(K) */
    subterranean_absorb_keyed(state, k, k_length);
    /* S.absorb(N) */
    subterranean_absorb_keyed(state, n, n_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
}

/**
* Apply the SAE encryption after separate initialization
*
*/
int subterranean_SAE_wrap_encrypt(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * y, unsigned char * t, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length){
    /* S.absorb(A,MAC) */
    subterranean_absorb_keyed(state, a, a_length);
    /* Y <= S.absorb(X,op) */
    subterranean_absorb_encrypt(state, y, x, x_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* T <= S.squeeze(tau) */
    subterranean_squeeze(state, t, t_length);
    return 0;
}

/**
* Apply the SAE decryption after separate initialization
*
*/
int subterranean_SAE_wrap_decrypt(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * y, unsigned char * t, const unsigned char * t_prime, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length){
    unsigned long long i;
    unsigned char tag_different;
    /* S.absorb(A,MAC) */
    subterranean_absorb_keyed(state, a, a_length);
    /* Y <= S.absorb(X,op) */
    subterranean_absorb_decrypt(state, y, x, x_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* T <= S.squeeze(tau) */
    subterranean_squeeze(state, t, t_length);
    /* if op = decrypt AND (tag != new_tag) then (Y,T) = (*,*) */
    tag_different = 0;
    /* Check if tags are matching */
    for(i = 0; i < ((t_length + 7) >> 3); i++){
        tag_different |= t[i] ^ t_prime[i];
    }
    /* If tags do not match */
    if(tag_different != 0){
        for(i = 0; i < ((x_length + 7) >> 3); i++){ 
            y[i] = 0;
        }
        for(i = 0; i < ((t_length + 7) >> 3); i++){ 
            t[i] = 0;
        }
        return -1;
    }
    else
        return 0;
}

/**
* Apply the SAE encryption directly for one message, key and associated data
*
*/
int subterranean_SAE_direct_encrypt(unsigned char * y, unsigned char * t, const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length){
    unsigned char state[SUBTERRANEAN_SIZE];
    /* S <= Subterranean() */
    subterranean_init(state);
    /* S.absorb(K) */
    subterranean_absorb_keyed(state, k, k_length);
    /* S.absorb(N) */
    subterranean_absorb_keyed(state, n, n_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* S.absorb(A,MAC) */
    subterranean_absorb_keyed(state, a, a_length);
    /* Y <= S.absorb(X,op) */
    subterranean_absorb_encrypt(state, y, x, x_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* T <= S.squeeze(tau) */
    subterranean_squeeze(state, t, t_length);
    return 0;
}

/**
* Apply the SAE decryption directly for one message, key and associated data
*
*/
int subterranean_SAE_direct_decrypt(unsigned char * y, unsigned char * t, const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length, const unsigned char * t_prime, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length){
    unsigned char state[SUBTERRANEAN_SIZE];
    unsigned long long i;
    unsigned char tag_different;
    /* S <= Subterranean() */
    subterranean_init(state);
    /* S.absorb(K) */
    subterranean_absorb_keyed(state, k, k_length);
    /* S.absorb(N) */
    subterranean_absorb_keyed(state, n, n_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* S.absorb(A,MAC) */
    subterranean_absorb_keyed(state, a, a_length);
    /* Y <= S.absorb(X,op) */
    subterranean_absorb_decrypt(state, y, x, x_length);
    /* S.blank(8) */
    subterranean_blank(state, 8);
    /* T <= S.squeeze(tau) */
    subterranean_squeeze(state, t, t_length);
    /* if op = decrypt AND (tag != new_tag) then (Y,T) = (*,*) */
    tag_different = 0;
    /* Check if tags are matching */
    for(i = 0; i < ((t_length + 7) >> 3); i++){
        tag_different |= t[i] ^ t_prime[i];
    }
    /* If tags do not match */
    if(tag_different != 0){
        for(i = 0; i < ((x_length + 7) >> 3); i++){ 
            y[i] = 0;
        }
        for(i = 0; i < ((t_length + 7) >> 3); i++){ 
            t[i] = 0;
        }
        return -1;
    }
    else
        return 0;
}
