#include "api.h"
#include <string.h>
#include "elephant_200.h"

#include "crypto_aead.h"

const WORD incomplete_block_mask[] = {
    0x0000000000000000ULL,
    0x8080808080808080ULL,
    0xc0c0c0c0c0c0c0c0ULL,
    0xe0e0e0e0e0e0e0e0ULL,
    0xf0f0f0f0f0f0f0f0ULL,
    0xf8f8f8f8f8f8f8f8ULL,
    0xfcfcfcfcfcfcfcfcULL,
    0xfefefefefefefefeULL
};

void mask_block(WORD *source, const WORD mask)
{
    for(SIZE l = 0; l < BLOCK_SIZE; l++)
        source[l] &= mask;
}

WORD slice_in(const WORD source){
    WORD dest = source & 0x8040201008040201ULL;
    dest |= (source<<7) & 0x4020100804020100ULL;
    dest |= (source<<14) & 0x2010080402010000ULL;
    dest |= (source<<21) & 0x1008040201000000ULL;
    dest |= (source<<28) & 0x0804020100000000ULL;
    dest |= (source<<35) & 0x0402010000000000ULL;
    dest |= (source<<42) & 0x0201000000000000ULL;
    dest |= (source<<49) & 0x0100000000000000ULL;

    dest |= (source>>7) & 0x80402010080402ULL;
    dest |= (source>>14) & 0x804020100804ULL;
    dest |= (source>>21) & 0x8040201008ULL;
    dest |= (source>>28) & 0x80402010ULL;
    dest |= (source>>35) & 0x804020ULL;
    dest |= (source>>42) & 0x8040ULL;
    dest |= (source>>49) & 0x80ULL;
    return dest;
}

void slice_in_block(WORD *source)
{
    for(SIZE l = 0; l < BLOCK_SIZE; l++)
        source[l] = slice_in(source[l]);
}

void slice_in_nonce(WORD *source)
{
    for(SIZE l = 0; l < CRYPTO_NPUBBYTES; l++)
        source[l] = slice_in(source[l]);
}

int constcmp(const BYTE* a, const BYTE* b, SIZE length)
{
    BYTE r = 0;

    for (SIZE i = 0; i < length; ++i)
    r |= a[i] ^ b[i];
    return r;
}

// State should be BLOCK_SIZE bytes long
// Note: input may be equal to output
void lfsr_step(BYTE* output, BYTE* input)
{
    BYTE temp = ROL8(input[0],1) ^ ROL8(input[2],1) ^ (input[13] << 1);
    for(SIZE i = 0; i < BLOCK_SIZE - 1; ++i)
        output[i] = input[i + 1];
    output[BLOCK_SIZE - 1] = temp;
}

void big_lfsr_step(WORD* output, WORD* input)
{
    WORD temp = ROL64(input[0],8) ^ ROL64(input[2],8) ^ ((input[13] << 8));
#ifdef MANUAL_LOOP_UNROLLING
    output[ 0] = input[ 1];
    output[ 1] = input[ 2];
    output[ 2] = input[ 3];
    output[ 3] = input[ 4];
    output[ 4] = input[ 5];
    output[ 5] = input[ 6];
    output[ 6] = input[ 7];
    output[ 7] = input[ 8];
    output[ 8] = input[ 9];
    output[ 9] = input[10];
    output[10] = input[11];
    output[11] = input[12];
    output[12] = input[13];
    output[13] = input[14];
    output[14] = input[15];
    output[15] = input[16];
    output[16] = input[17];
    output[17] = input[18];
    output[18] = input[19];
    output[19] = input[20];
    output[20] = input[21];
    output[21] = input[22];
    output[22] = input[23];
    output[23] = input[24];
#else
    for(SIZE i = 0; i < BLOCK_SIZE - 1; ++i)
        output[i] = input[i + 1];
#endif
    output[BLOCK_SIZE - 1] = temp;
}

void xor_tag_block(BYTE* state, const BYTE* block)
{
    for(SIZE i = 0; i < CRYPTO_ABYTES; ++i)
        state[i] ^= block[i];
}

void xor_block(BYTE* state, const BYTE* block, SIZE size)
{
    for(SIZE i = 0; i < size; ++i)
        state[i] ^= block[i];
}

void xor_blocks(BYTE* dest, const BYTE* src1, const BYTE* src2, SIZE size)
{
    for(SIZE i = 0; i < size; ++i)
        dest[i] = src1[i] ^ src2[i];
}

void xor_words(WORD* dest, const WORD* src)
{
    for(SIZE i = 0; i < BLOCK_SIZE; ++i)
        dest[i] ^= src[i];
}

void prepare_big_buffer(WORD* dest, const BYTE* src, SIZE size)
{
    for(SIZE l = 0; l < size; l++){
        dest[l] <<= 8;
        dest[l] |= src[l];
    }
}


// Write the ith assocated data block to "output".
// The nonce is prepended and padding is added as required.
// adlen is the length of the associated data in bytes
void get_ad_block(BYTE* output, const BYTE* ad, SIZE adlen, const BYTE* npub, SIZE i)
{
    SIZE len = 0;
    // First block contains nonce
    // Remark: nonce may not be longer then BLOCK_SIZE
    if(i == 0) {
        memcpy(output, npub, CRYPTO_NPUBBYTES);
        len += CRYPTO_NPUBBYTES;
    }
  
    const SIZE block_offset = i * BLOCK_SIZE - (i != 0) * CRYPTO_NPUBBYTES;
    // If adlen is divisible by BLOCK_SIZE, add an additional padding block
    if(i != 0 && block_offset == adlen) {
        memset(output, 0x00, BLOCK_SIZE);
        output[0] = 0x01;
        return;
    }
    const SIZE r_outlen = BLOCK_SIZE - len;
    const SIZE r_adlen  = adlen - block_offset;
    // Fill with associated data if available
    if(r_outlen <= r_adlen) { // enough AD
        memcpy(output + len, ad + block_offset, r_outlen);
    } else { // not enough AD, need to pad
        if(r_adlen > 0) // ad might be nullptr
            memcpy(output + len, ad + block_offset, r_adlen);
        memset(output + len + r_adlen, 0x00, r_outlen - r_adlen);
        output[len + r_adlen] = 0x01;
    }
}

// Return the ith ciphertext block.
// clen is the length of the ciphertext in bytes
void get_c_block(BYTE* output, const BYTE* c, SIZE clen, SIZE i)
{
    const SIZE block_offset = i * BLOCK_SIZE;
    // If clen is divisible by BLOCK_SIZE, add an additional padding block
    if(block_offset == clen) {
        memset(output, 0x00, BLOCK_SIZE);
        output[0] = 0x01;
        return;
    }
    const SIZE r_clen  = clen - block_offset;
    // Fill with ciphertext if available
    if(BLOCK_SIZE <= r_clen) { // enough ciphertext
        memcpy(output, c + block_offset, BLOCK_SIZE);
    } else { // not enough ciphertext, need to pad
        if(r_clen > 0) // c might be nullptr
            memcpy(output, c + block_offset, r_clen);
        memset(output + r_clen, 0x00, BLOCK_SIZE - r_clen);
        output[r_clen] = 0x01;
    }
}

// It is assumed that c is sufficiently long
// Also, tag and c should not overlap
void crypto_aead_impl(
    BYTE* c, BYTE* tag, const BYTE* m, SIZE mlen, const BYTE* ad, SIZE adlen,
    const BYTE* npub, const BYTE* k, int encrypt)
{
    // Compute number of blocks
    const SIZE nblocks_c  = 1 + mlen / BLOCK_SIZE;
    const SIZE nblocks_m  = (mlen % BLOCK_SIZE) ? nblocks_c : nblocks_c - 1;
    const SIZE nblocks_ad = 1 + (CRYPTO_NPUBBYTES + adlen) / BLOCK_SIZE;
    const SIZE nb_it = (nblocks_c > nblocks_ad) ? nblocks_c : nblocks_ad + 1;

    // Storage for the expanded key L
    BYTE expanded_key[BLOCK_SIZE] = {0};
    memcpy(expanded_key, k, CRYPTO_KEYBYTES);
    permutation(expanded_key);

    // Buffer to store blocks
    BYTE block_buffer[BLOCK_SIZE] = {0};
    memcpy(block_buffer, expanded_key, BLOCK_SIZE);

    // Big Buffers for storing previous, current and next mask
    WORD big_mask_buffer_1[BLOCK_SIZE] = {0};
    WORD big_mask_buffer_2[BLOCK_SIZE] = {0};
    WORD big_mask_buffer_3[BLOCK_SIZE] = {0};
    for(SIZE i = 0; i < WORDSIZE; i++) {
        prepare_big_buffer(big_mask_buffer_2, block_buffer, BLOCK_SIZE);
        lfsr_step(block_buffer, block_buffer);
    }
    slice_in_block(big_mask_buffer_2);

    WORD* big_next_next_mask = big_mask_buffer_1;
    WORD* big_current_mask = big_mask_buffer_2;
    WORD* big_next_mask = big_mask_buffer_3;
    big_lfsr_step(big_next_mask, big_current_mask);
    big_lfsr_step(big_next_next_mask, big_next_mask);

    // Prepare nonce in big buffer
    WORD big_n_buffer[BLOCK_SIZE] = {0};
    for(SIZE i = 0; i < WORDSIZE; i++)
        prepare_big_buffer(big_n_buffer, npub, CRYPTO_NPUBBYTES);
    slice_in_nonce(big_n_buffer);

    // Set tag to 0
    memset(tag, 0, CRYPTO_ABYTES);
    WORD big_tag_buffer[BLOCK_SIZE] = {0};

    WORD big_buffer[BLOCK_SIZE] = {0};
    for(SIZE i = 0; i < nb_it; i += WORDSIZE) {
        // Compute ciphertext block
        if(i < nblocks_m) {
            memcpy(big_buffer, big_n_buffer, WORDSIZE * BLOCK_SIZE);
            xor_words(big_buffer, big_current_mask);
            bigpermutation(big_buffer);
            xor_words(big_buffer, big_current_mask);
            slice_in_block(big_buffer);

            // Extract ciphertext block
            for(SIZE j = i; j < i+WORDSIZE  && j < nblocks_m; j++) {
                const SIZE r_size = (j == nblocks_m - 1) ? mlen - (j*BLOCK_SIZE) : BLOCK_SIZE;
                for(SIZE l = 0; l < r_size; l++)
                    block_buffer[l] = (BYTE) (big_buffer[l] >> (8*(WORDSIZE-1-j+i)));

                xor_blocks(c + (j*BLOCK_SIZE), m + (j*BLOCK_SIZE), block_buffer, r_size);
            }
        }

        // Compute tag for ciphertext block
        if(i < nblocks_c) {
            memset(big_buffer, 0x00, WORDSIZE * BLOCK_SIZE);
            for(SIZE j = i; j < i+WORDSIZE  && j < nblocks_c; j++){
                get_c_block(block_buffer, encrypt ? c : m, mlen, j);
                for(SIZE l = 0; l < BLOCK_SIZE; l++)
                    big_buffer[l] ^= ((WORD) block_buffer[l]) << (8*(WORDSIZE-1-j+i));
            }

            slice_in_block(big_buffer);
            xor_words(big_buffer, big_current_mask);
            xor_words(big_buffer, big_next_mask);
            bigpermutation(big_buffer);
            xor_words(big_buffer, big_current_mask);
            xor_words(big_buffer, big_next_mask);

            // XOR to tag buffer, mask if incomplete
            const SIZE nb_blocks_remaining = nblocks_c - i;
            if(nb_blocks_remaining < WORDSIZE)
                mask_block(big_buffer, incomplete_block_mask[nb_blocks_remaining]);
            xor_words(big_tag_buffer, big_buffer);
        }

        // If there is any AD left, compute tag for AD block
        if(i < nblocks_ad) {
            memset(big_buffer, 0x00, WORDSIZE * BLOCK_SIZE);
            for(SIZE j = i; j < i+WORDSIZE  && j < nblocks_ad; j++){
                get_ad_block(block_buffer, ad, adlen, npub, j);
                for(SIZE l = 0; l < BLOCK_SIZE; l++){
                    big_buffer[l] ^= ((WORD) block_buffer[l]) << (8*(WORDSIZE-1-j+i));
                    block_buffer[l] = (big_buffer[l] >> (8*(WORDSIZE-1-j+i)));
                }
            }

            slice_in_block(big_buffer);
            xor_words(big_buffer, big_current_mask);
            xor_words(big_buffer, big_next_next_mask);
            bigpermutation(big_buffer);
            xor_words(big_buffer, big_current_mask);
            xor_words(big_buffer, big_next_next_mask);

            // XOR to tag buffer, mask if incomplete
            if(nblocks_ad - i < WORDSIZE)
                mask_block(big_buffer, incomplete_block_mask[nblocks_ad - i]);
            xor_words(big_tag_buffer, big_buffer);
        }

      if(i + WORDSIZE < nb_it){
          WORD* const temp = big_current_mask;
          big_current_mask = big_next_next_mask;
          big_next_next_mask = temp;
          for(SIZE l = 0; l < WORDSIZE - 2; l++)
              big_lfsr_step(big_current_mask, big_current_mask);

          big_lfsr_step(big_next_mask, big_current_mask);
          big_lfsr_step(big_next_next_mask, big_next_mask);
      }
  }

  // Finish tag computation
  slice_in_block(big_tag_buffer);
  for(SIZE i = 0; i < WORDSIZE; ++i) {
      for(SIZE l = 0; l < CRYPTO_ABYTES; l++)
          block_buffer[l] = (BYTE) (big_tag_buffer[l] >> (8*(WORDSIZE-1-i)));
      xor_tag_block(tag, block_buffer);
  }
}

// Remark: c must be at least mlen + CRYPTO_ABYTES long
int crypto_aead_encrypt(
    unsigned char *c, unsigned long long *clen,
    const unsigned char *m, unsigned long long mlen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *nsec,
    const unsigned char *npub,
    const unsigned char *k)
{
    (void)nsec;
    *clen = mlen + CRYPTO_ABYTES;
    BYTE tag[CRYPTO_ABYTES];
    crypto_aead_impl(c, tag, m, mlen, ad, adlen, npub, k, 1);
    memcpy(c + mlen, tag, CRYPTO_ABYTES);
    return 0;
}

int crypto_aead_decrypt(
    unsigned char *m, unsigned long long *mlen,
    unsigned char *nsec,
    const unsigned char *c, unsigned long long clen,
    const unsigned char *ad, unsigned long long adlen,
    const unsigned char *npub,
    const unsigned char *k)
{
    (void)nsec;
    if(clen < CRYPTO_ABYTES)
    return -1;
    *mlen = clen - CRYPTO_ABYTES;
    BYTE tag[CRYPTO_ABYTES];
    crypto_aead_impl(m, tag, c, *mlen, ad, adlen, npub, k, 0);
    return (constcmp(c + *mlen, tag, CRYPTO_ABYTES) == 0) ? 0 : -1;
}
