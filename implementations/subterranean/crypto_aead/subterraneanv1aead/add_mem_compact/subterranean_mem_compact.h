#ifndef _SUBTERRANEAN_MEM_COMPACT_H_
#define _SUBTERRANEAN_MEM_COMPACT_H_

#define SUBTERRANEAN_BYTE_SIZE 33

void subterranean_round(unsigned char state[SUBTERRANEAN_BYTE_SIZE]);

void subterranean_init(unsigned char state[SUBTERRANEAN_BYTE_SIZE]);
void subterranean_duplex_empty(unsigned char state[SUBTERRANEAN_BYTE_SIZE]);
void subterranean_duplex_simple(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * sigma, const unsigned char size_bytes);
void subterranean_duplex_encrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * value_out, const unsigned char * sigma, const unsigned char size_bytes);
void subterranean_duplex_decrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * value_out, const unsigned char * sigma, const unsigned char size_bytes);
void subterranean_squeeze_simple(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char value_out[4]);

void subterranean_absorb_unkeyed(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * value_in, const unsigned long long value_in_length);
void subterranean_absorb_keyed(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * value_in, const unsigned long long value_in_length);
void subterranean_absorb_encrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * value_out, const unsigned char * value_in, const unsigned long long value_in_length);
void subterranean_absorb_decrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * value_out, const unsigned char * value_in, const unsigned long long value_in_length);
void subterranean_blank(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char r_calls);
void subterranean_squeeze(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * value_out, const unsigned long long value_out_length);

void subterranean_xof_init(unsigned char state[SUBTERRANEAN_BYTE_SIZE]);
void subterranean_xof_update(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * m, const unsigned long long m_length);
void subterranean_xof_finalize(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * z, const unsigned long long z_length);
void subterranean_xof_direct(unsigned char * z, const unsigned long long z_length, const unsigned char * m, const unsigned long long m_length);

void subterranean_deck_init(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * k, const unsigned long long k_length);
void subterranean_deck_update(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * m, const unsigned long long m_length);
void subterranean_deck_finalize(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * z, const unsigned long long z_length);
void subterranean_deck_direct(unsigned char * z, const unsigned long long z_length, const unsigned char * k, const unsigned long long k_length, const unsigned char * m, const unsigned long long m_length);

void subterranean_SAE_start(unsigned char state[SUBTERRANEAN_BYTE_SIZE], const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length);
int subterranean_SAE_wrap_encrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * y, unsigned char * t, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length);
int subterranean_SAE_wrap_decrypt(unsigned char state[SUBTERRANEAN_BYTE_SIZE], unsigned char * y, unsigned char * t, const unsigned char * t_prime, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length);
int subterranean_SAE_direct_encrypt(unsigned char * y, unsigned char * t, const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length);
int subterranean_SAE_direct_decrypt(unsigned char * y, unsigned char * t, const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length, const unsigned char * t_prime, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length);

#endif