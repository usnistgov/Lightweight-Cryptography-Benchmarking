#ifndef _SUBTERRANEAN_REF_H_
#define _SUBTERRANEAN_REF_H_

#define SUBTERRANEAN_SIZE 257

void byte_array_to_bit_array(unsigned char * o, const unsigned char * a, const unsigned char alen);
void bit_array_to_byte_array(unsigned char * o, const unsigned char * a, const unsigned char alen);

void subterranean_round(unsigned char state[SUBTERRANEAN_SIZE]);

void subterranean_init(unsigned char state[SUBTERRANEAN_SIZE]);
void subterranean_absorb_unkeyed(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * value_in, const unsigned long long value_in_length);
void subterranean_absorb_keyed(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * value_in, const unsigned long long value_in_length);
void subterranean_absorb_encrypt(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * value_out, const unsigned char * value_in, const unsigned long long value_in_length);
void subterranean_absorb_decrypt(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * value_out, const unsigned char * value_in, const unsigned long long value_in_length);
void subterranean_duplex(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * sigma, const unsigned char size);
void subterranean_extract(unsigned char state[SUBTERRANEAN_SIZE], unsigned char value_out[32]);
void subterranean_blank(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char r_calls);
void subterranean_squeeze(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * value_out, const unsigned long long value_out_length);

void subterranean_xof_init(unsigned char state[SUBTERRANEAN_SIZE]);
void subterranean_xof_update(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * m, const unsigned long long m_length);
void subterranean_xof_finalize(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * z, const unsigned long long z_length);
void subterranean_xof_direct(unsigned char * z, unsigned long long z_length, const unsigned char * m, const unsigned long long m_length);

void subterranean_deck_init(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * k, const unsigned long long k_length);
void subterranean_deck_update(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * m, const unsigned long long m_length);
void subterranean_deck_finalize(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * z, const unsigned long long z_length);
void subterranean_deck_direct(unsigned char * z, unsigned long long z_length, const unsigned char * k, const unsigned long long k_length, const unsigned char * m, const unsigned long long m_length);

void subterranean_SAE_start(unsigned char state[SUBTERRANEAN_SIZE], const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length);
int subterranean_SAE_wrap_encrypt(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * y, unsigned char * t, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length);
int subterranean_SAE_wrap_decrypt(unsigned char state[SUBTERRANEAN_SIZE], unsigned char * y, unsigned char * t, const unsigned char * t_prime, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length);
int subterranean_SAE_direct_encrypt(unsigned char * y, unsigned char * t, const unsigned char * k, const unsigned long long k_length, const unsigned char * n, const unsigned long long n_length, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length);
int subterranean_SAE_direct_decrypt(unsigned char * y, unsigned char * t, const unsigned char * k, const unsigned long long k_length, const unsigned char * n,const unsigned long long n_length, const unsigned char * t_prime, const unsigned long long t_length, const unsigned char * a, const unsigned long long a_length, const unsigned char * x, const unsigned long long x_length);


#endif