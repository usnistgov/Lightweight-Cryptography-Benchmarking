/*
Written by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 25 Feb 2019
*/

#include <stdint.h>

int sundae_enc(const uint8_t* N, unsigned long long Nlen,
                const uint8_t* A, unsigned long long Alen,
                const uint8_t* M, unsigned long long Mlen,
                const uint8_t K[16],
                uint8_t* C,
                int outputTag);

int sundae_dec(const uint8_t* N, unsigned long long Nlen,
                const uint8_t* A, unsigned long long Alen,
                uint8_t* M,
                const uint8_t K[16],
                const uint8_t* C, unsigned long long Clen);
