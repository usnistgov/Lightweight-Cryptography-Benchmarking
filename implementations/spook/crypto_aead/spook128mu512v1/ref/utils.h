/* Spook Reference Implementation v1
 *
 * Written in 2019 at UCLouvain (Belgium) by Olivier Bronchain, Gaetan Cassiers
 * and Charles Momin.
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#ifndef _H_UTILS_H_
#define _H_UTILS_H_

#include <stdint.h>

void xor_bytes(unsigned char* dest, const unsigned char* src1,
               const unsigned char* src2, unsigned long long n);

uint32_t rotr(uint32_t x, unsigned int c);

uint32_t le32u_dec(const unsigned char bytes[4]);

void le32u_enc(unsigned char bytes[4], uint32_t x);

#endif // _H_UTILS_H_
