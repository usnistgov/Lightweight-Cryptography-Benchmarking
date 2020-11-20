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
#include <stdint.h>

#include "utils.h"

// XOR buffers src1 and src2 into buffer dest (all buffers contain n bytes).
void xor_bytes(unsigned char* dest, const unsigned char* src1,
               const unsigned char* src2, unsigned long long n) {
  for (unsigned long long i = 0; i < n; i++) {
    dest[i] = src1[i] ^ src2[i];
  }
}

// Rotate right x by amount c.
// We use right rotation of integers for the lboxes while the specification
// tells left rotation of bitstrings due to the bitsting -> integer
// little-endian mapping used in Spook.
uint32_t rotr(uint32_t x, unsigned int c) { return (x >> c) | (x << (32 - c)); }

// Convert 4 bytes into a uint32. Bytes are in little-endian.
uint32_t le32u_dec(const unsigned char bytes[4]) {
  uint32_t res = 0;
  for (unsigned int col = 0; col < 4; col++) {
    res |= ((uint32_t)bytes[col]) << 8 * col;
  }
  return res;
}

// Convert a uint32 into 4 bytes. Bytes are in little-endian.
void le32u_enc(unsigned char bytes[4], uint32_t x) {
  for (unsigned int i = 0; i < 4; i++) {
    bytes[i] = x >> 8 * i;
  }
}
