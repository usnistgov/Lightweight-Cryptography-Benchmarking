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
#ifndef _H_PRIMITIVES_H_
#define _H_PRIMITIVES_H_

#include "parameters.h"

#define CLYDE128_NBYTES 16

#if SMALL_PERM
#define SHADOW_NBYTES 48
#else
#define SHADOW_NBYTES 64
#endif // SMALL_PERM

void clyde128_encrypt(unsigned char* c, const unsigned char* m,
                      const unsigned char* t, const unsigned char* k);

void clyde128_decrypt(unsigned char* m, const unsigned char* c,
                      const unsigned char* t, const unsigned char* k);

void shadow(unsigned char* x);

#endif //_H_PRIMITIVES_H_
