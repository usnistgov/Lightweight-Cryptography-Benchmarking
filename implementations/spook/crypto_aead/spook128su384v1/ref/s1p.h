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
#ifndef _H_S1P_H_
#define _H_S1P_H_

#include "parameters.h"

// Size of the P parameter
#define P_NBYTES 16

void s1p_encrypt(unsigned char *c, unsigned long long *clen,
                 const unsigned char *ad, unsigned long long adlen,
                 const unsigned char *m, unsigned long long mlen,
                 const unsigned char *k, const unsigned char *p,
                 const unsigned char *n);

int s1p_decrypt(unsigned char *m, unsigned long long *mlen,
                const unsigned char *ad, unsigned long long adlen,
                const unsigned char *c, unsigned long long clen,
                const unsigned char *k, const unsigned char *p,
                const unsigned char *n);

void init_keys(const unsigned char **k, unsigned char p[P_NBYTES],
               const unsigned char *k_glob);

#endif //_H_S1P_H_
