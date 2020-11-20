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
#ifndef _PARAMETERS_H_
#define _PARAMETERS_H_

#define MULTI_USER 1
#define SMALL_PERM 1

#if MULTI_USER
#define KEYBYTES 32
#else
#define KEYBYTES 16
#endif

#include "api.h"

#if (KEYBYTES != CRYPTO_KEYBYTES)
#error "Wrong parameters in api.h"
#endif

#endif //_PARAMETERS_H_
