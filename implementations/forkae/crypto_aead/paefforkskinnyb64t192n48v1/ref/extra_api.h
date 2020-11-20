/* Definitions and parameters complementary to api.h */

#ifndef EXTRA_API_H
#define EXTRA_API_H


#include "api.h"

#define CRYPTO_BLOCKSIZE 8
#define CRYPTO_TWEAKSIZE 8
#define CRYPTO_TWEAKEYSIZE (CRYPTO_KEYBYTES+CRYPTO_TWEAKSIZE) // 
#define TWEAKEY_BLOCKSIZE_RATIO ((CRYPTO_TWEAKEYSIZE % CRYPTO_BLOCKSIZE == 0) ? ((int) (CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE)) : ((int) (CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE) + 1)) /* Number of tweakey states */
#define CRYPTO_BLOCKSIZE_8
#define CRYPTO_NBROUNDS_BEFORE 17 // Number of rounds before forking
#define CRYPTO_NBROUNDS_AFTER 23 // Number of rounds after forking 

#endif