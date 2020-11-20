#ifndef SCHWAEMMCONFIG_H
#define SCHWAEMMCONFIG_H

//Define the version SCHWAEMM here. Notice that api.h must match.
#define SCHWAEMM128_128

//sizes are given in bits. For use in the code, util.h defines BYTE and WORD
//macros for on-the-fly conversion.

#define CRYPTO_KEYWORDS (CRYPTO_KEYBYTES/4)
#define CRYPTO_NPUBWORDS (CRYPTO_NPUBBYTES/4)


#if defined SCHWAEMM256_128

    #define STATESIZE 384
    #define RATE 256
    #define CAPACITY 128
    #define STEPSSLIM 7
    #define STEPSBIG 11
    #define B 3

    #define   PADADCONST (0 ^ (1 << 2)) /* 4 */
    #define NOPADADCONST (1 ^ (1 << 2)) /* 5 */
    #define   PADPTCONST (2 ^ (1 << 2)) /* 6 */
    #define NOPADPTCONST (3 ^ (1 << 2)) /* 7 */

#elif defined SCHWAEMM192_192

    #define STATESIZE 384
    #define RATE 192
    #define CAPACITY 192
    #define STEPSSLIM 7
    #define STEPSBIG 11
    #define B 3

    #define   PADADCONST (0 ^ (1 << 3)) /* 8 */
    #define NOPADADCONST (1 ^ (1 << 3)) /* 9 */
    #define   PADPTCONST (2 ^ (1 << 3)) /* 10 */
    #define NOPADPTCONST (3 ^ (1 << 3)) /* 11 */

#elif defined SCHWAEMM128_128

    #define STATESIZE 256
    #define RATE 128
    #define CAPACITY 128
    #define STEPSSLIM 7
    #define STEPSBIG 10
    #define B 2

    #define   PADADCONST (0 ^ (1 << 2)) /* 4 */
    #define NOPADADCONST (1 ^ (1 << 2)) /* 5 */
    #define   PADPTCONST (2 ^ (1 << 2)) /* 6 */
    #define NOPADPTCONST (3 ^ (1 << 2)) /* 7 */

#elif defined SCHWAEMM256_256

    #define STATESIZE 512
    #define RATE 256
    #define CAPACITY 256
    #define STEPSSLIM 8
    #define STEPSBIG 12
    #define B 4

    #define   PADADCONST (0 ^ (1 << 4)) /* 16 */
    #define NOPADADCONST (1 ^ (1 << 4)) /* 17 */
    #define   PADPTCONST (2 ^ (1 << 4)) /* 18 */
    #define NOPADPTCONST (3 ^ (1 << 4)) /* 19 */
#else
    #error "Invalid definition of algorithm instance."
#endif

#endif /*SCHWAEMMCONFIG_H*/
