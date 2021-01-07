#ifndef API_H
#define API_H

#define CRYPTO_KEYBYTES 16 // Size of the key in bytes.
#define CRYPTO_NSECBYTES 0 // UNUSED
#define CRYPTO_NOOVERLAP 1 // Shall be set to one.

/* SELECT INSTANCE HERE */
//#define paefforkskinnyb64t192n48
//#define paefforkskinnyb128t192n48
#define paefforkskinnyb128t256n112
//#define paefforkskinnyb128t288n104
//#define saefforkskinnyb128t192n56
//#define saefforkskinnyb128t256n120

#ifdef paefforkskinnyb64t192n48
	#define PAEF
	#define CRYPTO_NPUBBYTES 6 // Size of the nonce in bytes.
	#define CRYPTO_ABYTES 8 // Ciphertext expansion is one block, always.
	#define CRYPTO_BLOCKSIZE 8
	#define CRYPTO_TWEAKSIZE 8
	#define CRYPTO_TWEAKEYSIZE (CRYPTO_KEYBYTES+CRYPTO_TWEAKSIZE) //
	#define TWEAKEY_BLOCKSIZE_RATIO ((CRYPTO_TWEAKEYSIZE % CRYPTO_BLOCKSIZE == 0) ? ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE)) : ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE) + 1)) /* Number of tweakey states */
	#define CRYPTO_NBROUNDS_BEFORE 17 // Number of rounds before forking
	#define CRYPTO_NBROUNDS_AFTER 23 // Number of rounds after forking
#endif

#ifdef paefforkskinnyb128t192n48
	#define PAEF
	#define CRYPTO_NPUBBYTES 6 // Size of the nonce in bytes.
	#define CRYPTO_ABYTES 16 // Ciphertext expansion is one block, always.
	#define CRYPTO_BLOCKSIZE 16
	#define CRYPTO_TWEAKSIZE 8
	#define CRYPTO_TWEAKEYSIZE (CRYPTO_KEYBYTES+CRYPTO_TWEAKSIZE) //
	#define TWEAKEY_BLOCKSIZE_RATIO ((CRYPTO_TWEAKEYSIZE % CRYPTO_BLOCKSIZE == 0) ? ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE)) : ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE) + 1)) /* Number of tweakey states */
	#define CRYPTO_NBROUNDS_BEFORE 21 // Number of rounds before forking
	#define CRYPTO_NBROUNDS_AFTER 27 // Number of rounds after forking
#endif

#ifdef paefforkskinnyb128t256n112
	#define PAEF
	#define CRYPTO_NPUBBYTES 14 // Size of the nonce in bytes.
	#define CRYPTO_ABYTES 16 // Ciphertext expansion is one block, always.
	#define CRYPTO_BLOCKSIZE 16
	#define CRYPTO_TWEAKSIZE 16
	#define CRYPTO_TWEAKEYSIZE (CRYPTO_KEYBYTES+CRYPTO_TWEAKSIZE) //
	#define TWEAKEY_BLOCKSIZE_RATIO ((CRYPTO_TWEAKEYSIZE % CRYPTO_BLOCKSIZE == 0) ? ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE)) : ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE) + 1)) /* Number of tweakey states */
	#define CRYPTO_NBROUNDS_BEFORE 21 // Number of rounds before forking
	#define CRYPTO_NBROUNDS_AFTER 27 // Number of rounds after forking
#endif

#ifdef paefforkskinnyb128t288n104
	#define PAEF
	#define CRYPTO_NPUBBYTES 13 // Size of the nonce in bytes.
	#define CRYPTO_ABYTES 16 // Ciphertext expansion is one block, always.
	#define CRYPTO_BLOCKSIZE 16
	#define CRYPTO_TWEAKSIZE 20
	#define CRYPTO_TWEAKEYSIZE (CRYPTO_KEYBYTES+CRYPTO_TWEAKSIZE) //
	#define TWEAKEY_BLOCKSIZE_RATIO ((CRYPTO_TWEAKEYSIZE % CRYPTO_BLOCKSIZE == 0) ? ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE)) : ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE) + 1)) /* Number of tweakey states */
	#define CRYPTO_NBROUNDS_BEFORE 25 // Number of rounds before forking
	#define CRYPTO_NBROUNDS_AFTER 31 // Number of rounds after forking
#endif

#ifdef saefforkskinnyb128t192n56
	#define SAEF
	#define CRYPTO_NPUBBYTES 7 // Size of the nonce in bytes.
	#define CRYPTO_ABYTES 16 // Ciphertext expansion is one block, always.
	#define CRYPTO_BLOCKSIZE 16
	#define CRYPTO_TWEAKSIZE 8
	#define CRYPTO_TWEAKEYSIZE (CRYPTO_KEYBYTES+CRYPTO_TWEAKSIZE) //
	#define TWEAKEY_BLOCKSIZE_RATIO ((CRYPTO_TWEAKEYSIZE % CRYPTO_BLOCKSIZE == 0) ? ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE)) : ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE) + 1)) /* Number of tweakey states */
	#define CRYPTO_NBROUNDS_BEFORE 21 // Number of rounds before forking
	#define CRYPTO_NBROUNDS_AFTER 27 // Number of rounds after forking
#endif

#ifdef saefforkskinnyb128t256n120
	#define SAEF
	#define CRYPTO_NPUBBYTES 15 // Size of the nonce in bytes.
	#define CRYPTO_ABYTES 16 // Ciphertext expansion is one block, always.
	#define CRYPTO_BLOCKSIZE 16
	#define CRYPTO_TWEAKSIZE 16
	#define CRYPTO_TWEAKEYSIZE (CRYPTO_KEYBYTES+CRYPTO_TWEAKSIZE) //
	#define TWEAKEY_BLOCKSIZE_RATIO ((CRYPTO_TWEAKEYSIZE % CRYPTO_BLOCKSIZE == 0) ? ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE)) : ((CRYPTO_TWEAKEYSIZE/CRYPTO_BLOCKSIZE) + 1)) /* Number of tweakey states */
	#define CRYPTO_NBROUNDS_BEFORE 21 // Number of rounds before forking
	#define CRYPTO_NBROUNDS_AFTER 27 // Number of rounds after forking
#endif

#endif
