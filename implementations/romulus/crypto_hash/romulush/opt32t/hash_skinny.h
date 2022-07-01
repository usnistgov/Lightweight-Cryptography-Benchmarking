#define ___SKINNY_LOOP
//#define ___NUM_OF_ROUNDS_56

#include <stdint.h>

typedef struct ___hash_skinny_ctrl {
#ifdef ___NUM_OF_ROUNDS_56
    uint32_t roundKeys[144]; // number of rounds : 56
#else
    uint32_t roundKeys[112]; // number of rounds : 40
#endif
    void (*func_skinny_128_384_enc)(unsigned char*, unsigned char*, struct ___hash_skinny_ctrl*, unsigned char*, unsigned char*);
} hash_skinny_ctrl;

extern void hash_skinny_128_384_enc_321_main (unsigned char* h, unsigned char* g, hash_skinny_ctrl* pskinny_ctrl, unsigned char* key, unsigned char* m);
extern void hash_skinny_128_384_enc_32_main (unsigned char* h, unsigned char*g, hash_skinny_ctrl* pskinny_ctrl, unsigned char* key, unsigned char* m);

#define pack_word(x0, x1, x2, x3, w)    \
  w  = ((x3) << 24) ^                   \
       ((x2) << 16) ^                   \
       ((x1) << 8) ^                    \
       (x0);

#define unpack_word(x0, x1, x2, x3, w)  \
  x0  = ((w) & 0xff);                   \
  x1  = (((w) >> 8) & 0xff);            \
  x2  = (((w) >> 16) & 0xff);           \
  x3  = ((w) >> 24);

#define PERMUTATION(w0, w1)                                                       \
/* permutation */                                                                 \
                                                                                  \
  /* 7 6 5 4 3 2 1 0 */                                                           \
  /* 5 7 2 3 6 0 4 1 */                                                           \
                                                                                  \
  /* w0 (3 2 1 0) */                                                              \
  /* w1 (7 6 5 4) */                                                              \
                                                                                  \
  /* w0 (6 0 4 1) */                                                              \
  /* w1 (5 7 2 3) */                                                              \
                                                                                  \
  t0 = w1 << 8;         /* 6 5 4 - */                                             \
  t0 = t0 & 0xff00ff00; /* 6 - 4 - */                                             \
                                                                                  \
  t1 = w1 << 16;        /* 5 4 - - */                                             \
  t1 = t1 & 0xff000000; /* 5 - - - */                                             \
                                                                                  \
  t2 = w1 & 0xff000000; /* 7 - - - */                                             \
  t2 = t2 >> 8;         /* - 7 - - */                                             \
  t1 = t1 ^ t2;         /* 5 7 - - */                                             \
                                                                                  \
  t2 = w0 & 0xff000000; /* 3 - - - */                                             \
  t2 = t2 >> 24;        /* - - - 3 */                                             \
  t1 = t1 ^ t2;         /* 5 7 - 3 */                                             \
                                                                                  \
  w1 = w0 >> 8;         /* - 3 2 1 */                                             \
  w1 = w1 & 0x0000ff00; /* - - 2 - */                                             \
  w1 = w1 ^ t1;         /* 5 7 2 3 */                                             \
                                                                                  \
  t2 = w0 & 0x0000ff00; /* - - 1 - */                                             \
  t2 = t2 >> 8;         /* - - - 1 */                                             \
  t0 = t0 ^ t2;         /* 6 - 4 1 */                                             \
                                                                                  \
  w0 = w0 << 16;        /* 1 0 - - */                                             \
  w0 = w0 & 0x00ff0000; /* - 0 - - */                                             \
  w0 = w0 ^ t0;         /* 6 0 4 1 */ 

