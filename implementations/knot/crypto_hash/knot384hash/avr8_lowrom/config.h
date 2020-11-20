#ifndef __CONFIG_H__
#define __CONFIG_H__

//#define CRYPTO_AEAD
#define CRYPTO_HASH

#define   MAX_MESSAGE_LENGTH      128

#define   STATE_INBITS            384
/* For CRYPTO_AEAD */
#define   CRYPTO_KEYBITS          192
/* For CRYPTO_HASH */
#define   CRYPTO_BITS             384

#define   STATE_INBYTES         ((STATE_INBITS + 7) / 8)
#define   ROW_INBITS            ((STATE_INBITS + 3) / 4)
#define   ROW_INBYTES           ((ROW_INBITS   + 7) / 8)

/* For CRYPTO_AEAD */
#define   CRYPTO_KEYBYTES   ((CRYPTO_KEYBITS + 7) / 8)
#define   CRYPTO_NSECBYTES  0
#define   CRYPTO_NPUBBYTES  CRYPTO_KEYBYTES
#define   CRYPTO_ABYTES     CRYPTO_KEYBYTES
#define   CRYPTO_NOOVERLAP  1

#define   MAX_ASSOCIATED_DATA_LENGTH  32
#define   MAX_CIPHER_LENGTH           (MAX_MESSAGE_LENGTH + CRYPTO_ABYTES)

#define   TAG_MATCH        0
#define   TAG_UNMATCH     -1
#define   OTHER_FAILURES  -2

/* For CRYPTO_HASH */
#define   CRYPTO_BYTES            ((CRYPTO_BITS + 7) / 8)



#define DOMAIN_BITS          0x80
#define PAD_BITS             0x01
#define S384_R192_BITS       0x80

#if   (STATE_INBITS==256)
#define C1    1
#define C2    8
#define C3    25
#elif (STATE_INBITS==384)
#define C1    1
#define C2    8
#define C3    55
#elif (STATE_INBITS==512)
#define C1    1
#define C2    16
#define C3    25
#else
#error "Not specified state size"
#endif

#ifdef CRYPTO_AEAD
/* For CRYPTO_AEAD */
#define KEY_INBITS           (CRYPTO_KEYBYTES * 8)
#define KEY_INBYTES          (CRYPTO_KEYBYTES)

#define NONCE_INBITS         (CRYPTO_NPUBBYTES * 8)
#define NONCE_INBYTES        (CRYPTO_NPUBBYTES)

#define TAG_INBITS           (CRYPTO_ABYTES * 8)
#define TAG_INBYTES          (CRYPTO_ABYTES)

#if   (KEY_INBITS==128) && (STATE_INBITS==256)
#define   RATE_INBITS           64
#define   NR_0                  52
#define   NR_i                  28
#define   NR_f                  32
#elif (KEY_INBITS==128) && (STATE_INBITS==384)
#define   RATE_INBITS           192
#define   NR_0                  76
#define   NR_i                  28
#define   NR_f                  32
#elif (KEY_INBITS==192) && (STATE_INBITS==384)
#define   RATE_INBITS           96
#define   NR_0                  76
#define   NR_i                  40
#define   NR_f                  44
#elif (KEY_INBITS==256) && (STATE_INBITS==512)
#define   RATE_INBITS           128
#define   NR_0                  100
#define   NR_i                  52
#define   NR_f                  56
#else
#error "Not specified key size and state size"
#endif

#define   RATE_INBYTES          ((RATE_INBITS + 7) / 8)
#define   SQUEEZE_RATE_INBYTES  TAG_INBYTES

#endif

#ifdef CRYPTO_HASH
/* For CRYPTO_HASH */
#define HASH_DIGEST_INBITS   (CRYPTO_BYTES * 8)

#if   (HASH_DIGEST_INBITS==256) && (STATE_INBITS==256)
#define   HASH_RATE_INBITS                32
#define   HASH_SQUEEZE_RATE_INBITS        128
#define   NR_h                            68
#elif (HASH_DIGEST_INBITS==256) && (STATE_INBITS==384)
#define   HASH_RATE_INBITS                128
#define   HASH_SQUEEZE_RATE_INBITS        128
#define   NR_h                            80
#elif (HASH_DIGEST_INBITS==384) && (STATE_INBITS==384)
#define   HASH_RATE_INBITS                48
#define   HASH_SQUEEZE_RATE_INBITS        192
#define   NR_h                            104
#elif (HASH_DIGEST_INBITS==512) && (STATE_INBITS==512)
#define   HASH_RATE_INBITS                64
#define   HASH_SQUEEZE_RATE_INBITS        256
#define   NR_h                            140
#else
#error "Not specified hash digest size and state size"
#endif

#define   HASH_RATE_INBYTES               ((HASH_RATE_INBITS + 7) / 8)
#define   HASH_SQUEEZE_RATE_INBYTES       ((HASH_SQUEEZE_RATE_INBITS + 7) / 8)

#endif

#define TAG_MATCH       0
#define TAG_UNMATCH    -1
#define OTHER_FAILURES -2

#endif