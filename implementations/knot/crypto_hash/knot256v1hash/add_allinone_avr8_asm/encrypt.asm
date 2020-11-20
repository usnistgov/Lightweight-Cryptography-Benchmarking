;
; **********************************************
; * KNOT: a family of bit-slice lightweight    *
; *       authenticated encryption algorithms  *
; *       and hash functions                   *
; *                                            *
; * Assembly implementation for 8-bit AVR CPU  *
; * Version 1.0 2019 by KNOT Team              *
; **********************************************
;
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; For CRYPTO_AEAD
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

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; For CRYPTO_HASH
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


.include "./permutation.asm"

; require YH:YL be the address of the current associated data/cipher/message block
; for enc and dec, store ciphertext or plaintext
; require ZH:ZL be the address of the current cipher/message block
XOR_to_State:
    ldi  XH,   HIGH(SRAM_STATE)
    ldi  XL,   LOW(SRAM_STATE)
    mov  cnt0, rate
XOR_to_State_loop:
    ld   tmp0, Y+   ; plaintext/ciphertext
    ld   tmp1, X+   ; state
    eor  tmp1, tmp0 ; ciphertext/plaintext
    sbrc AEDH, 0    ; test auth or enc/dec, if AEDH[0] == 0, skip store result
    st   Z+,   tmp1 ; store ciphertext/plaintext
    sbrc AEDH, 1    ; test auth/enc or dec, if AEDH[1] == 0, skip repalce state byte
    mov  tmp1, tmp0 ; if dec, replace state
    st   X+,   tmp1 ; store state byte
    dec  cnt0
    brne XOR_to_State_loop
; YH:YL are now the address of the next associated data block 
ret

; require YH:YL pointed to the input data
; require ZH:ZL pointed to the output data
; require cnt0 containes the nubmer of bytes in source data
; require number of bytes in source data less than rate, i.e., 0 <= cnt0 < rate
;
; the 0th bit in AEDH is used to distinguish (auth AD) or (enc/dec M/C):
; AEDH[0] = 0 for (auth AD), AEDH[0] = 1 for (enc/dec M/C)
; the 1th bit in AEDH is used to distinguish (auth AD/enc M) or (dec C):
; AEDH[1] = 0 for (auth AD/enc M), AEDH[1] = 1 for (dec C)
; AEDH = 0b000 for (auth AD)
; AEDH = 0b001 for (enc M)
; AEDH = 0b011 for (dec C)
Pad_XOR_to_State:
    ldi  XH,   HIGH(SRAM_STATE)
    ldi  XL,   LOW(SRAM_STATE)
    tst  cnt0
    breq XOR_padded_data
XOR_source_data_loop:
    ld   tmp0,  Y+   ; plaintext/ciphertext
    ld   tmp1,  X    ; state
    eor  tmp1,  tmp0 ; ciphertext/plaintext
    sbrc AEDH,  0    ; test auth or enc/dec, if AEDH[0] == 0, skip store result
    st   Z+,    tmp1 ; store ciphertext/plaintext
    sbrc AEDH,  1    ; test auth/enc or dec, if AEDH[1] == 0, skip repalce state byte
    mov  tmp1,  tmp0 ; if dec, replace state
    st   X+,    tmp1 ; store state byte
    dec  cnt0
    brne XOR_source_data_loop
XOR_padded_data:
    ldi  tmp0,  PAD_BITS
    ld   tmp1,  X
    eor  tmp1,  tmp0
    st   X,     tmp1
ret

AddDomain:
    ldi  XH,   HIGH(SRAM_STATE + STATE_INBYTES - 1)
    ldi  XL,   LOW(SRAM_STATE + STATE_INBYTES - 1)
    ldi  tmp0,  DOMAIN_BITS
    ld   tmp1,  X
    eor  tmp0,  tmp1
    st   X,     tmp0
ret

; require ZH:ZL be the address of the destination
EXTRACT_from_State:
    ldi  XH,   HIGH(SRAM_STATE)
    ldi  XL,   LOW(SRAM_STATE)
    mov  tmp1, rate
EXTRACT_from_State_loop:
    ld   tmp0,   X+
    st   Z+,   tmp0
    dec  tmp1
    brne EXTRACT_from_State_loop
ret

AUTH:
    tst   adlen
    breq  AUTH_end
    cp    adlen, rate
    brlo  auth_ad_padded_block
auth_ad_loop:
    rcall XOR_to_State
    rcall Permutation
    sub   adlen, rate
    brsh  auth_ad_loop

auth_ad_padded_block:
    mov   cnt0, adlen
    rcall Pad_XOR_to_State
    rcall Permutation

AUTH_end:
ret

#ifdef CRYPTO_AEAD
Initialization:
    ldi  rn,   NR_0
    ldi  XH,   HIGH(SRAM_STATE)
    ldi  XL,   LOW(SRAM_STATE)

    ldi  YH,   HIGH(SRAM_NONCE)
    ldi  YL,   LOW(SRAM_NONCE)
    ldi  cnt0, CRYPTO_NPUBBYTES
load_nonce_loop:
    ld   tmp0, Y+
    st   X+,   tmp0
    dec  cnt0
    brne load_nonce_loop

    ldi  YH,   HIGH(SRAM_KEY)
    ldi  YL,   LOW(SRAM_KEY)
    ldi  cnt0, CRYPTO_KEYBYTES
load_key_loop:
    ld   tmp0, Y+
    st   X+, tmp0
    dec  cnt0
    brne load_key_loop

#if (STATE_INBITS==384) && (RATE_INBITS==192)
    ldi  cnt0, (STATE_INBYTES - CRYPTO_NPUBBYTES - CRYPTO_KEYBYTES - 1)
    clr  tmp0
empty_state_loop:
    st   X+, tmp0
    dec  cnt0
    brne empty_state_loop
    ldi  tmp0, S384_R192_BITS
    st   X+, tmp0
#endif

    rcall Permutation
ret

ENC:
    tst   mclen
    breq  ENC_end

    cp    mclen, rate
    brlo  enc_padded_block
enc_loop:
    rcall XOR_to_State
    ldi   rn, NR_i
    rcall Permutation
    sub   mclen, rate
    brsh  enc_loop

enc_padded_block:
    mov   cnt0, mclen
    rcall Pad_XOR_to_State
ENC_end:
ret

Finalization:
    ldi   rate, SQUEEZE_RATE_INBYTES
    ldi   rn, NR_f
    rcall Permutation
    rcall EXTRACT_from_State
ret

crypto_aead_encrypt:
    mov   tmp0,  mclen
    ldi   tmp1,  CRYPTO_ABYTES
    add   tmp0,  tmp1
    ldi   YH,    HIGH(SRAM_CLEN)
    ldi   YL,    LOW(SRAM_CLEN)
    st    Y,     tmp0

    rcall Initialization

    ldi   rn,   NR_i
    ldi   rate, RATE_INBYTES
    ldi   AEDH, 0b000 ; AEDH = 0b000 for (auth AD), AEDH = 0b001 for (enc M), AEDH = 0b011 for (dec C)
    ldi   YH,   HIGH(SRAM_ASSOCIATED_DATA)
    ldi   YL,   LOW(SRAM_ASSOCIATED_DATA)
    rcall AUTH
    rcall AddDomain
    ldi   AEDH, 0b001 ; AEDH = 0b000 for (auth AD), AEDH = 0b001 for (enc M), AEDH = 0b011 for (dec C)
    ldi   YH,   HIGH(SRAM_MESSAGE)
    ldi   YL,   LOW(SRAM_MESSAGE)
    ldi   ZH,   HIGH(SRAM_CIPHER)
    ldi   ZL,   LOW(SRAM_CIPHER)
    rcall ENC
    rcall Finalization
ret

crypto_aead_decrypt:
    mov   tmp0, mclen
    ldi   tmp1, CRYPTO_ABYTES
    add   tmp0, tmp1
    ldi   YH,   HIGH(SRAM_CLEN)
    ldi   YL,   LOW(SRAM_CLEN)
    st    Y,    tmp0

    rcall Initialization

    ldi   rn,   NR_i
    ldi   rate, RATE_INBYTES
    ldi   AEDH, 0b000 ; AEDH = 0b000 for (auth AD), AEDH = 0b001 for (enc M), AEDH = 0b011 for (dec C)
    ldi   YH,   HIGH(SRAM_ASSOCIATED_DATA)
    ldi   YL,   LOW(SRAM_ASSOCIATED_DATA)
    rcall AUTH
    rcall AddDomain
    ldi   AEDH, 0b011 ; AEDH = 0b000 for (auth AD), AEDH = 0b001 for (enc M), AEDH = 0b011 for (dec C)
    ldi   YH,   HIGH(SRAM_CIPHER)
    ldi   YL,   LOW(SRAM_CIPHER)
    ldi   ZH,   HIGH(SRAM_MESSAGE_TMP)
    ldi   ZL,   LOW(SRAM_MESSAGE_TMP)
    rcall ENC
    rcall Finalization

    sbiw ZH:ZL, CRYPTO_ABYTES
    ldi  cnt0,  CRYPTO_ABYTES
compare_tag:
    ld   tmp0,  Z+
    ld   tmp1,  Y+
    cp   tmp0,  tmp1
    brne return_tag_not_match
    dec  cnt0
    brne compare_tag
    rjmp return_tag_match

return_tag_not_match:
    ldi   ZH,    HIGH(SRAM_TAG_MATCH)
    ldi   ZL,    LOW(SRAM_TAG_MATCH)
    ldi   tmp0,  0xFF
    st    Z,     tmp0
    rjmp crypto_aead_decrypt_end

return_tag_match:
    ldi   YH,    HIGH(SRAM_MESSAGE_TMP)
    ldi   YL,    LOW(SRAM_MESSAGE_TMP)
    ldi   ZH,    HIGH(SRAM_MESSAGE)
    ldi   ZL,    LOW(SRAM_MESSAGE)
    mov   mclen, mclen_org
store_plaintext_loop:
    ld    tmp0,  X+
    st    Z+,    tmp0
    dec   mclen
    brne  store_plaintext_loop

    ldi   ZH,    HIGH(SRAM_TAG_MATCH)
    ldi   ZL,    LOW(SRAM_TAG_MATCH)
    clr   tmp0
    st    Z,  tmp0
crypto_aead_decrypt_end:
ret

; #ifdef CRYPTO_AEAD
#endif


#ifdef CRYPTO_HASH

crypto_hash:
    ldi XH,   HIGH(SRAM_STATE)
    ldi XL,   LOW(SRAM_STATE)
#if (STATE_INBITS==384) && (HASH_RATE_INBITS==192)
    ldi cnt0, STATE_INBYTES - 1
#else
    ldi cnt0, STATE_INBYTES
#endif
    clr tmp0
zero_state:
    st  X+, tmp0
    dec cnt0
    brne zero_state

#if (STATE_INBITS==384) && (HASH_RATE_INBITS==192)
    ldi tmp0, S384_R192_BITS
    st  X+, tmp0
#endif

    ldi   rn, NR_h
    ldi   AEDH, 0b100

HASH_ABSORBING:
    mov   adlen, mclen
    tst   adlen
    breq  EMPTY_M
    ldi   rate,  HASH_RATE_INBYTES
    ldi   YH,    HIGH(SRAM_MESSAGE)
    ldi   YL,    LOW(SRAM_MESSAGE)
    rcall AUTH
    rjmp  HASH_SQUEEZING

EMPTY_M:
    ldi  XH,   HIGH(SRAM_STATE)
    ldi  XL,   LOW(SRAM_STATE)
    ldi  tmp0,  PAD_BITS
    ld   tmp1,  X
    eor  tmp1,  tmp0
    st   X,     tmp1
    rcall Permutation

HASH_SQUEEZING:
    ldi   rate, HASH_SQUEEZE_RATE_INBYTES
    ldi   ZH,   HIGH(SRAM_DIGEST)
    ldi   ZL,   LOW(SRAM_DIGEST)
    ldi   tcnt, CRYPTO_BYTES
SQUEEZING_loop:
    rcall EXTRACT_from_State
    subi  tcnt, HASH_SQUEEZE_RATE_INBYTES
    breq  HASH_SQUEEZING_end
    rcall Permutation
    rjmp  SQUEEZING_loop
HASH_SQUEEZING_end:
ret

#endif


; Byte Order In AVR 8:
; KNOT-AEAD(128, 256, 64):
; N[ 0]        AEAD_State[ 0]  |  Message[ 0]             Perm_row_0[0]      0  Tag[ 0]
; N[ 1]        AEAD_State[ 1]  |  Message[ 1]             Perm_row_0[1]      0  Tag[ 1]
; N[ 2]        AEAD_State[ 2]  |  Message[ 2]             Perm_row_0[2]      0  Tag[ 2]
; N[ 3]        AEAD_State[ 3]  |  Message[ 3]             Perm_row_0[3]      0  Tag[ 3]
; N[ 4]        AEAD_State[ 4]  |  Message[ 4]  0x01       Perm_row_0[4]      0  Tag[ 4]
; N[ 5]        AEAD_State[ 5]  |  Message[ 5]  0x00       Perm_row_0[5]      0  Tag[ 5]
; N[ 6]        AEAD_State[ 6]  |  Message[ 6]  0x00       Perm_row_0[6]      0  Tag[ 6]
; N[ 7]        AEAD_State[ 7]  |  Message[ 7]  0x00       Perm_row_0[7] <<<  0  Tag[ 7]
; N[ 8]        AEAD_State[ 8]  |                          Perm_row_1[0]      1
; N[ 9]        AEAD_State[ 9]  |                          Perm_row_1[1]      1
; N[10]        AEAD_State[10]  |                          Perm_row_1[2]      1
; N[11]        AEAD_State[11]  |                          Perm_row_1[3]      1
; N[12]        AEAD_State[12]  |                          Perm_row_1[4]      1
; N[13]        AEAD_State[13]  |                          Perm_row_1[5]      1
; N[14]        AEAD_State[14]  |                          Perm_row_1[6]      1
; N[15]        AEAD_State[15]  |                          Perm_row_1[7] <<<  1
; K[ 0]        AEAD_State[16]  |                          Perm_row_2[0]      8
; K[ 1]        AEAD_State[17]  |                          Perm_row_2[1]      8
; K[ 2]        AEAD_State[18]  |                          Perm_row_2[2]      8
; K[ 3]        AEAD_State[19]  |                          Perm_row_2[3]      8
; K[ 4]        AEAD_State[20]  |                          Perm_row_2[4]      8
; K[ 5]        AEAD_State[21]  |                          Perm_row_2[5]      8
; K[ 6]        AEAD_State[22]  |                          Perm_row_2[6]      8
; K[ 7]        AEAD_State[23]  |                          Perm_row_2[7] <<<  8
; K[ 8]        AEAD_State[24]  |                          Perm_row_3[0]     25
; K[ 9]        AEAD_State[25]  |                          Perm_row_3[1]     25
; K[10]        AEAD_State[26]  |                          Perm_row_3[2]     25
; K[11]        AEAD_State[27]  |                          Perm_row_3[3]     25
; K[12]        AEAD_State[28]  |                          Perm_row_3[4]     25
; K[13]        AEAD_State[29]  |                          Perm_row_3[5]     25
; K[14]        AEAD_State[30]  |                          Perm_row_3[6]     25
; K[15]        AEAD_State[31]  |                    ^0x80 Perm_row_3[7] <<< 25
; 
; 
; KNOT-AEAD(128, 384, 192):
; Initalization
; N[ 0]        AEAD_State[ 0]  |  Message[ 0]             Perm_row_0[ 0]      0  Tag[ 0]
; N[ 1]        AEAD_State[ 1]  |  Message[ 1]             Perm_row_0[ 1]      0  Tag[ 1]
; N[ 2]        AEAD_State[ 2]  |  Message[ 2]             Perm_row_0[ 2]      0  Tag[ 2]
; N[ 3]        AEAD_State[ 3]  |  Message[ 3]             Perm_row_0[ 3]      0  Tag[ 3]
; N[ 4]        AEAD_State[ 4]  |  Message[ 4]   0x01      Perm_row_0[ 4]      0  Tag[ 4]
; N[ 5]        AEAD_State[ 5]  |  Message[ 5]   0x00      Perm_row_0[ 5]      0  Tag[ 5]
; N[ 6]        AEAD_State[ 6]  |  Message[ 6]   0x00      Perm_row_0[ 6]      0  Tag[ 6]
; N[ 7]        AEAD_State[ 7]  |  Message[ 7]   0x00      Perm_row_0[ 7]      0  Tag[ 7]
; N[ 8]        AEAD_State[ 8]  |  Message[ 8]   0x00      Perm_row_0[ 8]      0  Tag[ 8]
; N[ 9]        AEAD_State[ 9]  |  Message[ 9]   0x00      Perm_row_0[ 9]      0  Tag[ 9]
; N[10]        AEAD_State[10]  |  Message[10]   0x00      Perm_row_0[10]      0  Tag[10]
; N[11]        AEAD_State[11]  |  Message[11]   0x00      Perm_row_0[11] <<<  0  Tag[11]
; N[12]        AEAD_State[12]  |  Message[12]   0x00      Perm_row_1[ 0]      1  Tag[12]
; N[13]        AEAD_State[13]  |  Message[13]   0x00      Perm_row_1[ 1]      1  Tag[13]
; N[14]        AEAD_State[14]  |  Message[14]   0x00      Perm_row_1[ 2]      1  Tag[14]
; N[15]        AEAD_State[15]  |  Message[15]   0x00      Perm_row_1[ 3]      1  Tag[15]
; K[ 0]        AEAD_State[16]  |  Message[16]   0x00      Perm_row_1[ 4]      1
; K[ 1]        AEAD_State[17]  |  Message[17]   0x00      Perm_row_1[ 5]      1
; K[ 2]        AEAD_State[18]  |  Message[18]   0x00      Perm_row_1[ 6]      1
; K[ 3]        AEAD_State[19]  |  Message[19]   0x00      Perm_row_1[ 7]      1
; K[ 4]        AEAD_State[20]  |  Message[20]   0x00      Perm_row_1[ 8]      1
; K[ 5]        AEAD_State[21]  |  Message[21]   0x00      Perm_row_1[ 9]      1
; K[ 6]        AEAD_State[22]  |  Message[22]   0x00      Perm_row_1[10]      1
; K[ 7]        AEAD_State[23]  |  Message[23]   0x00      Perm_row_1[11] <<<  1
; K[ 8]        AEAD_State[24]  |                          Perm_row_2[ 0]      8
; K[ 9]        AEAD_State[25]  |                          Perm_row_2[ 1]      8
; K[10]        AEAD_State[26]  |                          Perm_row_2[ 2]      8
; K[11]        AEAD_State[27]  |                          Perm_row_2[ 3]      8
; K[12]        AEAD_State[28]  |                          Perm_row_2[ 4]      8
; K[13]        AEAD_State[29]  |                          Perm_row_2[ 5]      8
; K[14]        AEAD_State[30]  |                          Perm_row_2[ 6]      8
; K[15]        AEAD_State[31]  |                          Perm_row_2[ 7]      8
; 0x00         AEAD_State[32]  |                          Perm_row_2[ 8]      8
; 0x00         AEAD_State[33]  |                          Perm_row_2[ 9]      8
; 0x00         AEAD_State[34]  |                          Perm_row_2[10]      8
; 0x00         AEAD_State[35]  |                          Perm_row_2[11] <<<  8
; 0x00         AEAD_State[36]  |                          Perm_row_3[ 0]     55
; 0x00         AEAD_State[37]  |                          Perm_row_3[ 1]     55
; 0x00         AEAD_State[38]  |                          Perm_row_3[ 2]     55
; 0x00         AEAD_State[39]  |                          Perm_row_3[ 3]     55
; 0x00         AEAD_State[40]  |                          Perm_row_3[ 4]     55
; 0x00         AEAD_State[41]  |                          Perm_row_3[ 5]     55
; 0x00         AEAD_State[42]  |                          Perm_row_3[ 6]     55
; 0x00         AEAD_State[43]  |                          Perm_row_3[ 7]     55
; 0x00         AEAD_State[44]  |                          Perm_row_3[ 8]     55
; 0x00         AEAD_State[45]  |                          Perm_row_3[ 9]     55
; 0x00         AEAD_State[46]  |                          Perm_row_3[10]     55
; 0x00   ^0x80 AEAD_State[47]  |                    ^0x80 Perm_row_3[11] <<< 55
