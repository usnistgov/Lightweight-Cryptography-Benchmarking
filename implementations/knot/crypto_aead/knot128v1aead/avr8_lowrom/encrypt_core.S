;
; **********************************************
; * KNOT: a family of bit-slice lightweight    *
; *       authenticated encryption algorithms  *
; *       and hash functions                   *
; *                                            *
; * Assembly implementation for 8-bit AVR CPU  *
; * Version 1.0 2020 by KNOT Team              *
; **********************************************
;

;
; ============================================
;       S R A M   D E F I N I T I O N S
; ============================================
;
#include <avr/io.h>
#include "config.h"

.section .noinit
    SRAM_STATE:                 .BYTE 0, 0, 0, 0, 0, 0, 0, 0
								.BYTE 0, 0, 0, 0, 0, 0, 0, 0
			                    .BYTE 0, 0, 0, 0, 0, 0, 0, 0
								.BYTE 0, 0, 0, 0, 0, 0, 0, 0
#if (STATE_INBYTES > 32)
			                    .BYTE 0, 0, 0, 0, 0, 0, 0, 0
								.BYTE 0, 0, 0, 0, 0, 0, 0, 0
#endif
#if (STATE_INBYTES > 48)
			                    .BYTE 0, 0, 0, 0, 0, 0, 0, 0
								.BYTE 0, 0, 0, 0, 0, 0, 0, 0
#endif
    SRAM_MESSAGE_OUT_ADDR:      .BYTE 0, 0
    SRAM_MESSAGE_IN_ADDR:       .BYTE 0, 0
    SRAM_MESSAGE_IN_LEN:        .BYTE 0, 0
#ifdef CRYPTO_AEAD
; For CRYPTO_AEAD
    SRAM_ASSOCIATED_DATA_ADDR:  .BYTE 0, 0
    SRAM_ADLEN:                 .BYTE 0, 0
    SRAM_NONCE_ADDR:            .BYTE 0, 0
    SRAM_KEY_ADDR:              .BYTE 0, 0

    SRAM_ADDITIONAL:
	                            .BYTE 0, 0, 0, 0, 0, 0, 0, 0
								.BYTE 0, 0, 0, 0, 0, 0, 0, 0
#if (CRYPTO_ABYTES > 16)
	                            .BYTE 0, 0, 0, 0, 0, 0, 0, 0
#endif
#if (CRYPTO_ABYTES > 24)
	                            .BYTE 0, 0, 0, 0, 0, 0, 0, 0
#endif

#endif

.section .text

#include "permutation.h"

; require YH:YL be the address of the current associated data/cipher/message block
; for enc and dec, store ciphertext or plaintext
; require ZH:ZL be the address of the current cipher/message block
XOR_to_State:
    ldi  XH,   hi8(SRAM_STATE)
    ldi  XL,   lo8(SRAM_STATE)
    mov  cnt0, rate
XOR_to_State_loop:
    ld   tmp0, Y+   ; plaintext/ciphertext
    ld   tmp1, X    ; state
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
    ldi  XH,   hi8(SRAM_STATE)
    ldi  XL,   lo8(SRAM_STATE)
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
    ldi  XH,   hi8(SRAM_STATE + STATE_INBYTES - 1)
    ldi  XL,   lo8(SRAM_STATE + STATE_INBYTES - 1)
    ldi  tmp0,  DOMAIN_BITS
    ld   tmp1,  X
    eor  tmp0,  tmp1
    st   X,     tmp0
ret

; require ZH:ZL be the address of the destination
EXTRACT_from_State:
    ldi  XH,   hi8(SRAM_STATE)
    ldi  XL,   lo8(SRAM_STATE)
    mov  tmp1, rate
EXTRACT_from_State_loop:
    ld   tmp0,   X+
    st   Z+,   tmp0
    dec  tmp1
    brne EXTRACT_from_State_loop
ret

AUTH:
    tst   radlen
    breq  AUTH_end

    cp    radlen, rate
    brlo  auth_ad_padded_block

auth_ad_loop:
    rcall XOR_to_State
    rcall Permutation
    sub   radlen, rate
	cp    radlen, rate
    brlo  auth_ad_padded_block
	rjmp  auth_ad_loop

auth_ad_padded_block:
    mov   cnt0, radlen
    rcall Pad_XOR_to_State
    rcall Permutation

AUTH_end:
ret

#ifdef CRYPTO_AEAD
Initialization:
    ldi  rn,   NR_0
    ldi  XL,   lo8(SRAM_STATE)
    ldi  XH,   hi8(SRAM_STATE)

    lds  YH,   SRAM_NONCE_ADDR
    lds  YL,   SRAM_NONCE_ADDR + 1
    ldi  cnt0, CRYPTO_NPUBBYTES
load_nonce_loop:
    ld   tmp0, Y+
    st   X+,   tmp0
    dec  cnt0
    brne load_nonce_loop

    lds  YH,   SRAM_KEY_ADDR
    lds  YL,   SRAM_KEY_ADDR + 1
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
    cp    mclen, rate
    brlo  enc_padded_block
    rjmp  enc_loop

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

; void crypto_aead_encrypt_asm(
;      unsigned char *c,         
;      const unsigned char *m,   
;      unsigned long long mlen,  
;      const unsigned char *ad,  
;      unsigned long long adlen, 
;      const unsigned char *npub,
;      const unsigned char *k    
;      )
;
; unsigned char *c,            is passed in r24:r25
; const unsigned char *m,      is passed in r22:r23
; unsigned long long mlen,     is passed in r20:r21, only LSB (r20) is used
; const unsigned char *ad,     is passed in r18:r19
; unsigned long long adlen,    is passed in r16:r17, only LSB (r16) is used
; const unsigned char *npub,   is passed in r14:r15
; const unsigned char *k       is passed in r12:r13
.global crypto_aead_encrypt_asm
crypto_aead_encrypt_asm:
    PUSH_ALL
    ldi  XH,   hi8(SRAM_MESSAGE_OUT_ADDR)
    ldi  XL,   lo8(SRAM_MESSAGE_OUT_ADDR)
    st   X+, r25  ;store cipher address in SRAM_MESSAGE_OUT_ADDR
    st   X+, r24
    st   X+, r23  ;store message address in SRAM_MESSAGE_IN_ADDR
    st   X+, r22
    st   X+, r21  ;store message length in SRAM_MESSAGE_IN_LEN
    st   X+, r20
    st   X+, r19  ;store associated data address in SRAM_ASSOCIATED_DATA_ADDR
    st   X+, r18
    st   X+, r17  ;store associated data length in SRAM_ADLEN
    st   X+, r16
    st   X+, r15  ;store nonce address in SRAM_NONCE_ADDR
    st   X+, r14
    st   X+, r13  ;store key address in SRAM_KEY_ADDR
    st   X+, r12
    mov  radlen, r16
    mov  mclen, r20

    rcall Initialization

    ldi   rn,   NR_i
    ldi   rate, RATE_INBYTES
    ldi   AEDH, 0b000 ; AEDH = 0b000 for (auth AD), AEDH = 0b001 for (enc M), AEDH = 0b011 for (dec C)
    lds   YH,   SRAM_ASSOCIATED_DATA_ADDR
    lds   YL,   SRAM_ASSOCIATED_DATA_ADDR + 1
    rcall AUTH
    rcall AddDomain
    ldi   AEDH, 0b001 ; AEDH = 0b000 for (auth AD), AEDH = 0b001 for (enc M), AEDH = 0b011 for (dec C)
    lds   YH,   SRAM_MESSAGE_IN_ADDR
    lds   YL,   SRAM_MESSAGE_IN_ADDR + 1
    lds   ZH,   SRAM_MESSAGE_OUT_ADDR
    lds   ZL,   SRAM_MESSAGE_OUT_ADDR + 1
    rcall ENC
    rcall Finalization
    POP_ALL
ret

; int  crypto_aead_decrypt_asm(
;      unsigned char *m,          
;      const unsigned char *c,    
;      unsigned long long clen,   
;      const unsigned char *ad,   
;      unsigned long long adlen,  
;      const unsigned char *npub, 
;      const unsigned char *k     
;      )
;
; unsigned char *m,            is passed in r24:r25
; const unsigned char *c,      is passed in r22:r23
; unsigned long long clen,     is passed in r20:r21, only LSB (r20) is used
; const unsigned char *ad,     is passed in r18:r19
; unsigned long long adlen,    is passed in r16:r17, only LSB (r16) is used
; const unsigned char *npub,   is passed in r14:r15
; const unsigned char *k       is passed in r12:r13
.global crypto_aead_decrypt_asm
crypto_aead_decrypt_asm:
    PUSH_ALL
    ldi  XH,   hi8(SRAM_MESSAGE_OUT_ADDR)
    ldi  XL,   lo8(SRAM_MESSAGE_OUT_ADDR)
    st   X+, r25  ;store message address in SRAM_MESSAGE_OUT_ADDR
    st   X+, r24
    st   X+, r23  ;store cipher address in SRAM_MESSAGE_IN_ADDR
    st   X+, r22
    st   X+, r21  ;store cipher length in SRAM_MESSAGE_IN_LEN
    st   X+, r20
    st   X+, r19  ;store associated data address in SRAM_ASSOCIATED_DATA_ADDR
    st   X+, r18
    st   X+, r17  ;store associated data length in SRAM_ADLEN
    st   X+, r16
    st   X+, r15  ;store nonce address in SRAM_NONCE_ADDR
    st   X+, r14
    st   X+, r13  ;store key address in SRAM_KEY_ADDR
    st   X+, r12
    mov  radlen, r16
    mov  mclen, r20

    rcall Initialization

    ldi   rn,   NR_i
    ldi   rate, RATE_INBYTES
    ldi   AEDH, 0b000 ; AEDH = 0b000 for (auth AD), AEDH = 0b001 for (enc M), AEDH = 0b011 for (dec C)
    lds   YH,   SRAM_ASSOCIATED_DATA_ADDR
    lds   YL,   SRAM_ASSOCIATED_DATA_ADDR + 1
    rcall AUTH
    rcall AddDomain
    ldi   AEDH, 0b011 ; AEDH = 0b000 for (auth AD), AEDH = 0b001 for (enc M), AEDH = 0b011 for (dec C)
    lds   YH,   SRAM_MESSAGE_IN_ADDR
    lds   YL,   SRAM_MESSAGE_IN_ADDR + 1
    lds   ZH,   SRAM_MESSAGE_OUT_ADDR
    lds   ZL,   SRAM_MESSAGE_OUT_ADDR + 1
    rcall ENC

    ldi  ZH,   hi8(SRAM_ADDITIONAL)
    ldi  ZL,   lo8(SRAM_ADDITIONAL)
    rcall Finalization

    sbiw ZL, CRYPTO_ABYTES
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
    ldi   r25,  0xFF
	ldi   r24,  0xFF
    rjmp crypto_aead_decrypt_end

return_tag_match:
    clr   r25
	clr   r24
crypto_aead_decrypt_end:
    POP_ALL
ret

; #ifdef CRYPTO_AEAD
#endif


#ifdef CRYPTO_HASH

; void crypto_hash_asm(
;    unsigned char *out,
;    const unsigned char *in,
;    unsigned long long inlen
;    )
;
; unsigned char *out,           is passed in r24:r25
; const unsigned char *in,      is passed in r22:r23
; unsigned long long inlen,     is passed in r20:r21, only LSB (r20) is used
.global crypto_hash_asm
crypto_hash_asm:
    PUSH_ALL
    ldi  XH,   hi8(SRAM_MESSAGE_OUT_ADDR)
    ldi  XL,   lo8(SRAM_MESSAGE_OUT_ADDR)
    st   X+, r25  ;store message address in SRAM_MESSAGE_OUT_ADDR
    st   X+, r24
    st   X+, r23  ;store cipher address in SRAM_MESSAGE_IN_ADDR
    st   X+, r22
    st   X+, r21  ;store cipher length in SRAM_MESSAGE_IN_LEN
    st   X+, r20
    mov  mclen, r20

    ldi XH,   hi8(SRAM_STATE)
    ldi XL,   lo8(SRAM_STATE)
#if (STATE_INBITS==384) && (HASH_RATE_INBITS==128)
    ldi cnt0, STATE_INBYTES - 1
#else
    ldi cnt0, STATE_INBYTES
#endif
    clr tmp0
zero_state:
    st  X+, tmp0
    dec cnt0
    brne zero_state

#if (STATE_INBITS==384) && (HASH_RATE_INBITS==128)
    ldi tmp0, S384_R192_BITS
    st  X+, tmp0
#endif

    ldi   rn, NR_h
    ldi   AEDH, 0b100

HASH_ABSORBING:
    mov   radlen, mclen
    tst   radlen
    breq  EMPTY_M
    ldi   rate,  HASH_RATE_INBYTES
    lds   YH,   SRAM_MESSAGE_IN_ADDR
    lds   YL,   SRAM_MESSAGE_IN_ADDR + 1
    rcall AUTH
    rjmp  HASH_SQUEEZING

EMPTY_M:
    ldi  XH,   hi8(SRAM_STATE)
    ldi  XL,   lo8(SRAM_STATE)
    ldi  tmp0,  PAD_BITS
    ld   tmp1,  X
    eor  tmp1,  tmp0
    st   X,     tmp1
    rcall Permutation

HASH_SQUEEZING:
    ldi   rate, HASH_SQUEEZE_RATE_INBYTES
    lds   ZH,   SRAM_MESSAGE_OUT_ADDR
    lds   ZL,   SRAM_MESSAGE_OUT_ADDR + 1
    ldi   tcnt, CRYPTO_BYTES
SQUEEZING_loop:
    rcall EXTRACT_from_State
    subi  tcnt, HASH_SQUEEZE_RATE_INBYTES
    breq  HASH_SQUEEZING_end
    rcall Permutation
    rjmp  SQUEEZING_loop
HASH_SQUEEZING_end:
    POP_ALL
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
