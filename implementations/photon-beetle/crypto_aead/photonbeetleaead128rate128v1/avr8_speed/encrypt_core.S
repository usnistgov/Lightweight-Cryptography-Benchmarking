;
; **********************************************
; * PHOTON-Beetle                              *
; * Authenticated Encryption and Hash Family   *
; *                                            *
; * Assembly implementation for 8-bit AVR CPU  *
; * Version 1.0 2020 by PHOTON-Beetle Team     *
; **********************************************
;
#include "api.h"

#define CRYPTO_AEAD

#define STATE_INBITS          256
#define STATE_INBYTES         ((STATE_INBITS + 7) / 8)
#define RATE_INBITS           128
#define RATE_INBYTES          ((RATE_INBITS + 7) / 8)
#define RATE_INBYTES_MASK     (RATE_INBYTES - 1)
#define TAG_MATCH        0
#define TAG_UNMATCH     -1
#define OTHER_FAILURES  -2


; For CRYPTO_HASH
#define CRYPTO_BYTES            32
#define INITIAL_RATE_INBITS     128
#define INITIAL_RATE_INBYTES    ((INITIAL_RATE_INBITS + 7) / 8)
#define HASH_RATE_INBITS        32
#define HASH_RATE_INBYTES       ((HASH_RATE_INBITS + 7) / 8)
#define HASH_RATE_INBYTES_MASK  (HASH_RATE_INBYTES - 1)

;
; ============================================
;   R E G I S T E R   D E F I N I T I O N S
; ============================================
;
; [Add all register names here, include info on
;  all used registers without specific names]
; rmp: Multipurpose register
#define rmp     r16
#define rate    r17
#define mclen   r18
#define radlen   r19
#define adlen_org   r0

#define cnt0  r20
#define cnt1  r21
#define cnt2  r22

#define SQUEEZE_RATE_INBITS   128
#define SQUEEZE_RATE_INBYTES  ((SQUEEZE_RATE_INBITS + 7) / 8)
#define SQUEEZE_RATE_MASK     (SQUEEZE_RATE_INBYTES - 1)

#define CAPACITY_INBITS       (STATE_INBITS - RATE_INBITS)
#define CAPACITY_INBYTES      ((CAPACITY_INBITS + 7) / 8)

; For CRYPTO_AEAD
#define KEY_INBITS            (CRYPTO_KEYBYTES * 8)
#define KEY_INBYTES           (CRYPTO_KEYBYTES)

#define NONCE_INBITS          (CRYPTO_NPUBBYTES * 8)
#define NONCE_INBYTES         (CRYPTO_NPUBBYTES)

#define TAG_INBITS            (CRYPTO_ABYTES * 8)
#define TAG_INBYTES           (CRYPTO_ABYTES)

#define t0  r8
#define t1  r9
#define t2  r10
#define t3  r11

#define x0  r12
#define x1  r13
#define x2  r14
#define x3  r15

#define ed     r1

#define addr0  r2
#define addr1  r3
#define addr2  r4
#define addr3  r5
#define addr4  r6
#define addr5  r7

; domain_cnt overlap with cnt0, only temporarily used, no need to back up
#define domain_cnt  r20
#define domain_cnt0    r23
#define domain_cnt1    r24

.section .noinit
    SRAM_STATE:                 .BYTE 0, 0, 0, 0, 0, 0, 0, 0
                                .BYTE 0, 0, 0, 0, 0, 0, 0, 0
                                .BYTE 0, 0, 0, 0, 0, 0, 0, 0
                                .BYTE 0, 0, 0, 0, 0, 0, 0, 0
    SRAM_MESSAGE_OUT_ADDR:      .BYTE 0, 0
    SRAM_MESSAGE_IN_ADDR:       .BYTE 0, 0
    SRAM_MESSAGE_IN_LEN:        .BYTE 0, 0
#ifdef CRYPTO_AEAD
; For CRYPTO_AEAD
    SRAM_ASSOCIATED_DATA_ADDR:  .BYTE 0, 0
    SRAM_ADLEN:                 .BYTE 0, 0
    SRAM_NONCE_ADDR:            .BYTE 0, 0
    SRAM_KEY_ADDR:              .BYTE 0, 0
    SRAM_ADDITIONAL:            .BYTE 0, 0, 0, 0
                                .BYTE 0, 0, 0, 0
                                .BYTE 0, 0, 0, 0
                                .BYTE 0, 0, 0, 0
#endif

; SRAM required additionally, besides those used for API
    SRAM_PAD:                   .BYTE 0, 0, 0, 0
#if ((defined(CRYPTO_AEAD) && (RATE_INBYTES > 4)) || defined(CRYPTO_HASH))
                                .BYTE 0, 0, 0, 0
                                .BYTE 0, 0, 0, 0
                                .BYTE 0, 0, 0, 0
#endif

.section .text

#include "assist.h"
#include "photon.h"

AddDomainCounter:
    ldi YH,   hi8(SRAM_STATE + STATE_INBYTES - 3)
    ldi YL,   lo8(SRAM_STATE + STATE_INBYTES - 3)
    ldi rmp,  0x80
    ldi cnt1, 3
check_domain_bit:
    ror  domain_cnt
    brcc no_xor
    ld   x0,  Y
    eor  x0,  rmp
    st   Y,   x0
no_xor:
    adiw YL,   1
    dec  cnt1
    brne check_domain_bit
ret

; require XH:XL be the address of the current associated data/message block
XOR_to_State:
    ldi  YH,   hi8(SRAM_STATE)
    ldi  YL,   lo8(SRAM_STATE)
    mov  cnt0, rate
    dec  cnt0
XOR_to_State_loop:
    rcall Load_Reorder_32_bits
    ld   rmp,  Y
    eor  rmp,  x0
    st   Y+,   rmp
    ld   rmp,  Y
    eor  rmp,  x1
    st   Y+,   rmp
    ld   rmp,  Y
    eor  rmp,  x2
    st   Y+,   rmp
    ld   rmp,  Y
    eor  rmp,  x3
    st   Y+,   rmp
    subi  cnt0, 4
    brsh XOR_to_State_loop
; XH:XL are now the address of the next associated data/message block if this is not the last block
ret

; require XH:XL pointed to the source data to be padded
PAD_OneZero:
    ldi  YH,   hi8(SRAM_PAD)
    ldi  YL,   lo8(SRAM_PAD)
    mov  cnt1, rate
pad_copy:
    ld   rmp, X+
    st   Y+,  rmp
    dec  cnt1
    dec  cnt0
    brne pad_copy
pad_one:
    ldi  rmp, 1
    st   Y+,  rmp
    dec  cnt1
    breq pad_end
    clr  rmp
pad_zero:
    st   Y+, rmp
    dec  cnt1
    brne pad_zero
pad_end:
    ldi  XH,  hi8(SRAM_PAD)
    ldi  XL,  lo8(SRAM_PAD)
; XH:XL are now pointed to last block needed to be processed
ret

HASH:
    movw  addr0, XL
hash_block_loop:
    rcall PHOTON_Permutation
    movw  XL,    addr0
    cp    rate,  radlen
    brsh  hash_last_block
    rcall XOR_to_State
    movw  addr0, XL
    sub   radlen, rate
    rjmp  hash_block_loop

hash_last_block:
    cp    radlen, rate
    breq  hash_xor_domain
    mov   cnt0, radlen
    rcall PAD_OneZero

hash_xor_domain:
    clr   radlen
    rcall XOR_to_State
    mov   domain_cnt, domain_cnt0
    rcall AddDomainCounter
ret

TAG:
    rcall PHOTON_Permutation
    ldi   XH, hi8(SRAM_STATE)
    ldi   XL, lo8(SRAM_STATE)
    movw  YL, addr2
    rcall Load_invReorder_Store_128_bits
ret

#ifdef CRYPTO_AEAD
.IF (RATE_INBITS == 128)
XOR_to_Cipher:
    mov  t2, rate
    cp   t2, mclen
    brlo XOR_to_Cipher_Start
    mov  t2, mclen ; backup the real length of the remaining message

XOR_to_Cipher_Start:
    ldi  XH, hi8(SRAM_STATE)
    ldi  XL, lo8(SRAM_STATE)
    ldi  YH, hi8(SRAM_ADDITIONAL)
    ldi  YL, lo8(SRAM_ADDITIONAL)
    rcall Load_invReorder_Store_128_bits ; State move to additional SRAM and reorder

    movw XL, addr0
    movw ZL, addr2

    ; XOR Part 2
    sbiw YL, (RATE_INBYTES>>1) ; Pointed to Part 2
    ldi  cnt0, (RATE_INBYTES>>1)
    cp   cnt0, mclen
    brlo XOR_Part2_Store_Cipher_begin
    mov  cnt0, mclen
XOR_Part2_Store_Cipher_begin:
    sub  mclen, cnt0
XOR_Part2_Store_Cipher_loop:
    ld   t0, Y+
    ld   x0, X+
    eor  x0, t0
    st   Z+, x0
    dec  cnt0
    brne XOR_Part2_Store_Cipher_loop

    cpi  mclen, 1
    brlo XOR_to_Cipher_END

    ; XOR (Part 1 >>> 1)
    ldi  cnt0, (RATE_INBYTES>>1)
    cp   cnt0, mclen
    brlo XOR_Part1_Store_Cipher_begin
    mov  cnt0, mclen
XOR_Part1_Store_Cipher_begin:
    sub  mclen, cnt0
    ldi  YH, hi8(SRAM_ADDITIONAL)
    ldi  YL, lo8(SRAM_ADDITIONAL)
    ld   t0, Y
    bst  t0, 0
    adiw YL, (RATE_INBYTES>>1)-1
    ld   t0, Y
    ror  t0
    bld  t0, 7
    st   Y,  t0
    ldi  cnt1, (RATE_INBYTES>>1)-1
ROR_part1_loop:
    ld   t0, -Y
    ror  t0
    st   Y,  t0
    dec  cnt1
    brne ROR_part1_loop

XOR_Part1_Store_Cipher_loop:
    ld   t0, Y+
    ld   x0, X+
    eor  x0, t0
    st   Z+, x0
    dec  cnt0
    brne XOR_Part1_Store_Cipher_loop

XOR_to_Cipher_END:
    tst  ed
    brne XOR_to_Cipher_dec

XOR_to_Cipher_enc:
    movw  XL,   addr0
    cp    t2,   rate
    brsh  XOR_to_Cipher_XOR_to_State
    mov   cnt0, t2
    rcall PAD_OneZero
    rjmp  XOR_to_Cipher_XOR_to_State

XOR_to_Cipher_dec:
    movw  XL,   addr2
    cp    t2,   rate
    brsh  XOR_to_Cipher_XOR_to_State
    ; need to be padded
    mov   cnt0, t2
    rcall PAD_OneZero

XOR_to_Cipher_XOR_to_State:
    rcall XOR_to_State

    clr  rmp
    add  addr0, t2
    adc  addr1, rmp
    add  addr2, t2
    adc  addr3, rmp
ret
.ELSE
; RATE_INBITS == 32
XOR_to_Cipher:
    mov  t2, rate
    cp   t2, mclen
    brlo XOR_to_Cipher_Start
    mov  t2, mclen ; backup the real length of the remaining message

XOR_to_Cipher_Start:
    ldi XH, hi8(SRAM_STATE)
    ldi XL, lo8(SRAM_STATE)
    ld  x0, X+
    ld  x1, X+
    ld  x2, X+
    ld  x3, X+
    ldi YH, hi8(SRAM_ADDITIONAL)
    ldi YL, lo8(SRAM_ADDITIONAL)
    rcall invReorder_Store_32_bits

    movw XL, addr0
    movw ZL, addr2

    ; XOR Part 2
    sbiw YL, (RATE_INBYTES>>1) ; Pointed to Part 2
    ldi  cnt0, (RATE_INBYTES>>1)
    cp   cnt0, mclen
    brlo XOR_Part2_Store_Cipher_begin
    mov  cnt0, mclen
XOR_Part2_Store_Cipher_begin:
    sub  mclen, cnt0
XOR_Part2_Store_Cipher_loop:
    ld   t0, Y+
    ld   x0, X+
    eor  x0, t0
    st   Z+, x0
    dec  cnt0
    brne XOR_Part2_Store_Cipher_loop

    cpi  mclen, 1
    brlo XOR_to_Cipher_END

    ; XOR (Part 1 >>> 1)
    ldi  cnt0, (RATE_INBYTES>>1)
    cp   cnt0, mclen
    brlo XOR_Part1_Store_Cipher_begin
    mov  cnt0, mclen
XOR_Part1_Store_Cipher_begin:
    sub  mclen, cnt0
    ldi  YH, hi8(SRAM_ADDITIONAL)
    ldi  YL, lo8(SRAM_ADDITIONAL)
    ld   t0, Y+
    ld   t1, Y+
    bst  t0, 0
    ror  t1
    ror  t0
    bld  t1, 7

    ld   x0, X+
    eor  x0, t0
    st   Z+, x0
    dec  cnt0
    breq XOR_to_Cipher_END
    ld   x0, X+
    eor  x0, t1
    st   Z+, x0

XOR_to_Cipher_END:
    tst  ed
    brne XOR_to_Cipher_dec

XOR_to_Cipher_enc:
    movw  XL,   addr0
    cp    t2, rate
    brsh  XOR_to_Cipher_XOR_to_State
    mov   cnt0, t2
    rcall PAD_OneZero
    rjmp  XOR_to_Cipher_XOR_to_State

XOR_to_Cipher_dec:
    movw  XL,   addr2
    cp    t2,   rate
    brsh  XOR_to_Cipher_XOR_to_State
    ; need to be padded
    mov   cnt0, t2
    rcall PAD_OneZero

XOR_to_Cipher_XOR_to_State:
    rcall XOR_to_State

    clr  rmp
    add  addr0, t2
    adc  addr1, rmp
    add  addr2, t2
    adc  addr3, rmp
ret
.ENDIF

ENC:
    lds  ZH,    SRAM_MESSAGE_OUT_ADDR
    lds  ZL,    SRAM_MESSAGE_OUT_ADDR + 1
    lds  XH,    SRAM_MESSAGE_IN_ADDR
    lds  XL,    SRAM_MESSAGE_IN_ADDR + 1

    movw addr0, XL
    movw addr2, ZL

enc_block_loop:
    rcall PHOTON_Permutation
    rcall XOR_to_Cipher
    cpi   mclen, 1
    brsh  enc_block_loop

    mov   domain_cnt, domain_cnt1
    rcall AddDomainCounter
ret

AUTH_AND_ENCDEC:
    ldi YH, hi8(SRAM_STATE)
    ldi YL, lo8(SRAM_STATE)

    lds XH, SRAM_NONCE_ADDR
    lds XL, SRAM_NONCE_ADDR + 1
    rcall Load_Reorder_Store_128_bits
    lds XH, SRAM_KEY_ADDR
    lds XL, SRAM_KEY_ADDR + 1
    rcall Load_Reorder_Store_128_bits

    ldi domain_cnt0, 1
    ldi domain_cnt1, 1

test_adlen_zero:
    tst  radlen
    breq adlen_zero_test_mlen_zero

    ; radlen != 0
adlen_nzero_test_mlen_zero:
    tst   mclen
    brne  test_adlen_divisible
    ldi   domain_cnt0, 3
test_adlen_divisible:
    mov   rmp, radlen
    andi  rmp, RATE_INBYTES_MASK
    breq  hash_ad
    inc   domain_cnt0 ; 2 or 4
hash_ad:
    lds  XH, SRAM_ASSOCIATED_DATA_ADDR
    lds  XL, SRAM_ASSOCIATED_DATA_ADDR + 1
    rcall HASH
    tst   mclen
    breq  mlen_zero_inputout_address
    rjmp  test_mlen_divisible

adlen_zero_test_mlen_zero:
    ldi  domain_cnt1, 5
    tst  mclen
    breq adlen_zero_mlen_zero

    ; mclen != 0
test_mlen_divisible:
    mov  rmp, mclen
    andi rmp, RATE_INBYTES_MASK
    breq enc_dec_m
    inc  domain_cnt1 ; 2 or 6
enc_dec_m:
    rcall ENC
    rjmp AUTH_AND_ENCDEC_end

adlen_zero_mlen_zero:
    ; empty message and empty associated data
    ldi YH, hi8(SRAM_STATE + STATE_INBYTES - 3)
    ldi YL, lo8(SRAM_STATE + STATE_INBYTES - 3)
    ld  x0, Y
    ldi rmp, 0x80
    eor x0, rmp
    st  Y,  x0

mlen_zero_inputout_address:
    tst  ed
    brne dec_inputout_address
enc_inputout_address:
    lds  ZH,    SRAM_MESSAGE_OUT_ADDR
    lds  ZL,    SRAM_MESSAGE_OUT_ADDR + 1
    movw addr2, ZL
    rjmp AUTH_AND_ENCDEC_end
dec_inputout_address:
    lds  ZH,    SRAM_MESSAGE_IN_ADDR
    lds  ZL,    SRAM_MESSAGE_IN_ADDR + 1
    movw addr0, ZL

AUTH_AND_ENCDEC_end:
ret


; void crypto_aead_encrypt_asm(
;      unsigned char *c,         
;      const unsigned char *m,   
;      unsigned long long mlen,  
;      const unsigned char *ad,  
;      unsigned long long radlen, 
;      const unsigned char *npub,
;      const unsigned char *k    
;      )
;
; unsigned char *c,            is passed in r24:r25
; const unsigned char *m,      is passed in r22:r23
; unsigned long long mlen,     is passed in r20:r21, only LSB (r20) is used
; const unsigned char *ad,     is passed in r18:r19
; unsigned long long radlen,    is passed in r16:r17, only LSB (r16) is used
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
    mov  mclen, r20
    mov  radlen, r16

    ldi rate, RATE_INBYTES
    clr ed

    rcall AUTH_AND_ENCDEC
    rcall TAG

    POP_ALL
ret

; int  crypto_aead_decrypt_asm(
;      unsigned char *m,          
;      const unsigned char *c,    
;      unsigned long long clen,   
;      const unsigned char *ad,   
;      unsigned long long radlen,  
;      const unsigned char *npub, 
;      const unsigned char *k     
;      )
;
; unsigned char *m,            is passed in r24:r25
; const unsigned char *c,      is passed in r22:r23
; unsigned long long clen,     is passed in r20:r21, only LSB (r20) is used
; const unsigned char *ad,     is passed in r18:r19
; unsigned long long radlen,    is passed in r16:r17, only LSB (r16) is used
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
    mov  mclen, r20
    mov  radlen, r16

    ldi rate, RATE_INBYTES
    clr ed
    inc ed

    rcall AUTH_AND_ENCDEC

    ldi   YH,    hi8(SRAM_ADDITIONAL)
    ldi   YL,    lo8(SRAM_ADDITIONAL)
    movw  addr2, YL
    rcall TAG

    sbiw  YL, CRYPTO_ABYTES
    movw  XL, addr0

    ldi  cnt0, CRYPTO_ABYTES
compare_tag:
    ld   t0, Y+
    ld   x0, X+
    cp   t0, x0
    brne return_tag_not_match
    dec  cnt0
    brne compare_tag
    rjmp return_tag_match

return_tag_not_match:
    ldi  r25, 0xFF
    ldi  r24, 0xFF
    rjmp crypto_aead_decrypt_end
return_tag_match:
    clr	  r25
    clr	  r24

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

    ; empty half state
    ldi YH, hi8(SRAM_STATE + INITIAL_RATE_INBYTES)
    ldi YL, lo8(SRAM_STATE + INITIAL_RATE_INBYTES)
    clr rmp
    ldi cnt1, (STATE_INBYTES - INITIAL_RATE_INBYTES)
zero_state:
    st  Y+, rmp
    dec cnt1
    brne zero_state

    ldi domain_cnt0, 1
    sbiw YL, (STATE_INBYTES - INITIAL_RATE_INBYTES)
    lds XH, SRAM_MESSAGE_IN_ADDR
    lds XL, SRAM_MESSAGE_IN_ADDR + 1

    tst mclen
    breq add_domain

test_mlen_initrate:
    ; mclen != 0
    cpi mclen, INITIAL_RATE_INBYTES
    brlo less_than_initial_rate
    breq equal_to_initial_rate

more_than_initial_rate:
    rcall Load_Reorder_Store_128_bits
    ldi rate, HASH_RATE_INBYTES
    mov radlen, mclen
    subi radlen, INITIAL_RATE_INBYTES
    mov  rmp, radlen
    andi rmp, HASH_RATE_INBYTES_MASK
    breq hash_message
    inc  domain_cnt0
hash_message:
    rcall HASH
    rjmp gen_digest

equal_to_initial_rate:
    inc domain_cnt0
    rcall Load_Reorder_Store_128_bits
    rjmp add_domain
    
less_than_initial_rate:
    mov   cnt0, mclen
    ldi   rate, INITIAL_RATE_INBYTES
    rcall PAD_OneZero
    ldi YH, hi8(SRAM_STATE)
    ldi YL, lo8(SRAM_STATE)
    rcall Load_Reorder_Store_128_bits
    rjmp add_domain

add_domain:
    mov   domain_cnt, domain_cnt0
    rcall AddDomainCounter
gen_digest:
    lds XH, SRAM_MESSAGE_OUT_ADDR
    lds XL, SRAM_MESSAGE_OUT_ADDR + 1
    movw addr2, XL
    rcall TAG
    movw XL, addr2
    adiw XL, SQUEEZE_RATE_INBYTES
    movw addr2, XL
    rcall TAG

    POP_ALL
ret

#endif