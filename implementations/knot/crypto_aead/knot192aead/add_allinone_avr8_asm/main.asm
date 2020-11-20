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
.NOLIST
.INCLUDE "m128def.inc" ; Header for 
.LIST

#define CRYPTO_AEAD
;#define CRYPTO_HASH

#define   MAX_MESSAGE_LENGTH    32

#define   STATE_INBITS          384
#define   STATE_INBYTES         ((STATE_INBITS + 7) / 8)

#define   ROW_INBITS            ((STATE_INBITS + 3) / 4)
#define   ROW_INBYTES           ((ROW_INBITS   + 7) / 8)

; For CRYPTO_AEAD
#define   CRYPTO_KEYBITS    192
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

; For CRYPTO_HASH
#define   CRYPTO_BITS             384
#define   CRYPTO_BYTES            ((CRYPTO_BITS + 7) / 8)

;
; ============================================
;   R E G I S T E R   D E F I N I T I O N S
; ============================================
;
.DEF mclen      = r16 ; Register used overlapped, should be backed up before using
.DEF adlen      = r17 ; Register used overlapped, should be backed up before using
.DEF mclen_org  = r18 ; Register used overlapped, should be backed up before using
.DEF adlen_org  = r19 ; Register used overlapped, should be backed up before using
.DEF tcnt       = r17 ; Register used overlapped with adlen

.DEF tmp0       = r20 ; Temporary register, used freely
.DEF tmp1       = r21 ; Temporary register, used freely
.DEF cnt0       = r22 ; Temporary register, used freely

.DEF rn         = r23 ; Register used overlapped, should be backed up before using
.DEF rate       = r24 ; Register used overlapped, should be backed up before using

; AEDH = 0b000: for authenticate AD
; AEDH = 0b001: for encryption
; AEDH = 0b011: for decryption
; AEDH = 0b100: for hash
.DEF AEDH       = r25 ; Register used globally within this program

;
; ============================================
;       S R A M   D E F I N I T I O N S
; ============================================
;
.DSEG

; For CRYPTO_AEAD
    SRAM_KEY:              .BYTE CRYPTO_KEYBYTES
    SRAM_NONCE:            .BYTE CRYPTO_NPUBBYTES
    SRAM_MESSAGE:          .BYTE MAX_MESSAGE_LENGTH
    SRAM_ASSOCIATED_DATA:  .BYTE MAX_ASSOCIATED_DATA_LENGTH
    SRAM_CIPHER:           .BYTE MAX_CIPHER_LENGTH
    SRAM_MESSAGE_TMP:      .BYTE MAX_CIPHER_LENGTH
    SRAM_STATE:            .BYTE STATE_INBYTES
    SRAM_MLEN:             .BYTE 1
    SRAM_CLEN:             .BYTE 1
    SRAM_TAG_MATCH:        .BYTE 1

; For CRYPTO_HASH
    SRAM_DIGEST:           .BYTE CRYPTO_BYTES
;
; ============================================
;   R E S E T   A N D   I N T   V E C T O R S
; ============================================
;
.CSEG
.ORG $0000
    ; global interrupt disable
	cli
    ; [Add all other init routines here]
    ldi tmp0, HIGH(RAMEND) ; set stack register
    out SPH,  tmp0
    ldi tmp0, LOW(RAMEND)
    out SPL,  tmp0

    ; initialize trigger B1
  	ldi		r16, 0b11	; portB,1 = output (triggers)
  	out		DDRB, r16

    rjmp Main ; Reset vector

#if defined(CRYPTO_AEAD)||defined(CRYPTO_HASH)
.include "./encrypt.asm"
#endif
;
;
; ============================================
;     M A I N    P R O G R A M    I N I T
; ============================================
;
Main:

;
; ============================================
;         P R O G R A M    L O O P
; ============================================
;
.MACRO INIT_INPUTS
    ldi ZH,   HIGH(@0 + @1)
    ldi ZL,   LOW(@0 + @1)
    ldi tmp0, @1
    dec tmp0
@2:
    st  -Z,   tmp0
    dec tmp0
    brge @2
.ENDMACRO

.MACRO INIT_OUTPUTS
    ldi ZH,   HIGH(@0)
    ldi ZL,   LOW(@0)
    ldi cnt0, @1
    clr tmp0
@2:
    st Z+, tmp0
    dec cnt0
    brne @2
.ENDMACRO

init:

    INIT_INPUTS SRAM_MESSAGE, MAX_MESSAGE_LENGTH, init_message

; For CRYPTO_AEAD
    INIT_INPUTS SRAM_KEY,             CRYPTO_KEYBYTES,            init_key
    INIT_INPUTS SRAM_NONCE,           CRYPTO_NPUBBYTES,           init_nonce
    INIT_INPUTS SRAM_ASSOCIATED_DATA, MAX_ASSOCIATED_DATA_LENGTH, init_associated_data
    INIT_OUTPUTS SRAM_CIPHER, MAX_CIPHER_LENGTH, init_cipher

    clr mclen_org
mclen_loop:
    clr adlen_org
adlen_loop:
    mov mclen, mclen_org
    mov adlen, adlen_org

#ifdef CRYPTO_AEAD
    rcall crypto_aead_encrypt
#endif
    inc adlen_org
    ldi tmp0, MAX_ASSOCIATED_DATA_LENGTH + 1
    cpse adlen_org, tmp0
    rjmp adlen_loop

    inc mclen_org
    ldi tmp0, MAX_MESSAGE_LENGTH + 1
    cpse mclen, tmp0
    rjmp mclen_loop


; For CRYPTO_HASH
    INIT_OUTPUTS SRAM_DIGEST, CRYPTO_BYTES, init_digest

    clr mclen
hash_mclen_loop:
    mov mclen_org, mclen

#ifdef CRYPTO_HASH
    rcall crypto_hash
#endif
    mov mclen, mclen_org
    inc mclen
    ldi tmp0, MAX_MESSAGE_LENGTH + 1
    cpse mclen, tmp0
    rjmp hash_mclen_loop


Loop:
    rjmp loop ; go back to loop
;
; End of source code
;
