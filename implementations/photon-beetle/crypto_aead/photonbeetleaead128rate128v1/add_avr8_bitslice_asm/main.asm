;
; ********************************************
; * [Add Project title here]                 *
; * [Add more info on software version here] *
; * (C)20xx by [Add Copyright Info here]     *
; ********************************************
;
; Included header file for target AVR type
.NOLIST
.INCLUDE "m128def.inc" ; Header for 
.LIST
;
; ============================================
;   H A R D W A R E   I N F O R M A T I O N   
; ============================================
;
; [Add all hardware information here]
;
; ============================================
;      P O R T S   A N D   P I N S 
; ============================================
;
; [Add names for hardware ports and pins here]
; Format: .EQU Controlportout = PORTA
;         .EQU Controlportin = PINA
;         .EQU LedOutputPin = PORTA2
;
; ============================================
;    C O N S T A N T S   T O   C H A N G E 
; ============================================
;
; [Add all constants here that can be subject
;  to change by the user]
; Format: .EQU const = $ABCD
;
; ============================================
;  F I X + D E R I V E D   C O N S T A N T S 
; ============================================
;
; [Add all constants here that are not subject
;  to change or calculated from constants]
; Format: .EQU const = $ABCD
#define CRYPTO_AEAD 1
;#define CRYPTO_HASH 1

.EQU    MAX_MESSAGE_LENGTH   = 32

.EQU    STATE_INBITS         = 256
.EQU    STATE_INBYTES        = ((STATE_INBITS + 7) / 8)
.EQU    RATE_INBITS          = 128
.EQU    RATE_INBYTES         = ((RATE_INBITS + 7) / 8)
.EQU    RATE_INBYTES_MASK    = (RATE_INBYTES - 1)

; For CRYPTO_AEAD
.EQU    CRYPTO_KEYBYTES  = 16
.EQU    CRYPTO_NSECBYTES = 0
.EQU    CRYPTO_NPUBBYTES = 16
.EQU    CRYPTO_ABYTES    = 16
.EQU    CRYPTO_NOOVERLAP = 1

.EQU    MAX_ASSOCIATED_DATA_LENGTH = 32
.EQU    MAX_CIPHER_LENGTH          = (MAX_MESSAGE_LENGTH + CRYPTO_ABYTES)

.EQU    TAG_MATCH      =  0
.EQU    TAG_UNMATCH    = -1
.EQU    OTHER_FAILURES = -2

; For CRYPTO_HASH
.EQU    CRYPTO_BYTES           = 32
.EQU    INITIAL_RATE_INBITS    = 128
.EQU    INITIAL_RATE_INBYTES   = ((INITIAL_RATE_INBITS + 7) / 8)
.EQU    HASH_RATE_INBITS       = 32
.EQU    HASH_RATE_INBYTES      = ((HASH_RATE_INBITS + 7) / 8)
.EQU    HASH_RATE_INBYTES_MASK = (HASH_RATE_INBYTES - 1)


;
; ============================================
;   R E G I S T E R   D E F I N I T I O N S
; ============================================
;
; [Add all register names here, include info on
;  all used registers without specific names]
.DEF rmp    = r16 ; Multipurpose register
.DEF rate   = r17
.DEF mclen  = r18
.DEF adlen  = r19
.DEF adlen_org  = r0

.def cnt0 = r20
.def cnt1 = r21
.def cnt2 = r22
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
    SRAM_STATE:            .BYTE STATE_INBYTES
    SRAM_MLEN:             .BYTE 1
    SRAM_ADLEN:            .BYTE 1
    SRAM_CLEN:             .BYTE 1
    SRAM_TAG_MATCH:        .BYTE 1

; For CRYPTO_HASH
    SRAM_DIGEST:           .BYTE CRYPTO_BYTES
    SRAM_MCLEN_TMP:        .BYTE 1

; SRAM required additionally, besides those used for API
    SRAM_PAD:              .BYTE RATE_INBYTES
    SRAM_ADDITIONAL:       .BYTE RATE_INBYTES

; Format: Label: .BYTE N ; reserve N Bytes from Label:
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
    ldi rmp,  HIGH(RAMEND) ; set stack register
    out SPH,  rmp
    ldi rmp,  LOW(RAMEND)
    out SPL,  rmp

    ; initialize trigger B1
    ldi r16, 0b11 ; portB,1 = output (triggers)
    out DDRB, r16

    rjmp Main ; Reset vector


#if defined(CRYPTO_AEAD)||defined(CRYPTO_HASH)
.include "./encrypt.asm"
#endif
;
;
; ============================================
;     I N T E R R U P T   S E R V I C E S
; ============================================
;
; [Add all interrupt service routines here]
;
; ============================================
;     M A I N    P R O G R A M    I N I T
; ============================================
;
Main:

.MACRO INIT_INPUTS
    ldi ZH, HIGH(@0 + @1)
    ldi ZL, LOW(@0 + @1)
    ldi rmp, @1
    dec rmp
@2:
    st  -Z, rmp
    dec rmp
    brge @2
.ENDMACRO

.MACRO INIT_OUTPUTS
    ldi ZH, HIGH(@0)
    ldi ZL, LOW(@0)
    ldi cnt0, @1
    eor rmp, rmp
@2:
    st Z+, rmp
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

;
; ============================================
;         P R O G R A M    L O O P
; ============================================
;

    clr mclen
mclen_loop:
    sts SRAM_MCLEN_TMP, mclen
    clr adlen_org
adlen_loop:

    mov adlen, adlen_org
#ifdef CRYPTO_AEAD
    rcall crypto_aead_encrypt
#endif
    lds mclen, SRAM_MCLEN_TMP

    inc adlen_org
    ldi rmp, MAX_ASSOCIATED_DATA_LENGTH + 1
    cpse adlen_org, rmp
    rjmp adlen_loop

    inc mclen
    ldi rmp, MAX_MESSAGE_LENGTH + 1
    cpse mclen, rmp
    rjmp mclen_loop

; For CRYPTO_HASH

    INIT_OUTPUTS SRAM_DIGEST, CRYPTO_BYTES, init_digest

;
; ============================================
;         P R O G R A M    L O O P
; ============================================
;
    clr mclen
hash_mclen_loop:
    sts SRAM_MCLEN_TMP, mclen
#ifdef CRYPTO_HASH
    rcall crypto_hash
#endif
    lds mclen, SRAM_MCLEN_TMP
    inc mclen
    ldi rmp, MAX_MESSAGE_LENGTH + 1
    cpse mclen, rmp
    rjmp hash_mclen_loop

Loop:
    rjmp loop ; go back to loop
;
; End of source code
;