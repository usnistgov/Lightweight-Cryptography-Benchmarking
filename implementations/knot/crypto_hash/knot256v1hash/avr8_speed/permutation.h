;
; **********************************************
; * KNOT: a family of bit-slice lightweight    *
; *       authenticated encryption algorithms  *
; *       and hash functions                   *
; *                                            *
; * Assembly implementation for 8-bit AVR CPU  *
; * Version 1.1 2020 by KNOT Team              *
; **********************************************
;

;
; ============================================
;   R E G I S T E R   D E F I N I T I O N S
; ============================================
;

#define mclen       r16
#define radlen      r17
#define tcnt        r17
#define tmp0        r20
#define tmp1        r21
#define cnt0        r22
#define rn          r23
#define rate        r24


; AEDH = 0b000: for authenticate AD
; AEDH = 0b001: for encryption
; AEDH = 0b011: for decryption
; AEDH = 0b100: for hash
#define AEDH r25
#define rcnt  r26

#if   (STATE_INBITS==256)
#include "knot256.h"
#elif (STATE_INBITS==384)
#include "knot384.h"
#elif (STATE_INBITS==512)
#include "knot512.h"
#else
#error "Not specified key size and state size"
#endif


