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

; 
; ; AEDH = 0b000: for authenticate AD
; ; AEDH = 0b001: for encryption
; ; AEDH = 0b011: for decryption
; ; AEDH = 0b100: for hash
; #define AEDH        r25 ; Register used globally within this program
; 
; #define x30  r0   ; Register used without overlapping
; #define x31  r1   ; Register used without overlapping
; #define x32  r2   ; Register used without overlapping
; #define x33  r3   ; Register used without overlapping
; #define x34  r4   ; Register used without overlapping
; #define x35  r5   ; Register used without overlapping
; #define x36  r6   ; Register used without overlapping
; #define x37  r7   ; Register used without overlapping
; #define x38  r8   ; Register used without overlapping
; #define x39  r9   ; Register used without overlapping
; #define x3a  r10  ; Register used without overlapping
; #define x3b  r11  ; Register used without overlapping
; #define x3c  r12  ; Register used without overlapping
; #define x3d  r13  ; Register used without overlapping
; #define x3e  r14  ; Register used without overlapping
; #define x3f  r15  ; Register used without overlapping
; 
; #define x0j  r16  ; Register used overlapped, should be backed up before using
; #define x1j  r17  ; Register used overlapped, should be backed up before using
; #define x2j  r18  ; Register used overlapped, should be backed up before using
; #define x3j  r19  ; Register used overlapped, should be backed up before using
; 
; ; t2j used in knot512 to keep one byte in Row2 (because of rotating 16-bit),
; ; will not be interupt with LFSR which uses the overlapped register tmp1
; #define t2j  r21  ; Temporary register, used freely
; #define t1j  r22  ; Temporary register, used freely
; #define t3j  r23  ; Temporary register, used freely
; 
; #define rc    r24 ; Register used overlapped, should be backed up before using
; #define rcnt  r26 ; Register used overlapped, should be backed up before using
; #define ccnt  r27 ; Register used overlapped, should be backed up before using

#define AEDH r25
#define x30  r0
#define x31  r1
#define x32  r2
#define x33  r3
#define x34  r4
#define x35  r5
#define x36  r6
#define x37  r7
#define x38  r8
#define x39  r9
#define x3a  r10
#define x3b  r11
#define x3c  r12
#define x3d  r13
#define x3e  r14
#define x3f  r15

#define x0j  r16
#define x1j  r17
#define x2j  r18
#define x3j  r19

; t2j used in knot512 to keep one byte in Row2 (because of rotating 16-bit),
; will not be interupt with LFSR which uses the overlapped register tmp1
#define t2j  r21
#define t1j  r22
#define t3j  r23

#define rc    r24
#define rcnt  r26
#define ccnt  r27

#if   (STATE_INBITS==256)
#include "knot256.h"
#elif (STATE_INBITS==384)
#include "knot384.h"
#elif (STATE_INBITS==512)
#include "knot512.h"
#else
#error "Not specified key size and state size"
#endif


