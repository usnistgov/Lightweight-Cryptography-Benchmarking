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
.DEF x30 = r0   ; Register used without overlapping
.DEF x31 = r1   ; Register used without overlapping
.DEF x32 = r2   ; Register used without overlapping
.DEF x33 = r3   ; Register used without overlapping
.DEF x34 = r4   ; Register used without overlapping
.DEF x35 = r5   ; Register used without overlapping
.DEF x36 = r6   ; Register used without overlapping
.DEF x37 = r7   ; Register used without overlapping
.DEF x38 = r8   ; Register used without overlapping
.DEF x39 = r9   ; Register used without overlapping
.DEF x3a = r10  ; Register used without overlapping
.DEF x3b = r11  ; Register used without overlapping
.DEF x3c = r12  ; Register used without overlapping
.DEF x3d = r13  ; Register used without overlapping
.DEF x3e = r14  ; Register used without overlapping
.DEF x3f = r15  ; Register used without overlapping

.DEF x0j = r16  ; Register used overlapped, should be backed up before using
.DEF x1j = r17  ; Register used overlapped, should be backed up before using
.DEF x2j = r18  ; Register used overlapped, should be backed up before using
.DEF x3j = r19  ; Register used overlapped, should be backed up before using

; t2j used in knot512 to keep one byte in Row2 (because of rotating 16-bit),
; will not be interupt with LFSR which uses the overlapped register tmp1
.DEF t2j = r21  ; Temporary register, used freely
.DEF t1j = r22  ; Temporary register, used freely
.DEF t3j = r23  ; Temporary register, used freely

.DEF rc   = r24 ; Register used overlapped, should be backed up before using
.DEF rcnt = r26 ; Register used overlapped, should be backed up before using
.DEF ccnt = r27 ; Register used overlapped, should be backed up before using

#if   (STATE_INBITS==256)
.include "./knot256.asm"
#elif (STATE_INBITS==384)
.include "./knot384.asm"
#elif (STATE_INBITS==512)
.include "./knot512.asm"
#else
#error "Not specified key size and state size"
#endif


