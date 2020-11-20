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

; an intentionally arrangement of registers to facilitate movw
#define x20  r0
#define x21  r2
#define x22  r4
#define x23  r6
#define x24  r8
#define x25  r10
#define x26  r1
#define x27  r3
#define x28  r5
#define x29  r7
#define x2a  r9
#define x2b  r11

; an intentionally arrangement of registers to facilitate movw
#define x30 r22
#define x35 r20
#define x3a r18
#define x33 r16
#define x38 r14
#define x31 r12
#define x36 r23
#define x3b r21
#define x34 r19
#define x39 r17
#define x32 r15
#define x37 r13

#define t0j  r24
#define t1j  r25
#define x0j  r25
#define x1j  r27

#include "assist.h"

.macro Sbox i0, i1, i2, i3
    ldi  t0j,  0xFF
    eor  \i0,  t0j
    mov  t0j,  \i1
    and  \i1,   \i0
    eor  \i1,   \i2
    or   \i2,   t0j
    eor  \i0,   \i3
    eor  \i2,   \i0
    eor  t0j,   \i3
    and  \i0,   \i1
    eor  \i3,   \i1
    eor  \i0,   t0j
    and  t0j,  \i2
    eor  \i1,   t0j
.endm

.macro OneColumn i0, i1, i2, i3
    ld   \i0, Y
    ldd  \i1, Y + ROW_INBYTES
    Sbox \i0, \i1, \i2, \i3
    st   Y+, \i0
    rol  \i1                     ; ShiftRows -- Row 1 <<< 1
    std  Y + ROW_INBYTES -1, \i1
.endm

Permutation:
    PUSH_CONFLICT
    mov rcnt, rn

    ldi YH, hi8(SRAM_STATE + 2 * ROW_INBYTES)
    ldi YL, lo8(SRAM_STATE + 2 * ROW_INBYTES)
    ld  x20, Y+
    ld  x21, Y+
    ld  x22, Y+
    ld  x23, Y+
    ld  x24, Y+
    ld  x25, Y+
    ld  x26, Y+
    ld  x27, Y+
    ld  x28, Y+
    ld  x29, Y+
    ld  x2a, Y+
    ld  x2b, Y+
    ld  x30, Y+
    ld  x31, Y+
    ld  x32, Y+
    ld  x33, Y+
    ld  x34, Y+
    ld  x35, Y+
    ld  x36, Y+
    ld  x37, Y+
    ld  x38, Y+
    ld  x39, Y+
    ld  x3a, Y+
    ld  x3b, Y+

    ldi  ZL, lo8(RC_LFSR7)
    ldi  ZH, hi8(RC_LFSR7)

round_loop_start:
	; AddRC
	lpm  t0j,  Z+
    ldi  YH, hi8(SRAM_STATE)
    ldi  YL, lo8(SRAM_STATE)
    ld   x0j, Y
    eor  x0j, t0j

    ldd  x1j, Y + ROW_INBYTES
    Sbox x0j, x1j, x20, x30
    st   Y+, x0j
    lsl  x1j ; ShiftRows -- Row 1 <<< 1
    std  Y + ROW_INBYTES -1, x1j

    OneColumn x0j, x1j, x21, x31
    OneColumn x0j, x1j, x22, x32
    OneColumn x0j, x1j, x23, x33
    OneColumn x0j, x1j, x24, x34
    OneColumn x0j, x1j, x25, x35
    OneColumn x0j, x1j, x26, x36
    OneColumn x0j, x1j, x27, x37
    OneColumn x0j, x1j, x28, x38
    OneColumn x0j, x1j, x29, x39
    OneColumn x0j, x1j, x2a, x3a
    OneColumn x0j, x1j, x2b, x3b

    ld  x1j, Y
    eor t0j, t0j
    adc x1j, t0j
    st  Y,   x1j

    ;  b  a  9  8  7  6  5  4  3  2  1  0
    ; -- -- -- -- -- -- -- -- -- -- -- x- 0
    ; -- -- -- -- -- -- -- -- -- -- -- x' 0
    ; -- -- -- -- -- -- -- -- -- -- x- -- 1
    ; -- -- -- -- x' -- -- -- -- -- -- -- 7
    ;  4  3  2  1  0  b  a  9  8  7  6  5

    ; ShiftRows -- the last two rows
    ; <<< 8
	; b a 9 8 7 6 5 4 3 2 1 0 => a 9 8 7 6 5 4 3 2 1 0 b
    movw t0j, x25  ; t1j:t0j <= x2b:x25
    movw x25, x24  ; x2b:x25 <= x2a:x24
    movw x24, x23  ; x2a:x24 <= x29:x23
    movw x23, x22  ; x29:x23 <= x28:x22
    movw x22, x21  ; x28:x22 <= x27:x21
    movw x21, x20  ; x27:x21 <= x26:x20
    mov  x26, t0j  ; x26 <= x25
    mov  x20, t1j  ; x20 <= x2b

    ; >>> 1
    mov  t0j, x3b
    ror  t0j
    ror  x3a
    ror  x39
    ror  x38
    ror  x37
    ror  x36
    ror  x35
    ror  x34
    ror  x33
    ror  x32
    ror  x31
    ror  x30
    ror  x3b
    ; <<< 56
    ; b a 9 8 7 6 5 4 3 2 1 0 => 4 3 2 1 0 b a 9 8 7 6 5
    ; mov  x3j, x30
    ; mov  x30, x35
    ; mov  x35, x3a
    ; mov  x3a, x33
    ; mov  x33, x38
    ; mov  x38, x31
    ; mov  x31, x36
    ; mov  x36, x3b
    ; mov  x3b, x34
    ; mov  x34, x39
    ; mov  x39, x32
    ; mov  x32, x37
    ; mov  x37, x3j
    ; an intentionally arrangement of registers to facilitate movw
    ; x30 r22
    ; x35 r20
    ; x3a r18
    ; x33 r16
    ; x38 r14
    ; x31 r12
    ; x36 r23
    ; x3b r21
    ; x34 r19
    ; x39 r17
    ; x32 r15
    ; x37 r13
    movw t0j, x30 ; t1j:t0j <= x36:x30
    movw x30, x35 ; x36:x30 <= x3b:x35
    movw x35, x3a ; x3b:x35 <= x34:x3a
    movw x3a, x33 ; x34:x3a <= x39:x33
    movw x33, x38 ; x39:x33 <= x32:x38
    movw x38, x31 ; x32:x38 <= x37:x31
    mov  x31, t1j ; x31 <= x36
    mov  x37, t0j ; x37 <= x30

    dec rcnt
    breq round_loop_end
    jmp round_loop_start

round_loop_end:

    ldi YH, hi8(SRAM_STATE + 2 * ROW_INBYTES)
    ldi YL, lo8(SRAM_STATE + 2 * ROW_INBYTES)
    st   Y+, x20
    st   Y+, x21
    st   Y+, x22
    st   Y+, x23
    st   Y+, x24
    st   Y+, x25
    st   Y+, x26
    st   Y+, x27
    st   Y+, x28
    st   Y+, x29
    st   Y+, x2a
    st   Y+, x2b
    st   Y+, x30
    st   Y+, x31
    st   Y+, x32
    st   Y+, x33
    st   Y+, x34
    st   Y+, x35
    st   Y+, x36
    st   Y+, x37
    st   Y+, x38
    st   Y+, x39
    st   Y+, x3a
    st   Y+, x3b

    POP_CONFLICT
ret

RC_LFSR7:
.byte 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41, 0x03
.byte 0x06, 0x0c, 0x18, 0x30, 0x61, 0x42, 0x05, 0x0a
.byte 0x14, 0x28, 0x51, 0x23, 0x47, 0x0f, 0x1e, 0x3c
.byte 0x79, 0x72, 0x64, 0x48, 0x11, 0x22, 0x45, 0x0b
.byte 0x16, 0x2c, 0x59, 0x33, 0x67, 0x4e, 0x1d, 0x3a
.byte 0x75, 0x6a, 0x54, 0x29, 0x53, 0x27, 0x4f, 0x1f
.byte 0x3e, 0x7d, 0x7a, 0x74, 0x68, 0x50, 0x21, 0x43
.byte 0x07, 0x0e, 0x1c, 0x38, 0x71, 0x62, 0x44, 0x09
.byte 0x12, 0x24, 0x49, 0x13, 0x26, 0x4d, 0x1b, 0x36
.byte 0x6d, 0x5a, 0x35, 0x6b, 0x56, 0x2d, 0x5b, 0x37
.byte 0x6f, 0x5e, 0x3d, 0x7b, 0x76, 0x6c, 0x58, 0x31
.byte 0x63, 0x46, 0x0d, 0x1a, 0x34, 0x69, 0x52, 0x25
.byte 0x4b, 0x17, 0x2e, 0x5d, 0x3b, 0x77, 0x6e, 0x5c
.byte 0x39, 0x73, 0x66, 0x4c, 0x19, 0x32, 0x65, 0x4a
.byte 0x15, 0x2a, 0x55, 0x2b, 0x57, 0x2f, 0x5f, 0x3f
.byte 0x7f, 0x7e, 0x7c, 0x78, 0x70, 0x60, 0x40, 0x00