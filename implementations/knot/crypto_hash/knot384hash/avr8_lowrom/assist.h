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
.macro LFSR6_MACRO
    bst  rc,   5
    bld  tmp0, 0
    bst  rc,   4
    bld  tmp1, 0
    eor  tmp0, tmp1
    ror  tmp0
    rol  rc
    andi rc,   0x3F
.endm

.macro LFSR7_MACRO
    bst  rc,   6
    bld  tmp0, 0
    bst  rc,   5
    bld  tmp1, 0
    eor  tmp0, tmp1
    ror  tmp0
    rol  rc
    andi rc,   0x7F
.endm

.macro LFSR8_MACRO
    bst  rc,   7
    bld  tmp0, 0
    bst  rc,   5
    bld  tmp1, 0
    eor  tmp0, tmp1
    bst  rc,   4
    bld  tmp1, 0
    eor  tmp0, tmp1
    bst  rc,   3
    bld  tmp1, 0
    eor  tmp0, tmp1
    ror  tmp0
    rol  rc
.endm

.macro Sbox i0, i1, i2, i3
    mov tmp0,  \i1
    com \i0
    and \i1,   \i0
    eor \i1,   \i2
    or  \i2,   tmp0
    eor \i0,   \i3
    eor \i2,   \i0
    eor tmp0,  \i3
    and \i0,   \i1
    eor \i3,   \i1
    eor \i0,   tmp0
    and tmp0,  \i2
    eor \i1,   tmp0
.endm

.macro PUSH_CONFLICT
    push r16
    push r17
    push r18
    push r19

    push r23
    push r24

    push r26
    push r27
    push r28
    push r29
    push r30
    push r31
.endm

.macro POP_CONFLICT
    pop r31
    pop r30
    pop r29
    pop r28
    pop r27
    pop r26

    pop r24
    pop r23

    pop r19
    pop r18
    pop r17
    pop r16
.endm

.macro PUSH_ALL
    push    r2
    push    r3
    push    r4
    push    r5
    push    r6
    push    r7
    push    r8
    push    r9
    push    r10
    push    r11
    push    r12
    push    r13
    push    r14
    push    r15
    push    r16
    push    r17
    push    r28
    push    r29
.endm

.macro POP_ALL
    pop    r29
    pop    r28
    pop    r17
    pop    r16
    pop    r15
    pop    r14
    pop    r13
    pop    r12
    pop    r11
    pop    r10
    pop    r9
    pop    r8
    pop    r7
    pop    r6
    pop    r5
    pop    r4
    pop    r3
    pop    r2
    clr    r1
.endm