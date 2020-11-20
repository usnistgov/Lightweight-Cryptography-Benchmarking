;
; **********************************************
; * PHOTON-Beetle                              *
; * Authenticated Encryption and Hash Family   *
; *                                            *
; * Assembly implementation for 8-bit AVR CPU  *
; * Version 1.0 2020 by PHOTON-Beetle Team     *
; **********************************************
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Bitslice
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.MACRO Reorder_8_bits i0, i1, i2, i3, i4
    ror \i0
    ror \i1
    ror \i0
    ror \i2
    ror \i0
    ror \i3
    ror \i0
    ror \i4 
    ror \i0
    ror \i1
    ror \i0
    ror \i2
    ror \i0
    ror \i3
    ror \i0
    ror \i4 
.ENDM

.MACRO InvReorder_8_bits i0, i1, i2, i3, i4
    ror \i1
    ror \i0
    ror \i2
    ror \i0
    ror \i3
    ror \i0
    ror \i4 
    ror \i0
    ror \i1
    ror \i0
    ror \i2
    ror \i0
    ror \i3
    ror \i0
    ror \i4 
    ror \i0
.ENDM

; require XH:XL be the address of the input
Load_Reorder_32_bits:
    ldi cnt1, 4
reorder_8_bits_loop:
    ld rmp, X+
    Reorder_8_bits rmp, x0, x1, x2, x3
    dec cnt1
    brne reorder_8_bits_loop
ret

; require YH:YL be the address of the output
invReorder_Store_32_bits:
    ldi cnt1, 4
invreorder_8_bits_loop:
    InvReorder_8_bits rmp, x0, x1, x2, x3
    st Y+, rmp
    dec cnt1
    brne invreorder_8_bits_loop
ret

; require XH:XL be the address of the input
; require YH:YL be the address of the output
Load_Reorder_Store_128_bits:
    ldi cnt0, 4
reorder_32_bits_loop:
    rcall Load_Reorder_32_bits
    st Y+, x0
    st Y+, x1
    st Y+, x2
    st Y+, x3
    dec cnt0
    brne reorder_32_bits_loop
ret

; require XH:XL be the address of the input
; require YH:YL be the address of the output
Load_invReorder_Store_128_bits:
    ldi cnt0, 4
invreorder_32_bits_loop:
    ld x0, X+
    ld x1, X+
    ld x2, X+
    ld x3, X+
    rcall invReorder_Store_32_bits
    dec cnt0
    brne invreorder_32_bits_loop
ret

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
