;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Bitslice
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
.MACRO Reorder_8_bits
    ror @0
    ror @1
    ror @0
    ror @2
    ror @0
    ror @3
    ror @0
    ror @4 
    ror @0
    ror @1
    ror @0
    ror @2
    ror @0
    ror @3
    ror @0
    ror @4 
.ENDMACRO

.MACRO InvReorder_8_bits
    ror @1
    ror @0
    ror @2
    ror @0
    ror @3
    ror @0
    ror @4 
    ror @0
    ror @1
    ror @0
    ror @2
    ror @0
    ror @3
    ror @0
    ror @4 
    ror @0
.ENDMACRO

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
