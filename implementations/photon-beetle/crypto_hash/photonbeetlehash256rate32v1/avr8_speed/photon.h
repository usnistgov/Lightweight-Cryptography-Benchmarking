;
; **********************************************
; * PHOTON-Beetle                              *
; * Authenticated Encryption and Hash Family   *
; *                                            *
; * Assembly implementation for 8-bit AVR CPU  *
; * Version 1.1 2020 by PHOTON-Beetle Team     *
; **********************************************
;
#define ROUND_N  12
#define DIM      8

.MACRO Store_OneRow
    st X+, x0
    st X+, x1
    st X+, x2
    st X+, x3
.ENDM

.MACRO ROTL_1 i0
    bst  \i0, 7
    lsl  \i0
    bld  \i0, 0
.ENDM

.MACRO ROTR_1 i0
    bst  \i0, 0
    lsr  \i0
    bld  \i0, 7
.ENDM

.MACRO ROTR_4 i0
    swap \i0
.ENDM

.MACRO ROTR_1_ROW
    ROTR_1 x0
    ROTR_1 x1
    ROTR_1 x2
    ROTR_1 x3
.ENDM

.MACRO ROTL_1_ROW
    ROTL_1 x0
    ROTL_1 x1
    ROTL_1 x2
    ROTL_1 x3
.ENDM

.MACRO ROTR_4_ROW
    ROTR_4 x0
    ROTR_4 x1
    ROTR_4 x2
    ROTR_4 x3
.ENDM


; For all mul2_GF16_0x13_xor:
; Input
; MSB........LSB
; x0=@0: x1=@1: x2=@2: x3=@3
    ; # define mul2_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x3 = XOR (x3 ,x0); \
    ; } while (0) ; /* Output : ( MSB ) x1 ,x2 ,x3 , x0 ( LSB ) */
.MACRO mul2_GF16_0x13_xor
    ld  t3, X+
    ld  t2, X+
    ld  t1, X+
    ld  t0, X+
    eor t3, t0
    eor x0, t0
    eor x1, t3
    eor x2, t2
    eor x3, t1
.ENDM

    ; # define mul4_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x3 = XOR (x3 ,x0); x0 = XOR (x0 ,x1); \
    ; } while (0) ; /* Output : ( MSB ) x2 ,x3 ,x0 , x1 ( LSB ) */
.MACRO mul4_GF16_0x13_xor
    ld  t3, X+
    ld  t2, X+
    ld  t1, X+
    ld  t0, X+
    eor t3, t0
    eor t0, t1
    eor x0, t1
    eor x1, t0
    eor x2, t3
    eor x3, t2
.ENDM

    ; # define mul5_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x2 = XOR (x2 ,x0); x3 = XOR (x3 ,x1); \
    ;   x1 = XOR (x1 ,x2); x0 = XOR (x0 ,x3); \
    ; } while (0) ; /* Output : ( MSB ) x2 ,x0 ,x1 , x3 ( LSB ) */
.MACRO mul5_GF16_0x13_xor
    ld  t3, X+
    ld  t2, X+
    ld  t1, X+
    ld  t0, X+
    eor t2, t0
    eor t3, t1
    eor t1, t2
    eor t0, t3
    eor x0, t3
    eor x1, t1
    eor x2, t0
    eor x3, t2
.ENDM

    ; # define mul6_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x3 = XOR (x3 ,x1); x1 = XOR (x1 ,x0); \
    ;   x2 = XOR (x2 ,x1); x0 = XOR (x0 ,x2); \
    ;   x2 = XOR (x2 ,x3); \
    ; } while (0) ; /* Output : ( MSB ) x0 ,x2 ,x3 , x1 ( LSB ) */
.MACRO mul6_GF16_0x13_xor
    ld  t3, X+
    ld  t2, X+
    ld  t1, X+
    ld  t0, X+
    eor t3, t1
    eor t1, t0
    eor t2, t1
    eor t0, t2
    eor t2, t3
    eor x0, t1
    eor x1, t3
    eor x2, t2
    eor x3, t0
.ENDM

    ; # define mul8_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x3 = XOR (x3 ,x0); x0 = XOR (x0 ,x1); \
    ;   x1 = XOR (x1 ,x2); \
    ; } while (0) ; /* Output : ( MSB ) x3 ,x0 ,x1 , x2 ( LSB ) */
.MACRO mul8_GF16_0x13_xor
    ld  t3, X+
    ld  t2, X+
    ld  t1, X+
    ld  t0, X+
    eor t3, t0
    eor t0, t1
    eor t1, t2
    eor x0, t2
    eor x1, t1
    eor x2, t0
    eor x3, t3
.ENDM

    ; # define mul11_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x2 = XOR (x2 ,x0); x1 = XOR (x1 ,x3); \
    ;   x0 = XOR (x0 ,x1); x3 = XOR (x3 ,x2); \
    ; } while (0) ; /* Output : ( MSB ) x1 ,x2 ,x0 , x3 ( LSB ) */
.MACRO mulb_GF16_0x13_xor
    ld  t3, X+
    ld  t2, X+
    ld  t1, X+
    ld  t0, X+
    eor t2, t0
    eor t1, t3
    eor t0, t1
    eor t3, t2
    eor x0, t3
    eor x1, t0
    eor x2, t2
    eor x3, t1
.ENDM


.MACRO RoundFunction
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; Start AddRC_Sbox_ShiftRow
AddRC_Sbox_ShiftRow_Start:
    clr t3
    inc t3

    ldi XL, lo8(SRAM_STATE)
    ldi XH, hi8(SRAM_STATE)

    lpm t0, Z+ ; Load two nibbles of round constant for row 0, 1
    ; AddRC_TwoRows
    ld x0, X+
    ld x1, X+
    ld x2, X+
    ld x3, X+
    sbiw XL, 4

    ror  t0
    brcc row0_next1
    eor  x0, t3
row0_next1:
    ror  t0
    brcc row0_next2
    eor  x1, t3
row0_next2:
    ror  t0
    brcc row0_next3
    eor  x2, t3
row0_next3:
    ror  t0
    brcc row0_next4
    eor  x3, t3
row0_next4:
    ; Sbox_TwoRows
    eor  x1, x2
    mov  t1, x2
    and  t1, x1
    eor  x3, t1
    mov  t1, x3
    and  x3, x1
    eor  x3, x2
    mov  t2, x3
    eor  x3, x0
    com  x3
    mov  x2, x3
    or   t2, x0
    eor  x0, t1
    eor  x1, x0
    or   x2, x1
    eor  x2, t1
    eor  x1, t2
    eor  x3, x1
    Store_OneRow

    ; AddRC_TwoRows
    ld x0, X+
    ld x1, X+
    ld x2, X+
    ld x3, X+
    sbiw XL, 4

    ror  t0
    brcc row1_next1
    eor  x0, t3
row1_next1:
    ror  t0
    brcc row1_next2
    eor  x1, t3
row1_next2:
    ror  t0
    brcc row1_next3
    eor  x2, t3
row1_next3:
    ror  t0
    brcc row1_next4
    eor  x3, t3
row1_next4:
    ; Sbox_TwoRows
    eor  x1, x2
    mov  t1, x2
    and  t1, x1
    eor  x3, t1
    mov  t1, x3
    and  x3, x1
    eor  x3, x2
    mov  t2, x3
    eor  x3, x0
    com  x3
    mov  x2, x3
    or   t2, x0
    eor  x0, t1
    eor  x1, x0
    or   x2, x1
    eor  x2, t1
    eor  x1, t2
    eor  x3, x1

    ROTR_1_ROW
    Store_OneRow

    lpm t0, Z+ ; Load two nibbles of round constant for row 2i, 2i+1
    ; AddRC_TwoRows
    ld x0, X+
    ld x1, X+
    ld x2, X+
    ld x3, X+
    sbiw XL, 4

    ror  t0
    brcc row2_next1
    eor  x0, t3
row2_next1:
    ror  t0
    brcc row2_next2
    eor  x1, t3
row2_next2:
    ror  t0
    brcc row2_next3
    eor  x2, t3
row2_next3:
    ror  t0
    brcc row2_next4
    eor  x3, t3
row2_next4:
    ; Sbox_TwoRows
    eor  x1, x2
    mov  t1, x2
    and  t1, x1
    eor  x3, t1
    mov  t1, x3
    and  x3, x1
    eor  x3, x2
    mov  t2, x3
    eor  x3, x0
    com  x3
    mov  x2, x3
    or   t2, x0
    eor  x0, t1
    eor  x1, x0
    or   x2, x1
    eor  x2, t1
    eor  x1, t2
    eor  x3, x1

    ROTR_1_ROW
    ROTR_1_ROW
    Store_OneRow

    ; AddRC_TwoRows
    ld x0, X+
    ld x1, X+
    ld x2, X+
    ld x3, X+
    sbiw XL, 4

    ror  t0
    brcc row3_next1
    eor  x0, t3
row3_next1:
    ror  t0
    brcc row3_next2
    eor  x1, t3
row3_next2:
    ror  t0
    brcc row3_next3
    eor  x2, t3
row3_next3:
    ror  t0
    brcc row3_next4
    eor  x3, t3
row3_next4:
    ; Sbox_TwoRows
    eor  x1, x2
    mov  t1, x2
    and  t1, x1
    eor  x3, t1
    mov  t1, x3
    and  x3, x1
    eor  x3, x2
    mov  t2, x3
    eor  x3, x0
    com  x3
    mov  x2, x3
    or   t2, x0
    eor  x0, t1
    eor  x1, x0
    or   x2, x1
    eor  x2, t1
    eor  x1, t2
    eor  x3, x1

    ROTR_4_ROW
    ROTL_1_ROW
    Store_OneRow

    lpm t0, Z+ ; Load two nibbles of round constant for row 2i, 2i+1
    ; AddRC_TwoRows
    ld x0, X+
    ld x1, X+
    ld x2, X+
    ld x3, X+
    sbiw XL, 4

    ror  t0
    brcc row4_next1
    eor  x0, t3
row4_next1:
    ror  t0
    brcc row4_next2
    eor  x1, t3
row4_next2:
    ror  t0
    brcc row4_next3
    eor  x2, t3
row4_next3:
    ror  t0
    brcc row4_next4
    eor  x3, t3
row4_next4:
    ; Sbox_TwoRows
    eor  x1, x2
    mov  t1, x2
    and  t1, x1
    eor  x3, t1
    mov  t1, x3
    and  x3, x1
    eor  x3, x2
    mov  t2, x3
    eor  x3, x0
    com  x3
    mov  x2, x3
    or   t2, x0
    eor  x0, t1
    eor  x1, x0
    or   x2, x1
    eor  x2, t1
    eor  x1, t2
    eor  x3, x1

    ROTR_4_ROW
    Store_OneRow

    ; AddRC_TwoRows
    ld x0, X+
    ld x1, X+
    ld x2, X+
    ld x3, X+
    sbiw XL, 4

    ror  t0
    brcc row5_next1
    eor  x0, t3
row5_next1:
    ror  t0
    brcc row5_next2
    eor  x1, t3
row5_next2:
    ror  t0
    brcc row5_next3
    eor  x2, t3
row5_next3:
    ror  t0
    brcc row5_next4
    eor  x3, t3
row5_next4:
    ; Sbox_TwoRows
    eor  x1, x2
    mov  t1, x2
    and  t1, x1
    eor  x3, t1
    mov  t1, x3
    and  x3, x1
    eor  x3, x2
    mov  t2, x3
    eor  x3, x0
    com  x3
    mov  x2, x3
    or   t2, x0
    eor  x0, t1
    eor  x1, x0
    or   x2, x1
    eor  x2, t1
    eor  x1, t2
    eor  x3, x1

    ROTR_4_ROW
    ROTR_1_ROW
    Store_OneRow

    lpm t0, Z+ ; Load two nibbles of round constant for row 2i, 2i+1
    ; AddRC_TwoRows
    ld x0, X+
    ld x1, X+
    ld x2, X+
    ld x3, X+
    sbiw XL, 4

    ror  t0
    brcc row6_next1
    eor  x0, t3
row6_next1:
    ror  t0
    brcc row6_next2
    eor  x1, t3
row6_next2:
    ror  t0
    brcc row6_next3
    eor  x2, t3
row6_next3:
    ror  t0
    brcc row6_next4
    eor  x3, t3
row6_next4:
    ; Sbox_TwoRows
    eor  x1, x2
    mov  t1, x2
    and  t1, x1
    eor  x3, t1
    mov  t1, x3
    and  x3, x1
    eor  x3, x2
    mov  t2, x3
    eor  x3, x0
    com  x3
    mov  x2, x3
    or   t2, x0
    eor  x0, t1
    eor  x1, x0
    or   x2, x1
    eor  x2, t1
    eor  x1, t2
    eor  x3, x1

    ROTL_1_ROW
    ROTL_1_ROW
    Store_OneRow

    ; AddRC_TwoRows
    ld x0, X+
    ld x1, X+
    ld x2, X+
    ld x3, X+
    sbiw XL, 4

    ror  t0
    brcc row7_next1
    eor  x0, t3
row7_next1:
    ror  t0
    brcc row7_next2
    eor  x1, t3
row7_next2:
    ror  t0
    brcc row7_next3
    eor  x2, t3
row7_next3:
    ror  t0
    brcc row7_next4
    eor  x3, t3
row7_next4:
    ; Sbox_TwoRows
    eor  x1, x2
    mov  t1, x2
    and  t1, x1
    eor  x3, t1
    mov  t1, x3
    and  x3, x1
    eor  x3, x2
    mov  t2, x3
    eor  x3, x0
    com  x3
    mov  x2, x3
    or   t2, x0
    eor  x0, t1
    eor  x1, x0
    or   x2, x1
    eor  x2, t1
    eor  x1, t2
    eor  x3, x1

    ROTL_1_ROW
    Store_OneRow

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; Start MixColumns
MC_Start:

    ldi XH, hi8(SRAM_STATE)
    ldi XL, lo8(SRAM_STATE)
    movw YL, XL
A0:
    clr x0
    clr x1
    clr x2
    clr x3
    mul2_GF16_0x13_xor
    mul4_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mulb_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mul8_GF16_0x13_xor
    mul5_GF16_0x13_xor
    mul6_GF16_0x13_xor
    movw XL, YL
    Store_OneRow

A1:
    clr x0
    clr x1
    clr x2
    clr x3
    mul2_GF16_0x13_xor
    mul4_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mulb_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mul8_GF16_0x13_xor
    mul5_GF16_0x13_xor
    movw XL, YL
    mul6_GF16_0x13_xor
    Store_OneRow

A2:
    clr x0
    clr x1
    clr x2
    clr x3
    mul2_GF16_0x13_xor
    mul4_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mulb_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mul8_GF16_0x13_xor
    movw XL, YL
    mul5_GF16_0x13_xor
    mul6_GF16_0x13_xor
    Store_OneRow

A3:
    clr x0
    clr x1
    clr x2
    clr x3
    mul2_GF16_0x13_xor
    mul4_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mulb_GF16_0x13_xor
    mul2_GF16_0x13_xor
    movw XL, YL
    mul8_GF16_0x13_xor
    mul5_GF16_0x13_xor
    mul6_GF16_0x13_xor
    Store_OneRow

A4:
    clr x0
    clr x1
    clr x2
    clr x3
    mul2_GF16_0x13_xor
    mul4_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mulb_GF16_0x13_xor
    movw XL, YL
    mul2_GF16_0x13_xor
    mul8_GF16_0x13_xor
    mul5_GF16_0x13_xor
    mul6_GF16_0x13_xor
    Store_OneRow

A5:
    clr x0
    clr x1
    clr x2
    clr x3
    mul2_GF16_0x13_xor
    mul4_GF16_0x13_xor
    mul2_GF16_0x13_xor
    movw XL, YL
    mulb_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mul8_GF16_0x13_xor
    mul5_GF16_0x13_xor
    mul6_GF16_0x13_xor
    Store_OneRow

A6:
    clr x0
    clr x1
    clr x2
    clr x3
    mul2_GF16_0x13_xor
    mul4_GF16_0x13_xor
    movw XL, YL
    mul2_GF16_0x13_xor
    mulb_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mul8_GF16_0x13_xor
    mul5_GF16_0x13_xor
    mul6_GF16_0x13_xor
    Store_OneRow

A7:
    clr x0
    clr x1
    clr x2
    clr x3
    mul2_GF16_0x13_xor
    movw XL, YL
    mul4_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mulb_GF16_0x13_xor
    mul2_GF16_0x13_xor
    mul8_GF16_0x13_xor
    mul5_GF16_0x13_xor
    mul6_GF16_0x13_xor
    Store_OneRow
.ENDM

PHOTON_Permutation:
    ldi ZH, hi8(RC)
    ldi ZL, lo8(RC)
    ldi cnt2, ROUND_N
round_loop_start:
    RoundFunction
    dec cnt2
    breq round_loop_end
    jmp round_loop_start
round_loop_end:
ret

.section .text
RC:
.byte 0x01,0x62,0xFE,0x9D
.byte 0x23,0x40,0xDC,0xBF
.byte 0x67,0x04,0x98,0xFB
.byte 0xFE,0x9D,0x01,0x62
.byte 0xCD,0xAE,0x32,0x51
.byte 0xAB,0xC8,0x54,0x37
.byte 0x76,0x15,0x89,0xEA
.byte 0xDC,0xBF,0x23,0x40
.byte 0x89,0xEA,0x76,0x15
.byte 0x32,0x51,0xCD,0xAE
.byte 0x45,0x26,0xBA,0xD9
.byte 0xBA,0xD9,0x45,0x26
