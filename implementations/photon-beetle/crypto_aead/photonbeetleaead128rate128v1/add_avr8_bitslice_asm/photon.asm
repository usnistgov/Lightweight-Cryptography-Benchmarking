.EQU ROUND_N = 12
.EQU DIM     = 8

.MACRO Store_OneRow
    st X+, x0
    st X+, x1
    st X+, x2
    st X+, x3
.ENDMACRO

.MACRO ROTL_1
    bst  @0, 7
    lsl  @0
    bld  @0, 0
.ENDMACRO

.MACRO ROTR_1
    bst  @0, 0
    lsr  @0
    bld  @0, 7
.ENDMACRO

.MACRO ROTR_4
    swap @0
.ENDMACRO

ROTR_1_ROW:
    ROTR_1 x0
    ROTR_1 x1
    ROTR_1 x2
    ROTR_1 x3
ret

ROTL_1_ROW:
    ROTL_1 x0
    ROTL_1 x1
    ROTL_1 x2
    ROTL_1 x3
ret

ROTR_4_ROW:
    ROTR_4 x0
    ROTR_4 x1
    ROTR_4 x2
    ROTR_4 x3
ret

RoundFunction:

    rjmp AddRC_Sbox_ShiftRow_Start

ShiftRow_routine_table:
    rjmp ShiftRow_RecoverZ_NoLPM
    rjmp ShiftRow_1
    rjmp ShiftRow_2
    rjmp ShiftRow_3
    rjmp ShiftRow_4
    rjmp ShiftRow_5
    rjmp ShiftRow_6
    rjmp ShiftRow_7

ShiftRow_1:
    rcall ROTR_1_ROW
    rjmp ShiftRow_RecoverZ_LPM

ShiftRow_2:
    rcall ROTR_1_ROW
    rcall ROTR_1_ROW
    rjmp ShiftRow_RecoverZ_NoLPM

ShiftRow_3:
    rcall ROTR_4_ROW
    rcall ROTL_1_ROW
    rjmp ShiftRow_RecoverZ_LPM

ShiftRow_4:
    rcall ROTR_4_ROW
    rjmp ShiftRow_RecoverZ_NoLPM

ShiftRow_5:
    rcall ROTR_4_ROW
    rcall ROTR_1_ROW
    rjmp ShiftRow_RecoverZ_LPM

ShiftRow_6:
    rcall ROTL_1_ROW
    rcall ROTL_1_ROW
    rjmp ShiftRow_RecoverZ_NoLPM

ShiftRow_7:
    rcall ROTL_1_ROW
    rjmp ShiftRow_RecoverZ_NoLPM

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; Start AddRC_Sbox_ShiftRow
AddRC_Sbox_ShiftRow_Start:
    clr t3
    inc t3

    ldi XL, LOW(SRAM_STATE)
    ldi XH, HIGH(SRAM_STATE)

    ldi YL, LOW(ShiftRow_routine_table)
    ldi YH, HIGH(ShiftRow_routine_table)
    ldi rmp, DIM

    lpm t0, Z+ ; Load two nibbles of round constant for row 0, 1
AddRC_Sbox_ShiftRow_Loop:
    ; AddRC_TwoRows
    ld x0, X+
    ld x1, X+
    ld x2, X+
    ld x3, X+
    sbiw XH:XL, 4

    ror  t0
    brcc next1
    eor  x0, t3
next1:
    ror  t0
    brcc next2
    eor  x1, t3
next2:
    ror  t0
    brcc next3
    eor  x2, t3
next3:
    ror  t0
    brcc next4
    eor  x3, t3
next4:
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

    movw cnt0, ZL
    movw ZL, YL
    ijmp

ShiftRow_RecoverZ_NoLPM:
    movw ZL, cnt0
    rjmp ShiftRow_STORE_ROW
ShiftRow_RecoverZ_LPM:
    movw ZL, cnt0
    lpm t0, Z+ ; Load two nibbles of round constant for row 2i, 2i+1
ShiftRow_STORE_ROW:
    Store_OneRow
    adiw YH:YL, 1
    dec rmp
    brne AddRC_Sbox_ShiftRow_Loop

;;;;;;;;;;;;;;;;;;;;;;;;  MixColumn Subroutnes

    rjmp MC_Start

mul_routine_table:
    rjmp mul2_GF16_0x13_xor
    rjmp mul4_GF16_0x13_xor
    rjmp mul2_GF16_0x13_xor
    rjmp mulb_GF16_0x13_xor
    rjmp mul2_GF16_0x13_xor
    rjmp mul8_GF16_0x13_xor
    rjmp mul5_GF16_0x13_xor
    rjmp mul6_GF16_0x13_xor

; For all mul2_GF16_0x13_xor:
; Input
; MSB........LSB
; x0=@0: x1=@1: x2=@2: x3=@3
mul2_GF16_0x13_xor:
    ; # define mul2_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x3 = XOR (x3 ,x0); \
    ; } while (0) ; /* Output : ( MSB ) x1 ,x2 ,x3 , x0 ( LSB ) */
    eor t3, t0
    eor x0, t0
    eor x1, t3
    eor x2, t2
    eor x3, t1
    rjmp MC_INC_CNT1

mul4_GF16_0x13_xor:
    ; # define mul4_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x3 = XOR (x3 ,x0); x0 = XOR (x0 ,x1); \
    ; } while (0) ; /* Output : ( MSB ) x2 ,x3 ,x0 , x1 ( LSB ) */
    eor t3, t0
    eor t0, t1
    eor x0, t1
    eor x1, t0
    eor x2, t3
    eor x3, t2
    rjmp MC_INC_CNT1

mul5_GF16_0x13_xor:
    ; # define mul5_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x2 = XOR (x2 ,x0); x3 = XOR (x3 ,x1); \
    ;   x1 = XOR (x1 ,x2); x0 = XOR (x0 ,x3); \
    ; } while (0) ; /* Output : ( MSB ) x2 ,x0 ,x1 , x3 ( LSB ) */
    eor t2, t0
    eor t3, t1
    eor t1, t2
    eor t0, t3
    eor x0, t3
    eor x1, t1
    eor x2, t0
    eor x3, t2
    rjmp MC_INC_CNT1

mul6_GF16_0x13_xor:
    ; # define mul6_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x3 = XOR (x3 ,x1); x1 = XOR (x1 ,x0); \
    ;   x2 = XOR (x2 ,x1); x0 = XOR (x0 ,x2); \
    ;   x2 = XOR (x2 ,x3); \
    ; } while (0) ; /* Output : ( MSB ) x0 ,x2 ,x3 , x1 ( LSB ) */
    eor t3, t1
    eor t1, t0
    eor t2, t1
    eor t0, t2
    eor t2, t3
    eor x0, t1
    eor x1, t3
    eor x2, t2
    eor x3, t0
    rjmp MC_STORE_ROW

mul8_GF16_0x13_xor:
    ; # define mul8_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x3 = XOR (x3 ,x0); x0 = XOR (x0 ,x1); \
    ;   x1 = XOR (x1 ,x2); \
    ; } while (0) ; /* Output : ( MSB ) x3 ,x0 ,x1 , x2 ( LSB ) */
    eor t3, t0
    eor t0, t1
    eor t1, t2
    eor x0, t2
    eor x1, t1
    eor x2, t0
    eor x3, t3
    rjmp MC_INC_CNT1

mulb_GF16_0x13_xor:
    ; # define mul11_GF16_0x13 (x0 ,x1 ,x2 ,x3) do { \
    ;   x2 = XOR (x2 ,x0); x1 = XOR (x1 ,x3); \
    ;   x0 = XOR (x0 ,x1); x3 = XOR (x3 ,x2); \
    ; } while (0) ; /* Output : ( MSB ) x1 ,x2 ,x0 , x3 ( LSB ) */
    eor t2, t0
    eor t1, t3
    eor t0, t1
    eor t3, t2
    eor x0, t3
    eor x1, t0
    eor x2, t2
    eor x3, t1
    rjmp MC_INC_CNT1

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;; Start MixColumns
MC_Start:
    movw addr4, ZL
    ldi XH, high(SRAM_STATE)
    ldi XL, low(SRAM_STATE)
    movw YL, XL
    clr cnt0
    clr cnt1
A1:
    mov cnt1, cnt0
    clr x0
    clr x1
    clr x2
    clr x3
    ldi ZH, high(mul_routine_table)
    ldi ZL, low(mul_routine_table)
MC_MUL_LOOP:
    ld  t3, X+
    ld  t2, X+
    ld  t1, X+
    ld  t0, X+
    ijmp
MC_INC_CNT1:
    inc  cnt1
    cpi  cnt1, DIM
    brne MC_MUL_NEXT
    clr  cnt1
    movw XL, YL
MC_MUL_NEXT:
    adiw ZH:ZL, 1
    rjmp MC_MUL_LOOP
MC_STORE_ROW:
    cpi  cnt0, 0
    brne MC_STORE_DIRECT
    sbiw XH:XL, STATE_INBYTES
MC_STORE_DIRECT:
    Store_OneRow

    inc cnt0
    cpi cnt0, DIM
    brne A1
    movw ZL, addr4
ret

PHOTON_Permutation:
    ldi ZH, high(RC<<1)
    ldi ZL, low(RC<<1)
    ldi cnt2, ROUND_N
round_loop_start:
    rcall RoundFunction
    dec cnt2
    brne round_loop_start
ret

RC:
.db 0x01,0x62,0xFE,0x9D
.db 0x23,0x40,0xDC,0xBF
.db 0x67,0x04,0x98,0xFB
.db 0xFE,0x9D,0x01,0x62
.db 0xCD,0xAE,0x32,0x51
.db 0xAB,0xC8,0x54,0x37
.db 0x76,0x15,0x89,0xEA
.db 0xDC,0xBF,0x23,0x40
.db 0x89,0xEA,0x76,0x15
.db 0x32,0x51,0xCD,0xAE
.db 0x45,0x26,0xBA,0xD9
.db 0xBA,0xD9,0x45,0x26
