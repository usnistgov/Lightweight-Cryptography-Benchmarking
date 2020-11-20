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
#include "assist.h"

Permutation:
    PUSH_CONFLICT
    mov rcnt, rn

    ldi rc, 0x01
    ldi YH, hi8(SRAM_STATE + 3 * ROW_INBYTES)
    ldi YL, lo8(SRAM_STATE + 3 * ROW_INBYTES)
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

round_loop_start:
    rjmp AddRC_SubColumns_Start

load_columns_table:
    rjmp load_column0
    rjmp load_column1
    rjmp load_column2
    rjmp load_column3
    rjmp load_column4
    rjmp load_column5
    rjmp load_column6
    rjmp load_column7
    rjmp load_column8
    rjmp load_column9
    rjmp load_columna
    rjmp load_columnb
    rjmp amend_shiftRow

load_column0:
    mov  x3j, x30
    rjmp Sbox_one_column
load_column1:
    mov  x30, x3j
    mov  x3j, x31
    rjmp Sbox_one_column
load_column2:
    mov  x31, x3j
    mov  x3j, x32
    rjmp Sbox_one_column
load_column3:
    mov  x32, x3j
    mov  x3j, x33
    rjmp Sbox_one_column
load_column4:
    mov  x33, x3j
    mov  x3j, x34
    rjmp Sbox_one_column
load_column5:
    mov  x34, x3j
    mov  x3j, x35
    rjmp Sbox_one_column
load_column6:
    mov  x35, x3j
    mov  x3j, x36
    rjmp Sbox_one_column
load_column7:
    mov  x36, x3j
    mov  x3j, x37
    rjmp Sbox_one_column
load_column8:
    mov  x37, x3j
    mov  x3j, x38
    rjmp Sbox_one_column
load_column9:
    mov  x38, x3j
    mov  x3j, x39
    rjmp Sbox_one_column
load_columna:
    mov  x39, x3j
    mov  x3j, x3a
    rjmp Sbox_one_column
load_columnb:
    mov  x3a, x3j
    mov  x3j, x3b
    rjmp Sbox_one_column

;;;;;;;;;;;;;;;;;;;;;;;; Real Start
AddRC_SubColumns_Start:
    ldi  YH, hi8(SRAM_STATE)
    ldi  YL, lo8(SRAM_STATE)
    ldi  ZL, pm_lo8(load_columns_table)
    ldi  ZH, pm_hi8(load_columns_table)
    clr  ccnt
    ld   x0j, Y
    eor  x0j, rc
    LFSR7_MACRO

    ldd  x1j, Y + ROW_INBYTES
    ldd  x2j, Y + 2 * ROW_INBYTES
    ijmp
Sbox_one_column:
    Sbox x0j, x1j, x2j, x3j

    ;  b  a  9  8  7  6  5  4  3  2  1  0
    ; -- -- -- -- -- -- -- -- -- -- -- x- 0
    ; -- -- -- -- -- -- -- -- -- -- -- x' 0
    ; -- -- -- -- -- -- -- -- -- -- x- -- 1
    ; -- -- -- -- x' -- -- -- -- -- -- -- 7
    ;  4  3  2  1  0  b  a  9  8  7  6  5
    ; Store a byte to Row 0
    st   Y, x0j
    ; Store a byte combined with ShiftRow 1
    lsl  t1j
    mov  t1j, x1j ; back up the last updated byte in t1j, to be used in shiftRow1 (1 bit left)
    rol  x1j
    std  Y + ROW_INBYTES, x1j
    ; Store a byte combined with ShiftRow 2
    inc  ccnt
    cpi  ccnt, ROW_INBYTES
    breq ROW2_WRAP
    ldd  t2j, Y + 2 * ROW_INBYTES + 1 ; load next byte, the last updated byte needed to be shifted to the address of the next bytes
    std  Y + 2 * ROW_INBYTES + 1, x2j
    mov  x2j, t2j
    jmp  NO_ROW2_WRAP
ROW2_WRAP:
    std  Y + ROW_INBYTES + 1, x2j
    ; remain ShiftRow3 to be done at 'amend_shiftRow'
NO_ROW2_WRAP:
    adiw YL, 1
    ld   x0j, Y
    ldd  x1j, Y + ROW_INBYTES

    adiw ZL, 1
    ijmp

amend_shiftRow:
    ldi YH, hi8(SRAM_STATE + ROW_INBYTES)
    ldi YL, lo8(SRAM_STATE + ROW_INBYTES)

    ld  x1j, Y
    bst t1j, 7
    bld x1j, 0
    st  Y,   x1j

    ; >>> 1
    mov  x3b, x3j
    ror  x3j
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
    ;mov  x3j, x30
    ;mov  x30, x35
    ;mov  x35, x32
    ;mov  x32, x37
    ;mov  x37, x34
    ;mov  x34, x31
    ;mov  x31, x36
    ;mov  x36, x33
    ;mov  x33, x3j
    mov  x3j, x30
    mov  x30, x35
    mov  x35, x3a
    mov  x3a, x33
    mov  x33, x38
    mov  x38, x31
    mov  x31, x36
    mov  x36, x3b
    mov  x3b, x34
    mov  x34, x39
    mov  x39, x32
    mov  x32, x37
    mov  x37, x3j

    dec rcnt
    breq round_loop_end
    rjmp round_loop_start

round_loop_end:

    ldi YH, hi8(SRAM_STATE + 3 * ROW_INBYTES)
    ldi YL, lo8(SRAM_STATE + 3 * ROW_INBYTES)
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