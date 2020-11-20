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
    ld  x3c, Y+
    ld  x3d, Y+
    ld  x3e, Y+
    ld  x3f, Y+

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
    rjmp load_columnc
    rjmp load_columnd
    rjmp load_columne
    rjmp load_columnf
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
load_columnc:
    mov  x3b, x3j
    mov  x3j, x3c
    rjmp Sbox_one_column
load_columnd:
    mov  x3c, x3j
    mov  x3j, x3d
    rjmp Sbox_one_column
load_columne:
    mov  x3d, x3j
    mov  x3j, x3e
    rjmp Sbox_one_column
load_columnf:
    mov  x3e, x3j
    mov  x3j, x3f
    rjmp Sbox_one_column

#if defined(CRYPTO_AEAD) && defined(CRYPTO_HASH)
LFSR_table:
    rjmp LFSR7
    rjmp LFSR8
LFSR7:
    LFSR7_MACRO
    rjmp LFSR_DONE
LFSR8:
    LFSR8_MACRO
    rjmp LFSR_DONE
#endif

;;;;;;;;;;;;;;;;;;;;;;;; Real Start
AddRC_SubColumns_Start:
    ldi  YH, hi8(SRAM_STATE)
    ldi  YL, lo8(SRAM_STATE)
    clr  ccnt
    ld   x0j, Y
    eor  x0j, rc

#if defined(CRYPTO_AEAD) && defined(CRYPTO_HASH)
    ldi  ZL, pm_lo8(LFSR_table)
    ldi  ZH, pm_hi8(LFSR_table)
    sbrc AEDH,  2 ; AEDH[2] = 0 for AEAD and AEDH[1] = 1 for HASH
    adiw ZL, 1
    ijmp
LFSR_DONE:
#elif defined(CRYPTO_AEAD)
    LFSR7_MACRO ; only AEAD
#else
    LFSR8_MACRO ; only HASH
#endif

    ldd  x1j, Y + ROW_INBYTES
    ldd  x2j, Y + 2 * ROW_INBYTES
    ldd  t2j, Y + 2 * ROW_INBYTES + 1
    ldi  ZL, pm_lo8(load_columns_table)
    ldi  ZH, pm_hi8(load_columns_table)
    ijmp
Sbox_one_column:
    Sbox x0j, x1j, x2j, x3j

    ;  f  e  d  c  b  a  9  8  7  6  5  4  3  2  1  0
    ; -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- x- 0
    ; -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- x' 0
    ; -- -- -- -- -- -- -- -- -- -- -- -- -- x- -- -- 2
    ; -- -- -- -- -- -- -- -- -- -- -- -- x' -- -- -- 3
    ;  c  b  a  9  8  7  6  5  4  3  2  1  0  f  e  d
    ; Store a byte to Row 0
    st   Y, x0j
    ; Store a byte combined with ShiftRow1
    lsl  t1j
    mov  t1j, x1j ; back up the last updated byte in t1j, to be used in shiftRow1 (1 bit left)
    rol  x1j
    std  Y + ROW_INBYTES, x1j
    ; Store a byte combined with ShiftRow2
    inc  ccnt
    cpi  ccnt, ROW_INBYTES - 1
    brsh ROW2_WRAP
    ldd  tmp0, Y + 2 * ROW_INBYTES + 2 ; load next byte, the last updated byte needed to be shifted to the address of the next bytes
    std  Y + 2 * ROW_INBYTES + 2, x2j
    mov  x2j, t2j
    mov  t2j, tmp0
    jmp  NO_ROW2_WRAP
ROW2_WRAP:
    std  Y + ROW_INBYTES + 2, x2j
    mov  x2j, t2j

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

    ; <<< 1
    mov  x3f, x3j
    rol  x3j
    rol  x30
    rol  x31
    rol  x32
    rol  x33
    rol  x34
    rol  x35
    rol  x36
    rol  x37
    rol  x38
    rol  x39
    rol  x3a
    rol  x3b
    rol  x3c
    rol  x3d
    rol  x3e
    rol  x3f
    ; <<< 24
    ; f  e  d  c  b  a  9  8  7  6  5  4  3  2  1  0 =>
    ; c  b  a  9  8  7  6  5  4  3  2  1  0  f  e  d
    mov  x3j, x30
    mov  x30, x3d
    mov  x3d, x3a
    mov  x3a, x37
    mov  x37, x34
    mov  x34, x31
    mov  x31, x3e
    mov  x3e, x3b
    mov  x3b, x38
    mov  x38, x35
    mov  x35, x32
    mov  x32, x3f
    mov  x3f, x3c
    mov  x3c, x39
    mov  x39, x36
    mov  x36, x33
    mov  x33, x3j

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
    st   Y+, x3c
    st   Y+, x3d
    st   Y+, x3e
    st   Y+, x3f

    POP_CONFLICT
ret