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
.MACRO LFSR6_MACRO
    bst  rc,   5
    bld  tmp0, 0
    bst  rc,   4
    bld  tmp1, 0
    eor  tmp0, tmp1
    ror  tmp0
    rol  rc
    andi rc,   0x3F
.ENDMACRO

.MACRO LFSR7_MACRO
    bst  rc,   6
    bld  tmp0, 0
    bst  rc,   5
    bld  tmp1, 0
    eor  tmp0, tmp1
    ror  tmp0
    rol  rc
    andi rc,   0x7F
.ENDMACRO

.MACRO LFSR8_MACRO
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
.ENDMACRO

.MACRO Sbox
    mov tmp0, @1   ; t  =  b;
    com @0         ; a  = ~a;
    and @1,   @0   ; b &=  a;
    eor @1,   @2   ; b ^=  c;
    or  @2,   tmp0 ; c |=  t;
    eor @0,   @3   ; a ^=  d;
    eor @2,   @0   ; c ^=  a;
    eor tmp0, @3   ; t ^=  d;
    and @0,   @1   ; a &=  b;
    eor @3,   @1   ; d ^=  b;
    eor @0,   tmp0 ; a ^=  t;
    and tmp0, @2   ; t &=  c;
    eor @1,   tmp0 ; b ^=  t;
.ENDMACRO

.MACRO PUSH_CONFLICT
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
.ENDMACRO

.MACRO POP_CONFLICT
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
.ENDMACRO
