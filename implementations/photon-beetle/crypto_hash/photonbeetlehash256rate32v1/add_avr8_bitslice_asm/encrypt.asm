
.EQU SQUEEZE_RATE_INBITS  = 128
.EQU SQUEEZE_RATE_INBYTES = ((SQUEEZE_RATE_INBITS + 7) / 8)
.EQU SQUEEZE_RATE_MASK    = (SQUEEZE_RATE_INBYTES - 1)

.EQU CAPACITY_INBITS      = (STATE_INBITS - RATE_INBITS)
.EQU CAPACITY_INBYTES     = ((CAPACITY_INBITS + 7) / 8)

; For CRYPTO_AEAD
.EQU KEY_INBITS           = (CRYPTO_KEYBYTES * 8)
.EQU KEY_INBYTES          = (CRYPTO_KEYBYTES)

.EQU NONCE_INBITS         = (CRYPTO_NPUBBYTES * 8)
.EQU NONCE_INBYTES        = (CRYPTO_NPUBBYTES)

.EQU TAG_INBITS           = (CRYPTO_ABYTES * 8)
.EQU TAG_INBYTES          = (CRYPTO_ABYTES)

.def t0 = r8
.def t1 = r9
.def t2 = r10
.def t3 = r11

.def x0 = r12
.def x1 = r13
.def x2 = r14
.def x3 = r15

.def ed    = r1

.def addr0 = r2
.def addr1 = r3
.def addr2 = r4
.def addr3 = r5
.def addr4 = r6
.def addr5 = r7

.def domain_cnt = r20   ; overlap with cnt0, only temporarily used, no need to back up
.def domain_cnt0   = r23
.def domain_cnt1   = r24

.include "./assist.asm"
.include "./photon.asm"

AddDomainCounter:
    ldi YH,   HIGH(SRAM_STATE + STATE_INBYTES - 3)
    ldi YL,   LOW(SRAM_STATE + STATE_INBYTES - 3)
    ldi rmp,  0x80
    ldi cnt1, 3
check_domain_bit:
    ror  domain_cnt
    brcc no_xor
    ld   x0,  Y
    eor  x0,  rmp
    st   Y,   x0
no_xor:
    adiw Y,   1
    dec  cnt1
    brne check_domain_bit
ret

; require XH:XL be the address of the current associated data/message block
XOR_to_State:
    ldi  YH,   HIGH(SRAM_STATE)
    ldi  YL,   LOW(SRAM_STATE)
    mov  cnt0, rate
    dec  cnt0
XOR_to_State_loop:
    rcall Load_Reorder_32_bits
    ld   rmp,  Y
    eor  rmp,  x0
    st   Y+,   rmp
    ld   rmp,  Y
    eor  rmp,  x1
    st   Y+,   rmp
    ld   rmp,  Y
    eor  rmp,  x2
    st   Y+,   rmp
    ld   rmp,  Y
    eor  rmp,  x3
    st   Y+,   rmp
    subi  cnt0, 4
    brsh XOR_to_State_loop
; XH:XL are now the address of the next associated data/message block if this is not the last block
ret

; require XH:XL pointed to the source data to be padded
PAD_OneZero:
    ldi  YH,   HIGH(SRAM_PAD)
    ldi  YL,   LOW(SRAM_PAD)
    mov  cnt1, rate
pad_copy:
    ld   rmp, X+
    st   Y+,  rmp
    dec  cnt1
    dec  cnt0
    brne pad_copy
pad_one:
    ldi  rmp, 1
    st   Y+,  rmp
    dec  cnt1
    breq pad_end
    clr  rmp
pad_zero:
    st   Y+, rmp
    dec  cnt1
    brne pad_zero
pad_end:
    ldi  XH,  HIGH(SRAM_PAD)
    ldi  XL,  LOW(SRAM_PAD)
; XH:XL are now pointed to last block needed to be processed
ret

HASH:
    movw  addr0, XL
hash_block_loop:
    rcall PHOTON_Permutation
    movw  XL,    addr0
    cp    rate,  adlen
    brsh  hash_last_block
    rcall XOR_to_State
    movw  addr0, XL
    sub   adlen, rate
    rjmp  hash_block_loop

hash_last_block:
    cp    adlen, rate
    breq  hash_xor_domain
    mov   cnt0, adlen
    rcall PAD_OneZero

hash_xor_domain:
    clr   adlen
    rcall XOR_to_State
    mov   domain_cnt, domain_cnt0
    rcall AddDomainCounter
ret

TAG:
    rcall PHOTON_Permutation
    ldi   XH, HIGH(SRAM_STATE)
    ldi   XL, LOW(SRAM_STATE)
    movw  YL, addr2
    rcall Load_invReorder_Store_128_bits
ret

#ifdef CRYPTO_AEAD
.IF (RATE_INBITS == 128)
XOR_to_Cipher:
    mov  t2, rate
    cp   t2, mclen
    brlo XOR_to_Cipher_Start
    mov  t2, mclen ; backup the real length of the remaining message

XOR_to_Cipher_Start:
    ldi  XH, HIGH(SRAM_STATE)
    ldi  XL, LOW(SRAM_STATE)
    ldi  YH, HIGH(SRAM_ADDITIONAL)
    ldi  YL, LOW(SRAM_ADDITIONAL)
    rcall Load_invReorder_Store_128_bits ; State move to additional SRAM and reorder

    movw XL, addr0
    movw ZL, addr2

    ; XOR Part 2
    sbiw YH:YL, (RATE_INBYTES>>1) ; Pointed to Part 2
    ldi  cnt0, (RATE_INBYTES>>1)
    cp   cnt0, mclen
    brlo XOR_Part2_Store_Cipher_begin
    mov  cnt0, mclen
XOR_Part2_Store_Cipher_begin:
    sub  mclen, cnt0
XOR_Part2_Store_Cipher_loop:
    ld   t0, Y+
    ld   x0, X+
    eor  x0, t0
    st   Z+, x0
    dec  cnt0
    brne XOR_Part2_Store_Cipher_loop

    cpi  mclen, 1
    brlo XOR_to_Cipher_END

    ; XOR (Part 1 >>> 1)
    ldi  cnt0, (RATE_INBYTES>>1)
    cp   cnt0, mclen
    brlo XOR_Part1_Store_Cipher_begin
    mov  cnt0, mclen
XOR_Part1_Store_Cipher_begin:
    sub  mclen, cnt0
    ldi  YH, HIGH(SRAM_ADDITIONAL)
    ldi  YL, LOW(SRAM_ADDITIONAL)
    ld   t0, Y
    bst  t0, 0
    adiw YH:YL, (RATE_INBYTES>>1)-1
    ld   t0, Y
    ror  t0
    bld  t0, 7
    st   Y,  t0
    ldi  cnt1, (RATE_INBYTES>>1)-1
ROR_part1_loop:
    ld   t0, -Y
    ror  t0
    st   Y,  t0
    dec  cnt1
    brne ROR_part1_loop

XOR_Part1_Store_Cipher_loop:
    ld   t0, Y+
    ld   x0, X+
    eor  x0, t0
    st   Z+, x0
    dec  cnt0
    brne XOR_Part1_Store_Cipher_loop

XOR_to_Cipher_END:
    tst  ed
    brne XOR_to_Cipher_dec

XOR_to_Cipher_enc:
    movw  XL,   addr0
    cp    t2,   rate
    brsh  XOR_to_Cipher_XOR_to_State
    mov   cnt0, t2
    rcall PAD_OneZero
    rjmp  XOR_to_Cipher_XOR_to_State

XOR_to_Cipher_dec:
    movw  XL,   addr2
    cp    t2,   rate
    brsh  XOR_to_Cipher_XOR_to_State
    ; need to be padded
    mov   cnt0, t2
    rcall PAD_OneZero

XOR_to_Cipher_XOR_to_State:
    rcall XOR_to_State

    clr  rmp
    add  addr0, t2
    adc  addr1, rmp
    add  addr2, t2
    adc  addr3, rmp
ret
.ELSE
; RATE_INBITS == 32
XOR_to_Cipher:
    mov  t2, rate
    cp   t2, mclen
    brlo XOR_to_Cipher_Start
    mov  t2, mclen ; backup the real length of the remaining message

XOR_to_Cipher_Start:
    ldi XH, HIGH(SRAM_STATE)
    ldi XL, LOW(SRAM_STATE)
    ld  x0, X+
    ld  x1, X+
    ld  x2, X+
    ld  x3, X+
    ldi YH, HIGH(SRAM_ADDITIONAL)
    ldi YL, LOW(SRAM_ADDITIONAL)
    rcall invReorder_Store_32_bits

    movw XL, addr0
    movw ZL, addr2

    ; XOR Part 2
    sbiw YH:YL, (RATE_INBYTES>>1) ; Pointed to Part 2
    ldi  cnt0, (RATE_INBYTES>>1)
    cp   cnt0, mclen
    brlo XOR_Part2_Store_Cipher_begin
    mov  cnt0, mclen
XOR_Part2_Store_Cipher_begin:
    sub  mclen, cnt0
XOR_Part2_Store_Cipher_loop:
    ld   t0, Y+
    ld   x0, X+
    eor  x0, t0
    st   Z+, x0
    dec  cnt0
    brne XOR_Part2_Store_Cipher_loop

    cpi  mclen, 1
    brlo XOR_to_Cipher_END

    ; XOR (Part 1 >>> 1)
    ldi  cnt0, (RATE_INBYTES>>1)
    cp   cnt0, mclen
    brlo XOR_Part1_Store_Cipher_begin
    mov  cnt0, mclen
XOR_Part1_Store_Cipher_begin:
    sub  mclen, cnt0
    ldi  YH, HIGH(SRAM_ADDITIONAL)
    ldi  YL, LOW(SRAM_ADDITIONAL)
    ld   t0, Y+
    ld   t1, Y+
    bst  t0, 0
    ror  t1
    ror  t0
    bld  t1, 7

    ld   x0, X+
    eor  x0, t0
    st   Z+, x0
    dec  cnt0
    breq XOR_to_Cipher_END
    ld   x0, X+
    eor  x0, t1
    st   Z+, x0

XOR_to_Cipher_END:
    tst  ed
    brne XOR_to_Cipher_dec

XOR_to_Cipher_enc:
    movw  XL,   addr0
    cp    t2, rate
    brsh  XOR_to_Cipher_XOR_to_State
    mov   cnt0, t2
    rcall PAD_OneZero
    rjmp  XOR_to_Cipher_XOR_to_State

XOR_to_Cipher_dec:
    movw  XL,   addr2
    cp    t2,   rate
    brsh  XOR_to_Cipher_XOR_to_State
    ; need to be padded
    mov   cnt0, t2
    rcall PAD_OneZero

XOR_to_Cipher_XOR_to_State:
    rcall XOR_to_State

    clr  rmp
    add  addr0, t2
    adc  addr1, rmp
    add  addr2, t2
    adc  addr3, rmp
ret
.ENDIF

ENC:
    tst  ed
    brne dec_inputout_address
enc_inputout_address:
    ldi  ZH,    HIGH(SRAM_CIPHER)
    ldi  ZL,    LOW(SRAM_CIPHER)
    ldi  XH,    HIGH(SRAM_MESSAGE)
    ldi  XL,    LOW(SRAM_MESSAGE)
    rjmp backup_inputout_address
dec_inputout_address:
    ldi  ZH,    HIGH(SRAM_MESSAGE)
    ldi  ZL,    LOW(SRAM_MESSAGE)
    ldi  XH,    HIGH(SRAM_CIPHER)
    ldi  XL,    LOW(SRAM_CIPHER)
backup_inputout_address:
    movw addr0, XL
    movw addr2, ZL

enc_block_loop:
    rcall PHOTON_Permutation
    rcall XOR_to_Cipher
    cpi   mclen, 1
    brsh  enc_block_loop

    mov   domain_cnt, domain_cnt1
    rcall AddDomainCounter
ret

AUTH_AND_ENCDEC:
    ldi YH, HIGH(SRAM_STATE)
    ldi YL, LOW(SRAM_STATE)

    ldi XH, HIGH(SRAM_NONCE)
    ldi XL, LOW(SRAM_NONCE)
    rcall Load_Reorder_Store_128_bits
    ldi XH, HIGH(SRAM_KEY)
    ldi XL, LOW(SRAM_KEY)
    rcall Load_Reorder_Store_128_bits

    ldi domain_cnt0, 1
    ldi domain_cnt1, 1

test_adlen_zero:
    tst  adlen
    breq adlen_zero_test_mlen_zero

    ; adlen != 0
adlen_nzero_test_mlen_zero:
    tst   mclen
    brne  test_adlen_divisible
    ldi   domain_cnt0, 3
test_adlen_divisible:
    mov   rmp, adlen
    andi  rmp, RATE_INBYTES_MASK
    breq  hash_ad
    inc   domain_cnt0 ; 2 or 4
hash_ad:
    ldi  XH, HIGH(SRAM_ASSOCIATED_DATA)
    ldi  XL, LOW(SRAM_ASSOCIATED_DATA)
    rcall HASH
    tst   mclen
    breq  AUTH_AND_ENCDEC_end
    rjmp  test_mlen_divisible

adlen_zero_test_mlen_zero:
    ldi  domain_cnt1, 5
    tst  mclen
    breq adlen_zero_mlen_zero

    ; mclen != 0
test_mlen_divisible:
    mov  rmp, mclen
    andi rmp, RATE_INBYTES_MASK
    breq enc_dec_m
    inc  domain_cnt1 ; 2 or 6
enc_dec_m:
    rcall ENC
    rjmp AUTH_AND_ENCDEC_end

adlen_zero_mlen_zero:
    ; empty message and empty associated data
    ldi YH, HIGH(SRAM_STATE + STATE_INBYTES - 3)
    ldi YL, LOW(SRAM_STATE + STATE_INBYTES - 3)
    ld  x0, Y
    ldi rmp, 0x80
    eor x0, rmp
    st  Y,  x0

    tst  ed
    brne adlen_zero_dec_inputout_address
adlen_zero_enc_inputout_address:
    ldi  ZH,    HIGH(SRAM_CIPHER)
    ldi  ZL,    LOW(SRAM_CIPHER)
    rjmp adlen_zero_backup_inputout_address
adlen_zero_dec_inputout_address:
    ldi  ZH,    HIGH(SRAM_MESSAGE)
    ldi  ZL,    LOW(SRAM_MESSAGE)
adlen_zero_backup_inputout_address:
    movw addr2, ZL

AUTH_AND_ENCDEC_end:
ret

crypto_aead_encrypt:
    ldi rate, RATE_INBYTES
    clr ed

    mov t0, mclen
    ldi rmp, CRYPTO_ABYTES
    add t0, rmp
    ldi YH, HIGH(SRAM_CLEN)
    ldi YL, LOW(SRAM_CLEN)
    st  Y,  t0

    rcall AUTH_AND_ENCDEC
    rcall TAG
ret

crypto_aead_decrypt:
    ldi rate, RATE_INBYTES
    clr ed
    inc ed

    mov t0,  mclen
    ldi rmp, CRYPTO_ABYTES
    sub t0,  rmp
    ldi YH,  HIGH(SRAM_MLEN)
    ldi YL,  LOW(SRAM_MLEN)
    st  Y,   t0

    rcall AUTH_AND_ENCDEC

    movw  XL,    addr2
    ldi   YH,    HIGH(SRAM_ADDITIONAL)
    ldi   YL,    LOW(SRAM_ADDITIONAL)
    movw  addr2, YL
    rcall TAG
    sbiw  YH:YL, CRYPTO_ABYTES

    ldi   ZH,    HIGH(SRAM_TAG_MATCH)
    ldi   ZL,    LOW(SRAM_TAG_MATCH)

    ldi  cnt0, CRYPTO_ABYTES
compare_tag:
    ld   t0, Y+
    ld   x0, X+
    cp   t0, x0
    brne return_tag_not_match
    dec  cnt0
    brne compare_tag
    rjmp return_tag_match

return_tag_not_match:
    ldi  rmp, 0xFF
    st   Z, rmp
    rjmp crypto_aead_decrypt_end
return_tag_match:
    clr  rmp
    st   Z, rmp

crypto_aead_decrypt_end:
ret

; #ifdef CRYPTO_AEAD
#endif

#ifdef CRYPTO_HASH
crypto_hash:
    ; empty half state
    ldi YH, HIGH(SRAM_STATE + INITIAL_RATE_INBYTES)
    ldi YL, LOW(SRAM_STATE + INITIAL_RATE_INBYTES)
    clr rmp
    ldi cnt1, (STATE_INBYTES - INITIAL_RATE_INBYTES)
zero_state:
    st  Y+, rmp
    dec cnt1
    brne zero_state

    ldi domain_cnt0, 1
    sbiw YH:YL, (STATE_INBYTES - INITIAL_RATE_INBYTES)
    ldi XH, HIGH(SRAM_MESSAGE)
    ldi XL, LOW(SRAM_MESSAGE)

    tst mclen
    breq add_domain

test_mlen_initrate:
    ; mclen != 0
    cpi mclen, INITIAL_RATE_INBYTES
    brlo less_than_initial_rate
    breq equal_to_initial_rate

more_than_initial_rate:
    rcall Load_Reorder_Store_128_bits
    ldi rate, HASH_RATE_INBYTES
    mov adlen, mclen
    subi adlen, INITIAL_RATE_INBYTES
    mov  rmp, adlen
    andi rmp, HASH_RATE_INBYTES_MASK
    breq hash_message
    inc  domain_cnt0
hash_message:
    rcall HASH
    rjmp gen_digest

equal_to_initial_rate:
    inc domain_cnt0
    rcall Load_Reorder_Store_128_bits
    rjmp add_domain
    
less_than_initial_rate:
    mov   cnt0, mclen
    ldi   rate, INITIAL_RATE_INBYTES
    rcall PAD_OneZero
    ldi YH, HIGH(SRAM_STATE)
    ldi YL, LOW(SRAM_STATE)
    rcall Load_Reorder_Store_128_bits
    rjmp add_domain

add_domain:
    mov   domain_cnt, domain_cnt0
    rcall AddDomainCounter
gen_digest:
    ldi XH, HIGH(SRAM_DIGEST)
    ldi XL, LOW(SRAM_DIGEST)
    movw addr2, XL
    rcall TAG
    movw XL, addr2
    adiw XH:XL, SQUEEZE_RATE_INBYTES
    movw addr2, XL
    rcall TAG
ret

#endif

