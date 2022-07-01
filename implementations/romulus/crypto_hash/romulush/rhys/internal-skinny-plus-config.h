/*
 * Copyright (C) 2021 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef LW_INTERNAL_SKINNY_PLUS_CONFIG_H
#define LW_INTERNAL_SKINNY_PLUS_CONFIG_H

/**
 * \file internal-skinny-plus-config.h
 * \brief Configures the variant of SKINNY-128-384+ to use.
 */

/**
 * \brief Select the full fixsliced variant of SKINNY-128-384+.
 *
 * The full variant requires 656 bytes for the key schedule and uses the
 * fixslicing method to implement encryption.
 */
#define SKINNY_PLUS_VARIANT_FULL 0

/**
 * \brief Select the small variant of SKINNY-128-384+.
 *
 * The small variant requires 336 bytes to expand the key schedule ahead
 * of time and uses the regular method to implement encryption.
 */
#define SKINNY_PLUS_VARIANT_SMALL 1

/**
 * \brief Select the tiny variant of SKINNY-128-384+.
 *
 * The tiny variant requires 48 bytes for the key schedule and uses the
 * regular method to implement encryption.  The key schedule is expanded
 * on the fly during encryption.
 */
#define SKINNY_PLUS_VARIANT_TINY 2

/**
 * \def SKINNY_PLUS_VARIANT
 * \brief Selects the default variant of SKINNY-128-384+ to use
 * on this platform.
 */
/**
 * \def SKINNY_PLUS_VARIANT_ASM
 * \brief Defined to 1 if the SKINNY-128-384+ implementation has been
 * replaced with an assembly code version.
 */
#if defined(__AVR__)
#define SKINNY_PLUS_VARIANT_ASM 1
#define SKINNY_PLUS_VARIANT SKINNY_PLUS_VARIANT_TINY
#endif
#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#define SKINNY_PLUS_VARIANT_ASM 1
#define SKINNY_PLUS_VARIANT SKINNY_PLUS_VARIANT_FULL
#endif
#if !defined(SKINNY_PLUS_VARIANT)
#define SKINNY_PLUS_VARIANT SKINNY_PLUS_VARIANT_FULL
#endif
#if !defined(SKINNY_PLUS_VARIANT_ASM)
#define SKINNY_PLUS_VARIANT_ASM 0
#endif

#endif
