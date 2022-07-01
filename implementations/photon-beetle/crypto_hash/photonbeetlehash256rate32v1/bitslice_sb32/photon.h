#ifndef __PHOTON_H_
#define __PHOTON_H_

#include <stdint.h>
#ifdef AVR
#include <avr/pgmspace.h>
#endif

#if !defined(PC) && !defined(AVR) && !defined(MSP) && !defined(ARM)
#define PC
#endif

#define ROUND			12

#define D				8

/*
 *
 * Align memory boundaries in bytes
 *
 */
#define ALIGN_PC_BOUNDRY 64
#define ALIGN_AVR_BOUNDRY 2
#define ALIGN_MSP_BOUNDRY 2
#define ALIGN_ARM_BOUNDRY 8

#if defined(PC) && !defined(ALIGNED) /* PC ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_PC_BOUNDRY)))
#endif /* PC ALIGNED */

#if defined(AVR) && !defined(ALIGNED) /* AVR ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_AVR_BOUNDRY)))
#endif /* AVR ALIGNED */

#if defined(MSP) && !defined(ALIGNED) /* MSP ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_MSP_BOUNDRY)))
#endif /* MSP ALIGNED */

#if defined(ARM) && !defined(ALIGNED) /* ARM ALIGNED */
#define ALIGNED __attribute__ ((aligned(ALIGN_ARM_BOUNDRY)))
#endif /* ARM ALIGNED */


/* 
 *
 * RAM data types 
 *
 */
#define RAM_DATA_BYTE uint8_t ALIGNED
#define RAM_DATA_WORD uint16_t ALIGNED
#define RAM_DATA_DOUBLE_WORD uint32_t ALIGNED

#define READ_RAM_DATA_BYTE(x) x
#define READ_RAM_DATA_WORD(x) x
#define READ_RAM_DATA_DOUBLE_WORD(x) x


/* 
 *
 * Flash/ROM data types 
 *
 */
#if defined(AVR) /* AVR */
#define ROM_DATA_BYTE const uint8_t PROGMEM ALIGNED
#define ROM_DATA_WORD const uint16_t PROGMEM ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t PROGMEM ALIGNED

#define READ_ROM_DATA_BYTE(x) pgm_read_byte(&x)
#define READ_ROM_DATA_WORD(x) pgm_read_word(&x)
#define READ_ROM_DATA_DOUBLE_WORD(x) pgm_read_dword(&x)
#else /* AVR */
#define ROM_DATA_BYTE const uint8_t ALIGNED
#define ROM_DATA_WORD const uint16_t ALIGNED
#define ROM_DATA_DOUBLE_WORD const uint32_t ALIGNED

#define READ_ROM_DATA_BYTE(x) x
#define READ_ROM_DATA_WORD(x) x
#define READ_ROM_DATA_DOUBLE_WORD(x) x
#endif /* AVR */

typedef uint8_t  byte;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t CWord;
typedef u32 tword;

void PHOTON_Permutation(unsigned char *State_inout);

#endif /*  end of photon.h */
