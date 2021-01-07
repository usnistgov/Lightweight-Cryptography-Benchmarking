/******************************************************************************
 *
 * AES-128
 *
 ******************************************************************************/

#ifndef __AES_H__
#define __AES_H__

#include <stdint.h>

void aes_key_schedule(const uint8_t *key, uint8_t *round_keys);
// By CC - updated function name aes_encrypt()
void aes_encrypt2(uint8_t *state, uint8_t *round_keys);
void aes_decrypt(uint8_t *block, uint8_t *round_keys);

#endif
