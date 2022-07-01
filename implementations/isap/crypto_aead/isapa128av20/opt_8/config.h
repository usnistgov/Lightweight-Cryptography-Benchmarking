#ifndef CONFIG_H
#define CONFIG_H

#define ENABLE_HASH 0

#include "isap.h"

// ISAP-A-128a
const uint8_t ISAP_IV_A[] = {0x01, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};
const uint8_t ISAP_IV_KA[] = {0x02, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};
const uint8_t ISAP_IV_KE[] = {0x03, ISAP_K, ISAP_rH, ISAP_rB, ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK};

// Ascon-Hash
const uint8_t ASCON_HASH_IV[] = {0x00, 0x40, 0x0c, 0x00, 0x00, 0x00, 0x01, 0x00};

#endif // CONFIG_H
