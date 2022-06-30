
// Wrapper for testing the AVR version of GIFT-COFB on Arduino devices.

#include "api.h"
#include <avr/pgmspace.h>

extern "C" {
#include "giftb128.h"

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                    const unsigned char* m, unsigned long long mlen,
                    const unsigned char* ad, unsigned long long adlen,
                    const unsigned char* nsec, const unsigned char* npub,
                    const unsigned char* k);

int crypto_aead_decrypt(unsigned char* m, unsigned long long *mlen,
                    unsigned char* nsec, const unsigned char* c,
                    unsigned long long clen, const unsigned char* ad,
                    unsigned long long adlen, const unsigned char* npub,
                    const unsigned char *k);

} // extern "C"

#define DEFAULT_PERF_LOOPS 200
#define DEFAULT_PERF_LOOPS_16 200

static int PERF_LOOPS = DEFAULT_PERF_LOOPS;
static int PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16;

#define MAX_DATA_SIZE 128
#define MAX_TAG_SIZE 32

static unsigned char const key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char const nonce[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static unsigned char const kat_ciphertext[48] = {
    // PT = 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F
    // AD = 000102030405060708090A0B0C0D0E0F
    0x3B, 0xFF, 0x71, 0x5A, 0x56, 0xCB, 0xA4, 0x9D,
    0x1F, 0x7A, 0xC0, 0x69, 0x1A, 0x96, 0x6F, 0xDC,
    0x89, 0xB9, 0x47, 0xBC, 0x66, 0x2F, 0xA2, 0x75,
    0x28, 0xD1, 0xAC, 0x30, 0x53, 0x43, 0x03, 0x33,
    0x2F, 0x79, 0xD0, 0x9D, 0x51, 0x86, 0x93, 0xF6,
    0xF8, 0x13, 0xB9, 0x35, 0xD6, 0x0E, 0xF6, 0x41
};

static unsigned char plaintext[MAX_DATA_SIZE];
static unsigned char ciphertext[MAX_DATA_SIZE + MAX_TAG_SIZE];
static unsigned char ad[16];

static unsigned long encrypt_128_time = 0;
static unsigned long encrypt_16_time = 0;
static unsigned long decrypt_128_time = 0;
static unsigned long decrypt_16_time = 0;

void perfCipherEncrypt128(void)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt 128 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        crypto_aead_encrypt
            (ciphertext, &len, plaintext, 128, 0, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    encrypt_128_time = elapsed;

    Serial.print(elapsed / (128.0 * PERF_LOOPS));
    Serial.print("us per byte, ");
    Serial.print((128.0 * PERF_LOOPS * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt128(void)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long clen;
    unsigned long long plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    crypto_aead_encrypt
        (ciphertext, &clen, plaintext, 128, 0, 0, 0, nonce, key);

    Serial.print("   decrypt 128 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        crypto_aead_decrypt
            (plaintext, &plen, 0, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    decrypt_128_time = elapsed;

    Serial.print(elapsed / (128.0 * PERF_LOOPS));
    Serial.print("us per byte, ");
    Serial.print((128.0 * PERF_LOOPS * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherEncrypt16(void)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt  16 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        crypto_aead_encrypt
            (ciphertext, &len, plaintext, 16, 0, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    encrypt_16_time = elapsed;

    Serial.print(elapsed / (16.0 * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((16.0 * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt16(void)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long clen;
    unsigned long long plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    crypto_aead_encrypt
        (ciphertext, &clen, plaintext, 16, 0, 0, 0, nonce, key);

    Serial.print("   decrypt  16 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        crypto_aead_decrypt
            (plaintext, &plen, 0, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    decrypt_16_time = elapsed;

    Serial.print(elapsed / (16.0 * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((16.0 * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void printHex(const char *tag, const unsigned char *data, int size)
{
    static char const hex[] = "0123456789abcdef";
    Serial.print(tag);
    while (size > 0) {
        int b = *data++;
        Serial.print(hex[(b >> 4) & 0x0F]);
        Serial.print(hex[b & 0x0F]);
        --size;
    }
    Serial.println();
}

void katCheck(void)
{
    int count;
    unsigned long long clen;

    for (count = 0; count < 32; ++count)
        plaintext[count] = (unsigned char)count;

    for (count = 0; count < 16; ++count)
        ad[count] = (unsigned char)count;

    memset(ciphertext, 0xAA, sizeof(ciphertext));
    crypto_aead_encrypt
        (ciphertext, &clen, plaintext, 32, ad, 16, 0, nonce, key);

    if (!memcmp(ciphertext, kat_ciphertext, 48)) {
        Serial.println("   KAT test passed");
    } else {
        Serial.println("   KAT test failed");
        printHex("actual  : ", ciphertext, 48);
        printHex("expected: ", kat_ciphertext, 48);
    }
}

void setup(void)
{
    Serial.begin(9600);
    Serial.println();

    Serial.println("GIFT-COFB[avr_fixsliced_large]:");

    perfCipherEncrypt128();
    perfCipherDecrypt128();
    perfCipherEncrypt16();
    perfCipherDecrypt16();

    katCheck();

    Serial.println();
}

void loop()
{
}
