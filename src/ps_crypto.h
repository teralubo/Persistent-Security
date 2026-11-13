#ifndef PS_CRYPTO_H
#define PS_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void ps_sha256(const uint8_t* data, size_t length, uint8_t output[32]);
bool ps_pbkdf2_sha256(
    const uint8_t* password,
    size_t password_length,
    const uint8_t* salt,
    size_t salt_length,
    uint32_t iterations,
    uint8_t* output,
    size_t output_length);
void ps_secure_zero(void* data, size_t length);

#endif
