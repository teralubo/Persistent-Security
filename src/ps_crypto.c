#include "ps_crypto.h"

#include <limits.h>
#include <string.h>

typedef struct {
    uint32_t state[8];
    uint64_t bit_length;
    uint8_t block[64];
    size_t used;
} PsSha256;

static const uint32_t ps_sha256_k[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
    0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
    0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
    0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
};

static uint32_t ps_rotr(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32U - count));
}

static uint32_t ps_load_be32(const uint8_t* input) {
    return ((uint32_t)input[0] << 24U) | ((uint32_t)input[1] << 16U) |
           ((uint32_t)input[2] << 8U) | (uint32_t)input[3];
}

static void ps_store_be32(uint8_t* output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24U);
    output[1] = (uint8_t)(value >> 16U);
    output[2] = (uint8_t)(value >> 8U);
    output[3] = (uint8_t)value;
}

static void ps_sha256_transform(PsSha256* sha, const uint8_t block[64]) {
    uint32_t words[64];
    for(size_t i = 0; i < 16; ++i) {
        words[i] = ps_load_be32(&block[i * 4U]);
    }
    for(size_t i = 16; i < 64; ++i) {
        const uint32_t s0 = ps_rotr(words[i - 15U], 7U) ^
                            ps_rotr(words[i - 15U], 18U) ^ (words[i - 15U] >> 3U);
        const uint32_t s1 = ps_rotr(words[i - 2U], 17U) ^
                            ps_rotr(words[i - 2U], 19U) ^ (words[i - 2U] >> 10U);
        words[i] = words[i - 16U] + s0 + words[i - 7U] + s1;
    }

    uint32_t a = sha->state[0];
    uint32_t b = sha->state[1];
    uint32_t c = sha->state[2];
    uint32_t d = sha->state[3];
    uint32_t e = sha->state[4];
    uint32_t f = sha->state[5];
    uint32_t g = sha->state[6];
    uint32_t h = sha->state[7];

    for(size_t i = 0; i < 64; ++i) {
        const uint32_t sum1 = ps_rotr(e, 6U) ^ ps_rotr(e, 11U) ^ ps_rotr(e, 25U);
        const uint32_t choose = (e & f) ^ ((~e) & g);
        const uint32_t temp1 = h + sum1 + choose + ps_sha256_k[i] + words[i];
        const uint32_t sum0 = ps_rotr(a, 2U) ^ ps_rotr(a, 13U) ^ ps_rotr(a, 22U);
        const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint32_t temp2 = sum0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    sha->state[0] += a;
    sha->state[1] += b;
    sha->state[2] += c;
    sha->state[3] += d;
    sha->state[4] += e;
    sha->state[5] += f;
    sha->state[6] += g;
    sha->state[7] += h;
    ps_secure_zero(words, sizeof(words));
}

static void ps_sha256_init(PsSha256* sha) {
    static const uint32_t initial[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
    };
    memcpy(sha->state, initial, sizeof(initial));
    sha->bit_length = 0U;
    sha->used = 0U;
}

static void ps_sha256_update(PsSha256* sha, const uint8_t* data, size_t length) {
    for(size_t i = 0; i < length; ++i) {
        sha->block[sha->used++] = data[i];
        if(sha->used == sizeof(sha->block)) {
            ps_sha256_transform(sha, sha->block);
            sha->bit_length += 512U;
            sha->used = 0U;
        }
    }
}

static void ps_sha256_finish(PsSha256* sha, uint8_t output[32]) {
    const uint64_t total_bits = sha->bit_length + (uint64_t)sha->used * 8U;
    size_t i = sha->used;
    sha->block[i++] = 0x80U;

    if(i > 56U) {
        while(i < 64U) sha->block[i++] = 0U;
        ps_sha256_transform(sha, sha->block);
        i = 0U;
    }
    while(i < 56U) sha->block[i++] = 0U;
    for(size_t j = 0; j < 8U; ++j) {
        sha->block[63U - j] = (uint8_t)(total_bits >> (j * 8U));
    }
    ps_sha256_transform(sha, sha->block);

    for(size_t j = 0; j < 8U; ++j) {
        ps_store_be32(&output[j * 4U], sha->state[j]);
    }
    ps_secure_zero(sha, sizeof(*sha));
}

void ps_sha256(const uint8_t* data, size_t length, uint8_t output[32]) {
    PsSha256 sha;
    ps_sha256_init(&sha);
    if(length > 0U) ps_sha256_update(&sha, data, length);
    ps_sha256_finish(&sha, output);
}

static void ps_hmac_sha256(
    const uint8_t* key,
    size_t key_length,
    const uint8_t* first,
    size_t first_length,
    const uint8_t* second,
    size_t second_length,
    uint8_t output[32]) {
    uint8_t key_block[64] = {0U};
    uint8_t inner_hash[32];
    uint8_t pad[64];
    if(key_length > sizeof(key_block)) {
        ps_sha256(key, key_length, key_block);
    } else if(key_length > 0U) {
        memcpy(key_block, key, key_length);
    }

    for(size_t i = 0; i < sizeof(pad); ++i) pad[i] = (uint8_t)(key_block[i] ^ 0x36U);
    PsSha256 sha;
    ps_sha256_init(&sha);
    ps_sha256_update(&sha, pad, sizeof(pad));
    if(first_length > 0U) ps_sha256_update(&sha, first, first_length);
    if(second_length > 0U) ps_sha256_update(&sha, second, second_length);
    ps_sha256_finish(&sha, inner_hash);

    for(size_t i = 0; i < sizeof(pad); ++i) pad[i] = (uint8_t)(key_block[i] ^ 0x5cU);
    ps_sha256_init(&sha);
    ps_sha256_update(&sha, pad, sizeof(pad));
    ps_sha256_update(&sha, inner_hash, sizeof(inner_hash));
    ps_sha256_finish(&sha, output);

    ps_secure_zero(key_block, sizeof(key_block));
    ps_secure_zero(inner_hash, sizeof(inner_hash));
    ps_secure_zero(pad, sizeof(pad));
}

bool ps_pbkdf2_sha256(
    const uint8_t* password,
    size_t password_length,
    const uint8_t* salt,
    size_t salt_length,
    uint32_t iterations,
    uint8_t* output,
    size_t output_length) {
    if((password == NULL && password_length != 0U) || (salt == NULL && salt_length != 0U) ||
       (output == NULL && output_length != 0U) || iterations == 0U ||
       (uint64_t)output_length > (uint64_t)UINT32_MAX * 32U) {
        return false;
    }

    uint8_t block_counter[4];
    uint8_t u[32];
    uint8_t accumulator[32];
    size_t produced = 0U;
    uint32_t block_index = 1U;

    while(produced < output_length) {
        ps_store_be32(block_counter, block_index);
        ps_hmac_sha256(password, password_length, salt, salt_length, block_counter, 4U, u);
        memcpy(accumulator, u, sizeof(accumulator));

        for(uint32_t iteration = 1U; iteration < iterations; ++iteration) {
            ps_hmac_sha256(password, password_length, u, sizeof(u), NULL, 0U, u);
            for(size_t i = 0; i < sizeof(accumulator); ++i) accumulator[i] ^= u[i];
        }

        const size_t remaining = output_length - produced;
        const size_t take = remaining < sizeof(accumulator) ? remaining : sizeof(accumulator);
        memcpy(&output[produced], accumulator, take);
        produced += take;
        if(produced < output_length) {
            if(block_index == UINT32_MAX) {
                ps_secure_zero(u, sizeof(u));
                ps_secure_zero(accumulator, sizeof(accumulator));
                return false;
            }
            ++block_index;
        }
    }

    ps_secure_zero(u, sizeof(u));
    ps_secure_zero(accumulator, sizeof(accumulator));
    ps_secure_zero(block_counter, sizeof(block_counter));
    return true;
}

void ps_secure_zero(void* data, size_t length) {
    volatile uint8_t* bytes = (volatile uint8_t*)data;
    while(length-- > 0U) *bytes++ = 0U;
}
