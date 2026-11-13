#include "ps_security.h"
#include "ps_crypto.h"

#include <string.h>

#define PS_RECORD_VERSION 1U
#define PS_BACKOFF_BASE_MS 1000U
#define PS_BACKOFF_MAX_MS 3600000U

static bool ps_pin_is_valid(const PsDirection* pin, size_t pin_length) {
    if(pin == NULL || pin_length < PS_PIN_MIN_LENGTH || pin_length > PS_PIN_MAX_LENGTH) {
        return false;
    }
    for(size_t i = 0; i < pin_length; ++i) {
        if(!ps_direction_is_valid(pin[i])) return false;
    }
    return true;
}

bool ps_direction_is_valid(PsDirection direction) {
    return direction >= PsDirectionUp && direction <= PsDirectionRight;
}

static uint32_t ps_read_be32(const uint8_t* input) {
    return ((uint32_t)input[0] << 24U) | ((uint32_t)input[1] << 16U) |
           ((uint32_t)input[2] << 8U) | (uint32_t)input[3];
}

static void ps_write_be32(uint8_t* output, uint32_t value) {
    output[0] = (uint8_t)(value >> 24U);
    output[1] = (uint8_t)(value >> 16U);
    output[2] = (uint8_t)(value >> 8U);
    output[3] = (uint8_t)value;
}

static bool ps_constant_time_equal(const uint8_t* left, const uint8_t* right, size_t size) {
    uint8_t difference = 0U;
    for(size_t i = 0; i < size; ++i) difference |= (uint8_t)(left[i] ^ right[i]);
    return difference == 0U;
}

static uint64_t ps_backoff_ms(uint32_t failed_attempts) {
    if(failed_attempts == 0U) return 0U;
    uint64_t delay = PS_BACKOFF_BASE_MS;
    for(uint32_t i = 1U; i < failed_attempts && delay < PS_BACKOFF_MAX_MS; ++i) {
        delay *= 2U;
        if(delay > PS_BACKOFF_MAX_MS) delay = PS_BACKOFF_MAX_MS;
    }
    return delay;
}

static uint64_t ps_add_saturating(uint64_t left, uint64_t right) {
    if(UINT64_MAX - left < right) return UINT64_MAX;
    return left + right;
}

static void ps_update_record_checksum(uint8_t record[PS_RECORD_SIZE]) {
    ps_sha256(record, 64U, &record[64U]);
}

static bool ps_validate_record(const uint8_t record[PS_RECORD_SIZE]) {
    static const uint8_t magic[4] = {'F', 'P', 'S', '1'};
    uint8_t checksum[PS_VERIFIER_SIZE];
    const bool header_valid =
        memcmp(record, magic, sizeof(magic)) == 0 && record[4] == PS_RECORD_VERSION &&
        record[5] == 0U && record[6] == 0U && record[7] == 0U &&
        ps_read_be32(&record[8]) == PS_KDF_ITERATIONS;
    ps_sha256(record, 64U, checksum);
    const bool checksum_valid = ps_constant_time_equal(checksum, &record[64U], sizeof(checksum));
    ps_secure_zero(checksum, sizeof(checksum));
    return header_valid && checksum_valid;
}

static bool ps_derive_verifier(
    const PsDirection* pin,
    size_t pin_length,
    const uint8_t salt[PS_SALT_SIZE],
    uint8_t output[PS_VERIFIER_SIZE]) {
    uint8_t encoded[PS_PIN_MAX_LENGTH];
    for(size_t i = 0; i < pin_length; ++i) encoded[i] = (uint8_t)pin[i];
    const bool result = ps_pbkdf2_sha256(
        encoded, pin_length, salt, PS_SALT_SIZE, PS_KDF_ITERATIONS, output, PS_VERIFIER_SIZE);
    ps_secure_zero(encoded, sizeof(encoded));
    return result;
}

static PsStatus ps_persist_failed_attempts(PsSecurity* security, uint32_t failed_attempts) {
    ps_write_be32(&security->record[12], failed_attempts);
    ps_update_record_checksum(security->record);
    if(!security->store.write_record_atomic(
           security->store.context, security->record, sizeof(security->record))) {
        security->faulted = true;
        security->authenticated = false;
        return PsStatusStoreError;
    }
    security->failed_attempts = failed_attempts;
    return PsStatusReady;
}

PsStatus ps_security_init(PsSecurity* security, PsStore store, uint64_t monotonic_ms) {
    if(security == NULL || store.read_record == NULL || store.write_record_atomic == NULL) {
        return PsStatusBadArgument;
    }

    memset(security, 0, sizeof(*security));
    security->store = store;
    const PsStoreResult read_result =
        store.read_record(store.context, security->record, sizeof(security->record));
    if(read_result == PsStoreNotFound) return PsStatusNotConfigured;
    if(read_result != PsStoreOk) {
        security->faulted = true;
        return PsStatusStoreError;
    }
    if(!ps_validate_record(security->record)) {
        security->configured = true;
        security->faulted = true;
        return PsStatusCorruptRecord;
    }

    security->configured = true;
    security->failed_attempts = ps_read_be32(&security->record[12]);
    security->next_attempt_ms =
        ps_add_saturating(monotonic_ms, ps_backoff_ms(security->failed_attempts));
    return PsStatusReady;
}

PsStatus ps_security_configure(
    PsSecurity* security,
    PsRandom random,
    const PsDirection* pin,
    size_t pin_length) {
    if(security == NULL || random.fill == NULL || !ps_pin_is_valid(pin, pin_length)) {
        return PsStatusBadArgument;
    }
    if(security->faulted) return PsStatusStoreError;
    if(security->configured) return PsStatusAlreadyConfigured;

    uint8_t record[PS_RECORD_SIZE] = {0U};
    record[0] = 'F';
    record[1] = 'P';
    record[2] = 'S';
    record[3] = '1';
    record[4] = PS_RECORD_VERSION;
    ps_write_be32(&record[8], PS_KDF_ITERATIONS);

    if(!random.fill(random.context, &record[16], PS_SALT_SIZE)) {
        ps_secure_zero(record, sizeof(record));
        return PsStatusCryptoError;
    }
    if(!ps_derive_verifier(pin, pin_length, &record[16], &record[32])) {
        ps_secure_zero(record, sizeof(record));
        return PsStatusCryptoError;
    }
    ps_update_record_checksum(record);
    if(!security->store.write_record_atomic(
           security->store.context, record, sizeof(record))) {
        security->faulted = true;
        ps_secure_zero(record, sizeof(record));
        return PsStatusStoreError;
    }

    memcpy(security->record, record, sizeof(record));
    security->configured = true;
    security->failed_attempts = 0U;
    security->authenticated = false;
    security->next_attempt_ms = 0U;
    ps_secure_zero(record, sizeof(record));
    return PsStatusReady;
}

PsStatus ps_security_verify(
    PsSecurity* security,
    const PsDirection* pin,
    size_t pin_length,
    uint64_t monotonic_ms,
    uint64_t* retry_after_ms) {
    if(retry_after_ms != NULL) *retry_after_ms = 0U;
    if(security == NULL || !ps_pin_is_valid(pin, pin_length)) return PsStatusBadArgument;
    if(security->faulted) return PsStatusStoreError;
    if(!security->configured) return PsStatusNotConfigured;
    if(security->authenticated) return PsStatusReady;
    if(monotonic_ms < security->next_attempt_ms) {
        if(retry_after_ms != NULL) *retry_after_ms = security->next_attempt_ms - monotonic_ms;
        return PsStatusLocked;
    }

    uint8_t candidate[PS_VERIFIER_SIZE];
    if(!ps_derive_verifier(pin, pin_length, &security->record[16], candidate)) {
        ps_secure_zero(candidate, sizeof(candidate));
        return PsStatusCryptoError;
    }
    const bool matches = ps_constant_time_equal(candidate, &security->record[32], sizeof(candidate));
    ps_secure_zero(candidate, sizeof(candidate));

    if(matches) {
        if(ps_persist_failed_attempts(security, 0U) != PsStatusReady) return PsStatusStoreError;
        security->authenticated = true;
        security->next_attempt_ms = 0U;
        return PsStatusReady;
    }

    const uint32_t next_failures =
        security->failed_attempts == UINT32_MAX ? UINT32_MAX : security->failed_attempts + 1U;
    if(ps_persist_failed_attempts(security, next_failures) != PsStatusReady) {
        return PsStatusStoreError;
    }
    security->next_attempt_ms = ps_add_saturating(monotonic_ms, ps_backoff_ms(next_failures));
    if(retry_after_ms != NULL) *retry_after_ms = security->next_attempt_ms - monotonic_ms;
    return PsStatusWrongPin;
}

bool ps_security_is_authenticated(const PsSecurity* security) {
    return security != NULL && security->configured && !security->faulted &&
           security->authenticated;
}

bool ps_security_allows_protected_action(const PsSecurity* security) {
    if(security == NULL || security->faulted) return false;
    return !security->configured || security->authenticated;
}
