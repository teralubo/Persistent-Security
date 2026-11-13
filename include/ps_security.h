#ifndef PS_SECURITY_H
#define PS_SECURITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PS_PIN_MIN_LENGTH 16U
#define PS_PIN_MAX_LENGTH 64U
#define PS_SALT_SIZE 16U
#define PS_VERIFIER_SIZE 32U
#define PS_RECORD_SIZE 96U
#define PS_KDF_ITERATIONS 120000U

typedef enum {
    PsDirectionUp = 0,
    PsDirectionDown = 1,
    PsDirectionLeft = 2,
    PsDirectionRight = 3,
} PsDirection;

typedef enum {
    PsStoreOk = 0,
    PsStoreNotFound,
    PsStoreError,
} PsStoreResult;

/* read_record must fill exactly PS_RECORD_SIZE bytes on success.
   write_record_atomic must leave either the old full record or the new full
   record visible after any failure or power loss. */
typedef struct {
    void* context;
    PsStoreResult (*read_record)(void* context, uint8_t* out, size_t size);
    bool (*write_record_atomic)(void* context, const uint8_t* data, size_t size);
} PsStore;

typedef bool (*PsRandomFill)(void* context, uint8_t* out, size_t size);
typedef struct {
    void* context;
    PsRandomFill fill;
} PsRandom;

typedef enum {
    PsStatusReady = 0,
    PsStatusNotConfigured,
    PsStatusBadArgument,
    PsStatusAlreadyConfigured,
    PsStatusWrongPin,
    PsStatusLocked,
    PsStatusCorruptRecord,
    PsStatusStoreError,
    PsStatusCryptoError,
} PsStatus;

/* Public only so firmware can allocate the object without a heap. Treat every
   field as private; initialize with ps_security_init before other calls. */
typedef struct {
    PsStore store;
    uint64_t next_attempt_ms;
    uint32_t failed_attempts;
    bool configured;
    bool authenticated;
    bool faulted;
    uint8_t record[PS_RECORD_SIZE];
} PsSecurity;

PsStatus ps_security_init(
    PsSecurity* security,
    PsStore store,
    uint64_t monotonic_ms);

PsStatus ps_security_configure(
    PsSecurity* security,
    PsRandom random,
    const PsDirection* pin,
    size_t pin_length);

PsStatus ps_security_verify(
    PsSecurity* security,
    const PsDirection* pin,
    size_t pin_length,
    uint64_t monotonic_ms,
    uint64_t* retry_after_ms);

/* True only after verification in this process lifetime. */
bool ps_security_is_authenticated(const PsSecurity* security);

/* Unconfigured devices are allowed through, so an absent record cannot brick
   a device. A configured or corrupt record requires successful authentication. */
bool ps_security_allows_protected_action(const PsSecurity* security);

/* Returns true for direction values in the public enum range. */
bool ps_direction_is_valid(PsDirection direction);

#ifdef __cplusplus
}
#endif

#endif
