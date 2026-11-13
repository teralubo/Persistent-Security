#include "pc_store.h"
#include "ps_crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expression)                                                                    \
    do {                                                                                     \
        if(!(expression)) {                                                                  \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expression);            \
            return false;                                                                    \
        }                                                                                    \
    } while(0)

static const PsDirection correct_pin[] = {
    PsDirectionUp,    PsDirectionRight, PsDirectionDown, PsDirectionLeft,
    PsDirectionUp,    PsDirectionDown,  PsDirectionRight, PsDirectionLeft,
    PsDirectionDown,  PsDirectionUp,    PsDirectionLeft,  PsDirectionRight,
    PsDirectionUp,    PsDirectionLeft,  PsDirectionDown,  PsDirectionRight,
};
static const PsDirection wrong_pin[] = {
    PsDirectionUp,    PsDirectionRight, PsDirectionDown, PsDirectionLeft,
    PsDirectionUp,    PsDirectionDown,  PsDirectionRight, PsDirectionLeft,
    PsDirectionDown,  PsDirectionUp,    PsDirectionLeft,  PsDirectionRight,
    PsDirectionDown,  PsDirectionLeft,  PsDirectionDown,  PsDirectionRight,
};

static bool bytes_equal_hex(const uint8_t* bytes, size_t length, const char* expected) {
    static const char hex[] = "0123456789abcdef";
    if(strlen(expected) != length * 2U) return false;
    for(size_t i = 0; i < length; ++i) {
        if(hex[bytes[i] >> 4U] != expected[i * 2U] ||
           hex[bytes[i] & 0x0fU] != expected[i * 2U + 1U]) {
            return false;
        }
    }
    return true;
}

static bool test_crypto_vectors(void) {
    uint8_t digest[32];
    ps_sha256((const uint8_t*)"abc", 3U, digest);
    CHECK(bytes_equal_hex(
        digest,
        sizeof(digest),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));

    const uint8_t password[] = "password";
    const uint8_t salt[] = "salt";
    uint8_t derived[32];
    CHECK(ps_pbkdf2_sha256(
        password, sizeof(password) - 1U, salt, sizeof(salt) - 1U, 1U, derived, sizeof(derived)));
    CHECK(bytes_equal_hex(
        derived,
        sizeof(derived),
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"));
    CHECK(ps_pbkdf2_sha256(
        password, sizeof(password) - 1U, salt, sizeof(salt) - 1U, 2U, derived, sizeof(derived)));
    CHECK(bytes_equal_hex(
        derived,
        sizeof(derived),
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"));

    const uint8_t directional_pin[PS_PIN_MIN_LENGTH] = {
        0U, 3U, 1U, 2U, 0U, 1U, 3U, 2U, 1U, 0U, 2U, 3U, 0U, 2U, 1U, 3U,
    };
    const uint8_t directional_salt[PS_SALT_SIZE] = {
        37U, 74U, 111U, 148U, 185U, 222U, 3U, 40U, 77U, 114U, 151U, 188U, 225U, 6U, 43U, 80U,
    };
    CHECK(ps_pbkdf2_sha256(
        directional_pin,
        sizeof(directional_pin),
        directional_salt,
        sizeof(directional_salt),
        PS_KDF_ITERATIONS,
        derived,
        sizeof(derived)));
    CHECK(bytes_equal_hex(
        derived,
        sizeof(derived),
        "df1780866415dfdb3997bd77c209ed0058e4e2ce7455ecfbcf7c7aa76740ab49"));
    return true;
}

static bool test_unconfigured_and_configure(void) {
    PsPcStore backing;
    ps_pc_store_init(&backing);
    PsSecurity security;
    CHECK(ps_security_init(&security, ps_pc_store_interface(&backing), 0U) ==
          PsStatusNotConfigured);
    CHECK(ps_security_allows_protected_action(&security));
    CHECK(!ps_security_is_authenticated(&security));

    CHECK(ps_security_configure(
              &security,
              ps_pc_random_interface(&backing),
              correct_pin,
              PS_PIN_MIN_LENGTH - 1U) == PsStatusBadArgument);
    PsDirection invalid_pin[PS_PIN_MIN_LENGTH];
    memcpy(invalid_pin, correct_pin, sizeof(invalid_pin));
    invalid_pin[3] = (PsDirection)4;
    CHECK(ps_security_configure(
              &security,
              ps_pc_random_interface(&backing),
              invalid_pin,
              PS_PIN_MIN_LENGTH) == PsStatusBadArgument);
    CHECK(ps_security_configure(
              &security,
              ps_pc_random_interface(&backing),
              correct_pin,
              sizeof(correct_pin) / sizeof(correct_pin[0])) == PsStatusReady);
    CHECK(backing.exists);
    static const uint8_t encoded_pin[PS_PIN_MIN_LENGTH] = {
        0U, 3U, 1U, 2U, 0U, 1U, 3U, 2U, 1U, 0U, 2U, 3U, 0U, 2U, 1U, 3U,
    };
    CHECK(memcmp(&backing.record[32], encoded_pin, sizeof(encoded_pin)) != 0);
    CHECK(!ps_security_allows_protected_action(&security));
    CHECK(ps_security_configure(
              &security,
              ps_pc_random_interface(&backing),
              correct_pin,
              sizeof(correct_pin) / sizeof(correct_pin[0])) == PsStatusAlreadyConfigured);
    return true;
}

static bool test_restart_wrong_pin_backoff_and_authentication(void) {
    PsPcStore backing;
    ps_pc_store_init(&backing);
    PsStore store = ps_pc_store_interface(&backing);
    PsSecurity first;
    CHECK(ps_security_init(&first, store, 0U) == PsStatusNotConfigured);
    CHECK(ps_security_configure(
              &first,
              ps_pc_random_interface(&backing),
              correct_pin,
              sizeof(correct_pin) / sizeof(correct_pin[0])) == PsStatusReady);

    PsSecurity after_restart;
    CHECK(ps_security_init(&after_restart, store, 0U) == PsStatusReady);
    CHECK(!ps_security_is_authenticated(&after_restart));
    CHECK(!ps_security_allows_protected_action(&after_restart));

    uint64_t retry = 0U;
    CHECK(ps_security_verify(
              &after_restart,
              wrong_pin,
              sizeof(wrong_pin) / sizeof(wrong_pin[0]),
              100U,
              &retry) == PsStatusWrongPin);
    CHECK(retry == 1000U);
    CHECK(ps_security_verify(
              &after_restart,
              correct_pin,
              sizeof(correct_pin) / sizeof(correct_pin[0]),
              500U,
              &retry) == PsStatusLocked);
    CHECK(retry == 600U);

    PsSecurity after_power_cycle;
    CHECK(ps_security_init(&after_power_cycle, store, 0U) == PsStatusReady);
    CHECK(ps_security_verify(
              &after_power_cycle,
              correct_pin,
              sizeof(correct_pin) / sizeof(correct_pin[0]),
              0U,
              &retry) == PsStatusLocked);
    CHECK(retry == 1000U);
    CHECK(ps_security_verify(
              &after_power_cycle,
              correct_pin,
              sizeof(correct_pin) / sizeof(correct_pin[0]),
              1000U,
              &retry) == PsStatusReady);
    CHECK(ps_security_is_authenticated(&after_power_cycle));
    CHECK(ps_security_allows_protected_action(&after_power_cycle));

    PsSecurity next_boot;
    CHECK(ps_security_init(&next_boot, store, 0U) == PsStatusReady);
    CHECK(!ps_security_is_authenticated(&next_boot));
    CHECK(!ps_security_allows_protected_action(&next_boot));
    return true;
}

static bool test_atomic_write_failure_and_corruption(void) {
    PsPcStore backing;
    ps_pc_store_init(&backing);
    PsStore store = ps_pc_store_interface(&backing);
    PsSecurity security;
    CHECK(ps_security_init(&security, store, 0U) == PsStatusNotConfigured);
    CHECK(ps_security_configure(
              &security,
              ps_pc_random_interface(&backing),
              correct_pin,
              sizeof(correct_pin) / sizeof(correct_pin[0])) == PsStatusReady);

    uint8_t committed[PS_RECORD_SIZE];
    memcpy(committed, backing.record, sizeof(committed));
    /* Simulate power loss before the atomic commit: old record must survive. */
    backing.fail_next_write = true;
    uint64_t retry = 0U;
    CHECK(ps_security_verify(
              &security,
              wrong_pin,
              sizeof(wrong_pin) / sizeof(wrong_pin[0]),
              0U,
              &retry) == PsStatusStoreError);
    CHECK(!ps_security_allows_protected_action(&security));
    CHECK(memcmp(committed, backing.record, sizeof(committed)) == 0);

    PsSecurity after_failed_commit;
    CHECK(ps_security_init(&after_failed_commit, store, 0U) == PsStatusReady);
    CHECK(ps_security_verify(
              &after_failed_commit,
              correct_pin,
              sizeof(correct_pin) / sizeof(correct_pin[0]),
              0U,
              &retry) == PsStatusReady);

    backing.record[20] ^= 1U;
    PsSecurity corrupt;
    CHECK(ps_security_init(&corrupt, store, 0U) == PsStatusCorruptRecord);
    CHECK(!ps_security_allows_protected_action(&corrupt));
    CHECK(!ps_security_is_authenticated(&corrupt));
    return true;
}

static bool test_storage_read_failure_fails_closed(void) {
    PsPcStore backing;
    ps_pc_store_init(&backing);
    PsStore store = ps_pc_store_interface(&backing);
    PsSecurity security;
    CHECK(ps_security_init(&security, store, 0U) == PsStatusNotConfigured);
    CHECK(ps_security_configure(
              &security,
              ps_pc_random_interface(&backing),
              correct_pin,
              sizeof(correct_pin) / sizeof(correct_pin[0])) == PsStatusReady);

    backing.fail_next_read = true;
    PsSecurity unavailable;
    CHECK(ps_security_init(&unavailable, store, 0U) == PsStatusStoreError);
    CHECK(!ps_security_allows_protected_action(&unavailable));
    return true;
}

int main(void) {
    const struct {
        const char* name;
        bool (*run)(void);
    } tests[] = {
        {"crypto vectors", test_crypto_vectors},
        {"unconfigured and configure", test_unconfigured_and_configure},
        {"restart, wrong PIN, backoff, authentication", test_restart_wrong_pin_backoff_and_authentication},
        {"atomic write failure and corruption", test_atomic_write_failure_and_corruption},
        {"storage read failure fails closed", test_storage_read_failure_fails_closed},
    };

    unsigned failures = 0U;
    for(size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        const bool passed = tests[i].run();
        printf("%s: %s\n", passed ? "PASS" : "FAIL", tests[i].name);
        if(!passed) ++failures;
    }
    return failures == 0U ? EXIT_SUCCESS : EXIT_FAILURE;
}
