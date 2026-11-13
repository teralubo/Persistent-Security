# Flipper Persistent Security v0.1

Independent C11 proof of concept for a directional PIN gate intended for later
integration into Flipper Zero firmware. This repository contains no firmware
source, no firmware patches, and no hardware-specific memory driver.

## v0.1 contents

- Direction sequence API using UP, DOWN, LEFT, RIGHT values.
- PIN length of 16 to 64 directions. A 16-symbol sequence has only 32 bits of
  theoretical entropy; use a longer sequence where practical.
- Random 16-byte salt and PBKDF2-HMAC-SHA-256 verifier (120,000 iterations).
- Constant-time verifier comparison.
- Persistent exponential delay after wrong attempts: 1 second, doubling to a
  maximum of 1 hour. The failed-attempt count is stored with the credential and
  the full delay is applied again at each process start.
- Storage callbacks with an explicit all-or-nothing write contract.
- Protected-action API. An unconfigured device is allowed through to avoid
  bricking; configured, unauthenticated, corrupt, or unavailable storage denies
  access.
- PC-only in-memory storage adapter and unit tests.

The binary record is 96 bytes: fixed header and KDF parameters, failed-attempt
counter, salt, verifier, and an unkeyed SHA-256 integrity checksum. The PIN is
never written to the record.

## Build and run tests

Requires CMake 3.16+ and a C11 compiler.

    cmake -S . -B build
    cmake --build build
    ctest --test-dir build --output-on-failure

The tests cover:

- SHA-256 and PBKDF2 known-answer vectors, including the production iteration count.
- Missing configuration, setup, restarts, wrong PINs, and persistent backoff.
- A simulated power interruption before atomic commit and storage failures.
- Invalid direction values and corrupt records.

## Firmware integration outline

The module deliberately leaves button input, user interface, random-number
generation, monotonic time, and persistent storage to its caller.

1. Implement PsStore over an approved storage region. Its writer must provide
   old-or-new whole-record semantics after reset or power loss. A plain
   overwrite that can leave a torn record does not satisfy this contract.
2. Supply PsRandom.fill from the firmware's cryptographically suitable random
   source. Do not use a predictable seed or the PC test adapter in firmware.
3. Collect direction events in the UI and pass only the enum sequence to
   ps_security_configure or ps_security_verify. Clear the UI's input buffer
   after use.
4. Create and initialize one PsSecurity object during each boot. Authentication
   is held only in that object's RAM and is therefore cleared on reboot.
5. Call ps_security_allows_protected_action at every firmware entry point that
   must be gated. This project does not itself protect the launcher, RPC/qFlipper,
   SD operations, GPIO, USB, or any firmware service.

A future internal-Flash adapter must be based on a verified device memory map,
linker symbols, firmware ownership rules, and a power-loss-safe write design.
This project does not select an address, erase a page, change Option Bytes, or
implement a STM32 Flash driver.

## Security limits

- This is a PoC, not a security-reviewed product. The C implementation of
  SHA-256, HMAC, and PBKDF2 needs independent review and additional test vectors
  before production use.
- Directional symbols provide only two bits each. Even the minimum 16-symbol
  PIN has a small search space for a determined offline attacker. PBKDF2 raises
  the cost per guess but does not add entropy; the iteration count must be
  benchmarked on the target MCU and balanced against startup and input latency.
- The record checksum detects accidental corruption. It is not a MAC: an
  attacker who can rewrite storage can replace the verifier or reset the
  attempt counter. A secure element or protected hardware secret would be
  needed to authenticate stored records against a physical attacker.
- Rate limiting depends on durable atomic storage. If a backend loses or rolls
  back a failed-attempt write, an attacker may retry sooner. Backend failure
  denies access for the current process lifetime.
- This API is a software gate only. Firmware that omits a check can be called
  around. Replacing firmware, using a debug interface, or otherwise controlling
  the device can bypass this protection. No protection is claimed for RPC, SD,
  GPIO, or boot/recovery paths.
- An absent record is treated as not yet configured and is allowed through. A backend that cannot distinguish a never-provisioned device from a deleted configured record can therefore be bypassed by deleting the record; firmware integration must account for provisioning state if this threat matters.
- Corrupt or unreadable configured data fails closed. Recovery must be handled
  by a separately designed, documented maintenance procedure; v0.1 provides no
  PIN reset or disable operation.
- Battery-removal persistence is an expected property of a correct durable
  backend, not verified by the PC adapter or by a hardware test.

## License

MIT. See LICENSE.

## Git workflow

Clone the repository and work on the main branch:

    git clone https://github.com/T4r4L/Persistent-Security.git
    cd Persistent-Security
    git switch main

Check changes and commit them:

    git status
    git add .
    git commit -m "Describe the change"
    git push origin main

For isolated work, create a feature branch with git switch -c feature/short-name,
then push it with git push --set-upstream origin feature/short-name.
