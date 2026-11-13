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
- Invalid direction values, corrupt records, and authenticated PIN changes across restart.

## Install and use on a real Flipper Zero

### What this version can be installed as

This repository currently contains a C library and PC tests, not a ready-to-install
Flipper app or firmware package. It does not create a FAP. Copying files to the
microSD card, using qFlipper to copy them, or using ufbt to launch an app will
not protect the device: a standalone app cannot gate the launcher or firmware
services. The integration steps below require firmware source changes and a
device-specific storage adapter. No ready-to-flash image is published here.

### Prepare a firmware checkout

When a firmware integration has been prepared, start from the official Flipper
Zero firmware repository (not a Momentum checkout):

    git clone --recursive https://github.com/flipperdevices/flipperzero-firmware.git
    cd flipperzero-firmware
    git switch -c persistent-security-integration

This repository does not yet contain a patch that can be applied to that
checkout. A firmware integrator must add include/ps_security.h, src/ps_security.c,
src/ps_crypto.c, and src/ps_crypto.h to a firmware build target, then implement
the persistent storage adapter, the PIN user interface, and checks at every
protected entry point. Do not include tests/pc_store.c in device firmware. The
storage adapter must use an approved persistent region and provide atomic
old-record-or-new-record writes; this project supplies no STM32 Flash driver or
memory address.

### Build and install the integrated firmware

After those integration changes exist and have been reviewed, build the firmware
with the Flipper Build Tool:

    ./fbt

To build, upload, and install the USB update package on a normally booted,
working Flipper Zero:

    ./fbt flash_usb

On Windows, use the repository's command wrapper:

    .\fbt.cmd
    .\fbt.cmd flash_usb

The official firmware documentation describes these FBT targets and platform
setup: [Flipper firmware build guide](https://github.com/flipperdevices/flipperzero-firmware/blob/dev/ReadMe.md)
and [FBT reference](https://github.com/flipperdevices/flipperzero-firmware/blob/dev/documentation/fbt.md).
The device must be running working firmware for USB updater installation. This
project has not been integrated, built, or installed on a Flipper; the commands
above alone will build the official firmware without Persistent Security.

### Set the first directional PIN

The PIN is a sequence of 16–64 direction presses (UP, DOWN, LEFT, RIGHT), not a
numeric keypad PIN. The library has no on-device setup screen yet. After a
firmware UI and adapter have been written:

1. On first boot, call ps_security_init with the storage adapter and monotonic
   time. PsStatusNotConfigured means no credential record was found.
2. In a setup screen, collect the sequence twice and have the user confirm it.
   Check that both entries match and contain only direction values.
3. Call ps_security_configure with the sequence and a cryptographically suitable
   random provider. A successful write returns PsStatusReady but does not mark
   the user authenticated. Prompt for the sequence again and call
   ps_security_verify; only a successful verification opens the session.
4. Check ps_security_allows_protected_action before every protected action.

Until the setup UI and durable adapter are integrated, there is no way to set a
PIN on the physical device from this repository alone.

### Unlock and change the PIN

At each boot, initialize a fresh PsSecurity object. After a configured record is
loaded, authentication is false. The device UI should request the directional
sequence, call ps_security_verify with the current monotonic time, and allow
protected actions only after it returns PsStatusReady and
ps_security_allows_protected_action returns true. Wrong attempts return
PsStatusWrongPin; PsStatusLocked includes the remaining delay. The delay and
failed-attempt count survive restarts only when the firmware adapter provides
the required durable atomic storage.

To change the PIN in an integrated build:

1. Enter the current sequence and verify it successfully in this boot session.
2. Collect the new sequence twice in the UI and check that the entries match.
3. Call ps_security_change_pin with the new sequence and random provider. This
   API requires the current session to be authenticated and persists a new salt
   and verifier atomically. On success, the session remains authenticated.
4. If the device reboots before the change is committed, the adapter must expose
   either the old complete record or the new complete record.

The library API supports this authenticated change, but the repository does not
include a PIN screen or a user-facing change menu. Lost-PIN reset and disable
flows are not implemented. Do not edit the stored binary record manually.

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
