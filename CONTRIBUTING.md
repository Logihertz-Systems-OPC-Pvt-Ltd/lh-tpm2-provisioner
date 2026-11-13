# Contributing to Logihertz TPM 2.0 Provisioning Engine (`lh-tpm2-provisioner`)

Thank you for contributing to `lh-tpm2-provisioner`. This project provides hardware TPM 2.0 cryptographic calculation, policy synthesis, secret sealing, and posture auditing for high-assurance Linux systems.

---

## Architectural & Engineering Standards

1. **Zero External Dependencies**:
   - The entire codebase must compile cleanly under standard C11 (`-std=c11 -O2 -Wall -Wextra -Werror -pedantic`).
   - Only POSIX/C standard library headers (`<stdint.h>`, `<stdbool.h>`, `<stddef.h>`, `<stdlib.h>`, `<string.h>`, `<stdio.h>`) are permitted. External cryptographic or JSON libraries (OpenSSL, Libgcrypt, cJSON, Jansson) are strictly forbidden.
2. **Cryptographic Rigor & Constant-Time Guarantees**:
   - Sensitive memory comparisons (such as HMAC verification tags and authentication PINs) must use constant-time operations (`lh_constant_time_memcmp`).
   - Plaintext secrets, derived keys, and scratch buffers must be sanitized using volatile memory zeroization (`lh_secure_zero_memory`) before returning.
3. **TPM 2.0 Specification Compliance**:
   - All extend calculations, composite digests, and trial session digests must conform to ISO/IEC 11889 Parts 1–4 and TCG TPM 2.0 Library Specifications.
   - Magic constant `TPM_GENERATED_VALUE = 0xFF544347` (`"\xFFTCG"`) and command code `TPM_CC_PolicyPCR = 0x0000017F` must be accurately respected.

---

## Development & Test Workflow

### Compilation
```bash
# Build the production CLI binary (bin/lh-tpm2)
make CC=gcc

# Build and execute the test runner
make test
```

### Formatting & Cleanliness
- Code must compile with `-Wall -Wextra -Werror -pedantic` with zero warnings under both `gcc` and `clang`.
- No dynamic memory leaks; all allocations must have deterministic lifetimes.

---

## Pull Request Guidelines

1. Accompany every cryptographic primitive or policy parser update with deterministic test assertions in `tests/test_runner.c`.
2. Ensure clean builds across both GCC and Clang compilers.
3. All contributions are licensed under the Apache License 2.0.
