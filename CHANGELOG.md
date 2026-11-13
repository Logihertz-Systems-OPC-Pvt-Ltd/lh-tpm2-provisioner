# Changelog

All notable changes to `lh-tpm2-provisioner` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-13

### Added
- **Core Cryptographic Primitives (`sha256_hmac.c`, `sha256_hmac.h`)**:
  - Clean-room FIPS 180-4 SHA-256 state machine implementation (`lh_sha256_init`, `lh_sha256_update`, `lh_sha256_final`).
  - RFC 2104 HMAC-SHA256 keyed-hash message authentication code.
  - Constant-time memory comparison (`lh_constant_time_memcmp`) to prevent timing side-channel attacks.
  - Volatile memory zeroization (`lh_secure_zero_memory`) to resist dead-store compiler elimination.
  - Hexadecimal encoding and decoding utilities.
- **ISO/IEC 11889 PCR & Policy Engine (`pcr_policy.c`, `pcr_policy.h`)**:
  - Full 24-register PCR bank state machine with standard reset vectors (zeroes for PCR $0\dots 15, 23$; $0\text{xFF}$ for dynamic DRTM registers $17\dots 22$).
  - Non-invertible `TPM2_PCR_Extend` operation ($\text{PCR}_{\text{new}} = \text{SHA-256}(\text{PCR}_{\text{old}} \parallel \text{SHA-256}(\text{measurement}))$).
  - Multi-register composite digest calculation ($D_{\text{PCR}}$) for arbitrary 24-bit selection masks.
  - Canonical `TPM2_PolicyPCR` (`0x0000017F`) trial session digest calculator.
  - `TPMS_ATTEST` quote structure synthesizer with standard TCG magic constant `0xFF544347` (`"\xFFTCG"`), freshness nonce verification, and AIK signature verification.
- **PCR-Bound Secret Sealing Engine (`seal_engine.c`, `seal_engine.h`)**:
  - KeyedHash secret sealing bound to `PolicyPCR` and optional PIN authentication values.
  - Counter-mode SHA-256 encryption with 16-byte nonce and HMAC-SHA256 authenticated integrity tags.
  - Authenticated unsealing with live PCR bank state verification and evil-maid tamper rejection.
- **Zero-Dependency JSON Parser (`json_parser.c`, `json_parser.h`)**:
  - Lightweight parser for TPM 2.0 provisioning policy manifests and boot event logs.
- **10-Rule Hardware TPM 2.0 Posture Auditor (`tpm2_auditor.c`, `tpm2_auditor.h`)**:
  - `LH-TPM-001`: Legacy SHA-1 PCR bank active (Critical, 25 pts, CWE-328).
  - `LH-TPM-002`: Incomplete PCR sealing policy for disk encryption (Critical, 25 pts, CWE-345).
  - `LH-TPM-003`: Empty or default TPM 2.0 hierarchy authorization values (Critical, 25 pts, CWE-306).
  - `LH-TPM-004`: Weak Dictionary Attack lockout parameters (High, 10 pts, CWE-307).
  - `LH-TPM-005`: Unencrypted CPU-to-TPM SPI/I2C bus sessions (High, 10 pts, CWE-319).
  - `LH-TPM-006`: Weak Storage Root Key or AIK cryptographic template (High, 10 pts, CWE-326).
  - `LH-TPM-007`: Remote attestation quote missing nonce or EK cert check (High, 10 pts, CWE-294).
  - `LH-TPM-008`: NVRAM anti-rollback counter index unlocked (Medium, 4 pts, CWE-276).
  - `LH-TPM-009`: Unbrokered /dev/tpm0 device access used (Medium, 4 pts, CWE-250).
  - `LH-TPM-010`: Missing TCG Binary BIOS Event Log replay verification (Low, 1 pt, CWE-778).
- **Multi-Format Exporters & CLI (`exporters.c`, `main.c`)**:
  - Colorized ANSI terminal tables with posture score banners.
  - Canonical deterministic JSON exporter.
  - OASIS SARIF v2.1.0 output for CI/CD DevSecOps.
  - Subcommands: `scan`, `pcr-extend`, `policy-pcr`, `seal`, `unseal`, `quote`, `--version`, `--help`.
- **Zero-Dependency C11 Build**:
  - Pure C11 codebase targeting both GCC and Clang with `-Wall -Wextra -Werror -pedantic`.
