# lh-tpm2-provisioner (`lh-tpm2`)

**Production-Grade, Zero-Dependency C11 Hardware TPM 2.0 Provisioning Engine, PCR Policy Calculator, LUKS Secret Sealer, Attestation Quote Verifier, and 10-Rule Security Posture Auditor**

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-tpm2-provisioner/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-tpm2-provisioner/actions/workflows/ci.yml)
[![Standard](https://img.shields.io/badge/standard-C11-blue.svg)](https://en.wikipedia.org/wiki/C11_(C_standard_revision))
[![TCG Specification](https://img.shields.io/badge/TCG-TPM%202.0%20ISO%2FIEC%2011889-success.svg)](https://trustedcomputinggroup.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## 1. Overview & Architectural Mission

`lh-tpm2-provisioner` (`bin/lh-tpm2`) is an enterprise-grade, zero-dependency C11 utility engineered for embedded Linux platforms, sovereign appliances, edge AI gateways, and industrial control systems requiring verifiable hardware-rooted trust.

Adhering strictly to **TCG TPM 2.0 / ISO/IEC 11889** specifications, `lh-tpm2` operates without any external cryptographic libraries (clean-room FIPS 180-4 SHA-256 and RFC 2104 HMAC-SHA256 implementations) or third-party JSON parsers. It provides:

1. **Deterministic PCR State Progression**: Full 24-register SHA-256 PCR bank simulation, measurement event logging, and TCG reset-state management ($0 \dots 15, 23 = \texttt{0x00}$, DRTM $17 \dots 22 = \texttt{0xFF}$).
2. **PolicyPCR Trial Session Math**: Precise calculation of composite PCR digests and trial session `TPM2_PolicyPCR` (`TPM_CC_PolicyPCR = 0x0000017F`) digests for authorization policies.
3. **PCR-Bound Key Sealing Engine**: Counter-mode authenticated encryption of disk encryption keys (LUKS master keys) bound to composite platform states and optional user PINs.
4. **Remote Attestation Engine**: Generation and verification of `TPMS_ATTEST` (`0xFF544347` / `0x8018`) quotes signed under Attestation Identity Keys (AIK).
5. **10-Rule Security Posture Auditor**: Automated static and runtime policy auditing (`LH-TPM-001` through `LH-TPM-010`) with output in ANSI tables, Canonical JSON, and OASIS SARIF v2.1.0.

```
+----------------------------------------------------------------------------------------------------+
|                                    LOGIHERTZ TPM 2.0 ARCHITECTURE                                  |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|    +-----------------------------+           +------------------------------+                      |
|    |  Firmware / Boot Sequence   |           |  TCG Binary Event Log        |                      |
|    |  (CRTM, UEFI, GRUB, UKI)    |           |  /sys/kernel/security/tpm0   |                      |
|    +--------------+--------------+           +--------------+---------------+                      |
|                   |                                         |                                      |
|                   v                                         v                                      |
|    +------------------------------------------------------------------------+                      |
|    |               ISO/IEC 11889 PCR Bank State Machine (24 Registers)      |                      |
|    |         PCR[i] = SHA-256(PCR_old[i] || SHA-256(MeasurementData))       |                      |
|    +------------------------------------+-----------------------------------+                      |
|                                         |                                                          |
|                    +--------------------+--------------------+                                     |
|                    |                                         |                                     |
|                    v                                         v                                     |
|    +--------------------------------+       +--------------------------------+                     |
|    |     PolicyPCR Trial Session    |       |      TPMS_ATTEST Quote Gen     |                     |
|    |    Opcode: 0x0000017F          |       |    Magic: 0xFF544347 (TCG)     |                     |
|    |    D_pcr = SHA256(PCR_sel...)  |       |    AIK HMAC-SHA256 Signature   |                     |
|    +----------------+---------------+       +----------------+---------------+                     |
|                     |                                        |                                     |
|                     v                                        v                                     |
|    +--------------------------------+       +--------------------------------+                     |
|    |   Authenticated Key Sealer     |       |   Remote Attestation Verifier  |                     |
|    |   K_enc, K_mac <- PolicyDigest |       |   Freshness Nonce Replay Check |                     |
|    |   LUKS Master Key Storage      |       |   Platform Baseline Validation |                     |
|    +--------------------------------+       +--------------------------------+                     |
|                                                                                                    |
|    +------------------------------------------------------------------------+                      |
|    |              10-Rule TPM 2.0 Security Posture Auditor Engine           |                      |
|    |    Evaluates LH-TPM-001..010 -> ANSI Table / JSON / OASIS SARIF v2.1.0 |                      |
|    +------------------------------------------------------------------------+                      |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Mathematical & Cryptographic Formulations

### 2.1. PCR Extend Transition Function
For any register index $i \in [0, 23]$, extending measurement data $M$ executes:
$$M_{\text{digest}} = \text{SHA-256}(M)$$
$$\text{PCR}_{t+1}[i] = \text{SHA-256}\left(\text{PCR}_t[i] \parallel M_{\text{digest}}\right)$$

### 2.2. Composite PCR Digest ($D_{\text{PCR}}$)
Given a 24-bit selection bitmask $M_{\text{pcr}}$ with active indices $i_1 < i_2 < \dots < i_k$:
$$D_{\text{PCR}} = \text{SHA-256}\left(\text{PCR}[i_1] \parallel \text{PCR}[i_2] \parallel \dots \parallel \text{PCR}[i_k]\right)$$

### 2.3. Trial Session `TPM2_PolicyPCR` Computation
Following TCG Part 1/Part 3 specifications, a trial policy session initializes with $\text{policyDigest}_0 = 0^{32}$. Executing `TPM2_PolicyPCR` (`TPM_CC_PolicyPCR = 0x0000017F`):
$$\text{policyDigest}_{\text{new}} = \text{SHA-256}\left(\text{policyDigest}_{\text{old}} \parallel \texttt{0x0000017F}_{\text{BE}} \parallel \text{pcrSelection}[3]_{\text{LE}} \parallel D_{\text{PCR}}\right)$$
where $\text{pcrSelection}[3]_{\text{LE}}$ encodes the 3-byte selection bitmask.

### 2.4. Key Derivation & Authenticated Sealing
Secrets are sealed under a Storage Root Key (SRK) seed, a computed `policyDigest`, and an optional PIN auth value:
$$\text{auth\_digest} = \text{SHA-256}(\text{PIN})$$
$$K_{\text{enc}} = \text{HMAC-SHA256}\left(\text{SRK\_seed}, \texttt{"LH\_TPM2\_ENC"} \parallel \text{policyDigest} \parallel \text{auth\_digest}\right)$$
$$K_{\text{mac}} = \text{HMAC-SHA256}\left(\text{SRK\_seed}, \texttt{"LH\_TPM2\_MAC"} \parallel \text{policyDigest} \parallel \text{auth\_digest}\right)$$

Keystream block $j$ is generated via counter mode:
$$B_j = \text{HMAC-SHA256}\left(K_{\text{enc}}, \text{nonce}_{16} \parallel \text{uint32\_be}(j)\right)$$
$$\text{Ciphertext} = \text{Plaintext} \oplus \bigcup B_j$$

The authentication tag verifies both ciphertext and binding parameters:
$$\text{AuthTag} = \text{HMAC-SHA256}\left(K_{\text{mac}}, \text{nonce}_{16} \parallel \text{uint32\_be}(M_{\text{pcr}}) \parallel \text{uint32\_be}(\text{len}) \parallel \text{Ciphertext}\right)$$

Unsealing recalculates the live platform $D_{\text{PCR}}$ and `policyDigest`. If live state differs from the sealed policy digest, the request is immediately rejected with `TPM_RC_POLICY_FAIL` without deriving keys.

---

## 3. 10-Rule Security Posture Audit Matrix

The audit engine evaluates appliance configuration manifests against 10 critical security vectors.

| Rule ID | Severity | Deduction | CWE | Rule Title & Vulnerability Condition | Remediation |
|:---|:---:|:---:|:---:|:---|:---|
| **`LH-TPM-001`** | CRITICAL | 25 pts | CWE-328 | **SHA-1 Deprecated PCR Bank Active**<br>`sha1_pcr_bank_enabled == true` or `active_alg != "SHA256"` | Disable SHA-1 PCR bank in firmware; enforce SHA-256 active measurement bank. |
| **`LH-TPM-002`** | CRITICAL | 25 pts | CWE-345 | **Incomplete PCR Sealing Policy**<br>`!pcr0_bound` \|\| `!pcr4_bound` \|\| `!pcr7_bound` | Bind disk encryption keys to PCR 0 (CRTM), PCR 4 (Bootloader), and PCR 7 (Secure Boot). |
| **`LH-TPM-003`** | CRITICAL | 25 pts | CWE-306 | **Empty Hierarchy Authorizations**<br>`!owner_auth` \|\| `!endorsement_auth` \|\| `!lockout_auth` | Set strong authorization values on Owner, Endorsement, and Lockout hierarchies. |
| **`LH-TPM-004`** | HIGH | 10 pts | CWE-307 | **Weak Dictionary Attack Parameters**<br>`da_max_tries > 10` \|\| `recovery < 600s` \|\| `lockout < 3600s` | Configure DA parameters: `maxTries <= 10`, `recoveryTime >= 600`, `lockoutRecovery >= 3600`. |
| **`LH-TPM-005`** | HIGH | 10 pts | CWE-319 | **Unencrypted CPU-to-TPM Bus Session**<br>`!aes_cfb_param_enc` \|\| `!salted_hmac_session` | Enforce AES-128-CFB parameter encryption and salted HMAC sessions on SPI/I2C buses. |
| **`LH-TPM-006`** | HIGH | 10 pts | CWE-326 | **Insecure SRK or AIK Template**<br>`srk_bits < 2048` \|\| `!aik_restricted_signing` | Generate SRK using RSA 2048+ or ECC NIST P-256; enforce restricted signing on AIK. |
| **`LH-TPM-007`** | HIGH | 10 pts | CWE-294 | **Weak Remote Attestation Protocol**<br>`quote_nonce_min < 16` \|\| `!verify_ek_cert_chain` | Require $\ge 16$-byte freshness nonces; verify Endorsement Key (EK) certificate chain. |
| **`LH-TPM-008`** | MEDIUM | 4 pts | CWE-276 | **NVRAM Anti-Rollback Unlocked**<br>`!nv_rollback_locked` \|\| `!require_pin_with_pcr` | Lock NVRAM indices with `TPMA_NV_WRITEDEFINE`; require user PIN alongside PCR policy. |
| **`LH-TPM-009`** | MEDIUM | 4 pts | CWE-250 | **Direct Unbrokered /dev/tpm0 Access**<br>`!use_kernel_tpmrm0` \|\| `device_permissions != 0600` | Route userspace callers through `/dev/tpmrm0`; restrict `/dev/tpm0` permissions to 0600. |
| **`LH-TPM-010`** | LOW | 1 pt | CWE-778 | **Missing Event Log Replay Check**<br>`!verify_tcg_event_log_replay` | Replay binary BIOS event log against hardware PCR values to confirm boot integrity. |

### Scoring & Posture Classification
$$\text{Score} = \max\left(0, 100 - \sum \text{Failed Rule Deductions}\right)$$
- **Score = 100**: `HARDENED` (Exit 0)
- **Score 80–99**: `ACCEPTABLE` (Exit 1)
- **Score 50–79**: `DEGRADED` (Exit 1)
- **Score 0–49**: `NON-COMPLIANT` (Exit 1)

---

## 4. CLI Reference & Usage

### 4.1. Audit Policy Manifest (`scan`)
```bash
# Terminal table output with ANSI coloring
./bin/lh-tpm2 scan fixtures/hardened_tpm2_policy.json

# Export to Canonical JSON
./bin/lh-tpm2 scan fixtures/hardened_tpm2_policy.json --format=json --output=report.json

# Export to OASIS SARIF v2.1.0 for CI/CD analysis
./bin/lh-tpm2 scan fixtures/vulnerable_tpm2_policy.json --format=sarif --output=report.sarif
```

### 4.2. PCR Bank Simulation & Event Log Replay (`pcr-extend`)
```bash
# Replay measured boot log and save bank state
./bin/lh-tpm2 pcr-extend --boot-log=fixtures/sample_pcr_boot_log.json --bank-out=boot_bank.bin

# Extend individual PCR with raw string or precomputed hash
./bin/lh-tpm2 pcr-extend --bank-in=boot_bank.bin --pcr=8 --data="console=ttyS0 root=/dev/dm-0" --bank-out=updated_bank.bin
```

### 4.3. PolicyPCR Calculation (`policy-pcr`)
```bash
# Compute PolicyPCR digest for PCR 0, 2, 4, 7 (mask 0x000095)
./bin/lh-tpm2 policy-pcr --mask=0x000095 --bank-in=boot_bank.bin
```

### 4.4. Secret Sealing & Unsealing (`seal` / `unseal`)
```bash
# Seal LUKS master key bound to PCR 0, 2, 4, 7 and PIN
./bin/lh-tpm2 seal \
  --srk-seed=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  --mask=0x000095 \
  --secret="LUKS-KEY-394857-SOVEREIGN-ROBOTIC-PAYLOAD" \
  --auth=4815162342 \
  --bank-in=boot_bank.bin \
  --out=luks_master.sealed

# Unseal key with live PCR bank and correct PIN
./bin/lh-tpm2 unseal \
  --srk-seed=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
  --auth=4815162342 \
  --bank-in=boot_bank.bin \
  --in=luks_master.sealed
```

### 4.5. Remote Attestation Quote Generation & Verification (`quote` / `verify-quote`)
```bash
# Generate quote with 32-byte freshness nonce signed by AIK
./bin/lh-tpm2 quote \
  --aik-key=11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff \
  --nonce=99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa \
  --mask=0x000095 \
  --bank-in=boot_bank.bin \
  --out=attest_quote.json

# Verify attestation quote against expected platform bank
./bin/lh-tpm2 verify-quote \
  --aik-key=11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff \
  --nonce=99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa \
  --bank-in=boot_bank.bin \
  --quote=attest_quote.json
```

---

## 5. Build, Test & Verification

`lh-tpm2-provisioner` compiles cleanly under both `gcc` and `clang` with strict `-Wall -Wextra -Werror -pedantic` flags.

```bash
# Build binary
make all

# Run comprehensive test suite (98 assertions)
make test

# Package release tarball
make dist
```

---

## 6. Security Considerations & Hardware Protection

1. **Bus Sniffing Mitigation**: Physical probes on SPI/I2C buses can capture cleartext command/response parameters if unencrypted sessions are permitted. `lh-tpm2` mandates AES-128-CFB parameter encryption and salted HMAC sessions (`LH-TPM-005`).
2. **Evil Maid & Physical Tampering**: If an attacker boots a modified kernel or bootloader, PCR registers 4 or 7 will diverge from the sealed policy digest, immediately rendering `unseal` impossible (`TPM_RC_POLICY_FAIL`).
3. **Anti-Hammering & DA Lockout**: Monotonic dictionary attack counters must enforce exponential lockout penalties (`LH-TPM-004`) to neutralize PIN brute-forcing attempts.
4. **Memory Hygiene**: All sensitive key material, intermediate state structures, and plaintexts are explicitly wiped using `lh_secure_zero_memory` to prevent memory residue exposure.

---

## 7. License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
