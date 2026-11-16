# Engineering & Technical Architecture Specification

**Specification ID**: `LH-SPEC-2026-044`  
**Repository**: `lh-tpm2-provisioner`  
**CLI Executable**: `lh-tpm2`  
**Standard Release Version**: `0.1.0`  
**Standard License**: `Apache-2.0`  
**Classification**: `Industrial Sovereign Cybersecurity & Critical Infrastructure Telemetry`

---

## Section 1: Document Control & Specification Metadata

| Metadata Attribute | Value |
| :--- | :--- |
| **Document Identification** | `LH-SPEC-2026-044` |
| **System Name** | `Logihertz Systems Sovereign Ecosystem` |
| **Target Component** | `lh-tpm2-provisioner` (`lh-tpm2`) |
| **Target Language / Platform** | `C` |
| **Legal Entity** | Logihertz Systems (OPC) Private Limited |
| **Corporate Identity (CIN)** | `U72100MH2025OPC463857` |
| **GSTIN Registration** | `27AAGCL6394P1ZL` |
| **Principal Architect** | Sameer Tawade (`ops@logihertz.com` / `security@logihertz.com`) |
| **Headquarters & Registered Office** | Mumbai, Maharashtra, Republic of India |
| **Official Portal** | [https://www.logihertz.com](https://www.logihertz.com) |
| **Repository URL** | [https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-tpm2-provisioner](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-tpm2-provisioner) |
| **Document Status** | `APPROVED FOR PRODUCTION & INDUSTRIAL CERTIFICATION` |
| **Effective Release Date** | `2026-11-16` |

---

## Section 2: Normative RFC 2119 Requirements & System Invariants

This technical architecture specification enforces strict deterministic execution invariants in accordance with **RFC 2119** (`MUST`, `MUST NOT`, `REQUIRED`, `SHALL`, `SHALL NOT`, `SHOULD`, `RECOMMENDED`, `MAY`).

1. **Zero-Daemon Execution Invariant**:
   - The CLI binary `lh-tpm2` `MUST` execute as a clean, self-contained, stateless, zero-daemon process.
   - It `MUST NOT` spawn background daemons, fork unmonitored worker processes, or establish persistent Unix domain socket listeners unless explicitly invoked in daemon mode.
   - All state transitions `MUST` be deterministic, ephemeral, and strictly bounded by the execution lifecycle.

2. **Zero External Runtime Dependency Mandate**:
   - The software `MUST NOT` load, link, or depend upon third-party runtime package registries (e.g. PyPI, npm, Packagist, crates.io, Maven) at runtime.
   - For `C`, all cryptographic, mathematical, serialization, and networking primitives `MUST` be implemented exclusively via language standard libraries or clean-room internal zero-dependency modules.

3. **Deterministic Air-Gapped Operation**:
   - The system `MUST` function with 100% feature parity in air-gapped, isolated, and offline enclaves.
   - The software `MUST NOT` initiate unsolicited network calls, telemetry telemetry pings, phone-home beacons, or external CDN queries.
   - All verification baselines, heuristics, and schemas `MUST` be packaged locally within the distribution.

4. **Constant-Time Cryptographic Comparison**:
   - All cryptographic comparison routines (hashes, HMAC tags, signatures, secret tokens, and commitments) `MUST` execute in constant time (`subtle.ConstantTimeCompare`, `CRYPTO_memcmp`, or equivalent).
   - The implementation `MUST NOT` short-circuit string comparisons when evaluating sensitive keys, thereby mitigating timing side-channel attacks.

5. **Memory Safety & Explicit Zeroization**:
   - All transient buffers containing sensitive key material, decrypted plaintexts, seeds, and cryptographic nonces `MUST` be explicitly overwritten with zeroes immediately following completion of the cryptographic operation.
   - For C/C++ implementations, bounds checks and safe buffer wrappers `MUST` prevent stack/heap overflows. For Rust implementations, `#![forbid(unsafe_code)]` `MUST` be enforced.

6. **Standardized Telemetry Interoperability**:
   - All security assessment outputs `MUST` support machine-readable ingestion via OASIS SARIF v2.1.0 JSON and Canonical Indented JSON schemas, alongside ANSI console tables.

---

## Section 3: Core Mathematical & Algorithmic Specification

### 3.1 Domain Engine Mathematical Foundation: TPM 2.0 SHA-256 Platform Configuration Register Extension

The underlying computational core of `lh-tpm2-provisioner` is formally governed by the following mathematical and algorithmic formulations:

$$\text{PCR}_i^{(k+1)} = \text{SHA-256}\left(\text{PCR}_i^{(k)} \parallel \text{Measurement}\right)$$

### 3.2 Standardized Logihertz Security Posture Score Formulation

To achieve absolute cross-tool normalization across all 60 repositories in the Logihertz Systems Ecosystem, the security posture score $S_{\text{posture}}$ is evaluated on a standardized continuous integer scale $[0, 100]$:

$$S_{\text{posture}} = \max\left(0, \; 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

Where:
- $c_{\text{CRITICAL}}$ represents the total count of triggered Critical-severity normative rules (deduction: $-25$ per finding).
- $c_{\text{HIGH}}$ represents the total count of triggered High-severity normative rules (deduction: $-10$ per finding).
- $c_{\text{MEDIUM}}$ represents the total count of triggered Medium-severity normative rules (deduction: $-4$ per finding).
- $c_{\text{LOW}}$ represents the total count of triggered Low-severity normative rules (deduction: $-1$ per finding).

The final compliance verdict is strictly bifurcated:
$$\text{Verdict} = \begin{cases} \text{PASS} & \text{if } S_{\text{posture}} = 100 \land \sum c_i = 0 \\ \text{FAIL} & \text{otherwise} \end{cases}$$

---

## Section 4: Normative 10-Rule Detection Matrix

The detection engine evaluates configurations, manifests, firmware, protocols, and streams against the following 10 deterministic security rules:

| Rule ID | Severity | Weight | CWE ID | Trigger Predicate / Condition | Remediation Guideline |
| :--- | :--- | :---: | :---: | :--- | :--- |
| `LH-TPM-001` | `CRITICAL` | `25` | `CWE-328` | SHA-1 Deprecated PCR Bank Active<br>sha1_pcr_bank_enabled == true or active_alg != "SHA256" | Disable SHA-1 PCR bank in firmware; enforce SHA-256 active measurement bank. |
| `LH-TPM-002` | `CRITICAL` | `25` | `CWE-345` | !pcr7_bound | Bind disk encryption keys to PCR 0 (CRTM), PCR 4 (Bootloader), and PCR 7 (Secure Boot). |
| `LH-TPM-003` | `CRITICAL` | `25` | `CWE-306` | !lockout_auth | Set strong authorization values on Owner, Endorsement, and Lockout hierarchies. |
| `LH-TPM-004` | `HIGH` | `10` | `CWE-307` | lockout < 3600s | Configure DA parameters: maxTries <= 10, recoveryTime >= 600, lockoutRecovery >= 3600. |
| `LH-TPM-005` | `HIGH` | `10` | `CWE-319` | !salted_hmac_session | Enforce AES-128-CFB parameter encryption and salted HMAC sessions on SPI/I2C buses. |
| `LH-TPM-006` | `HIGH` | `10` | `CWE-326` | !aik_restricted_signing | Generate SRK using RSA 2048+ or ECC NIST P-256; enforce restricted signing on AIK. |
| `LH-TPM-007` | `HIGH` | `10` | `CWE-294` | !verify_ek_cert_chain | Require $\ge 16$-byte freshness nonces; verify Endorsement Key (EK) certificate chain. |
| `LH-TPM-008` | `MEDIUM` | `4` | `CWE-276` | !require_pin_with_pcr | Lock NVRAM indices with TPMA_NV_WRITEDEFINE; require user PIN alongside PCR policy. |
| `LH-TPM-009` | `MEDIUM` | `4` | `CWE-250` | device_permissions != 0600 | Route userspace callers through /dev/tpmrm0; restrict /dev/tpm0 permissions to 0600. |
| `LH-TPM-010` | `LOW` | `1` | `CWE-778` | Missing Event Log Replay Check<br>!verify_tcg_event_log_replay | Replay binary BIOS event log against hardware PCR values to confirm boot integrity. |

---

## Section 5: CLI Contract, Exit Codes & OASIS SARIF v2.1.0 Specification

### 5.1 Command-Line Interface Syntax

The primary entrypoint `lh-tpm2` conforms to standard POSIX argument conventions:

```text
USAGE:
  lh-tpm2 <command> [flags] [arguments]

CORE COMMANDS:
  scan <target> [--format table|json|sarif] [--output <file>]
      Execute deterministic security evaluation against target manifest or telemetry stream.
  verify <target>
      Validate operational parameters, cryptographic checksums, and structural invariants.
  --version, version
      Output release version, architecture, and legal attribution.
  --help, help
      Display comprehensive operational usage and command reference.
```

### 5.2 Deterministic Exit Code Protocol

| Exit Code | Classification | Operational Semantics |
| :---: | :--- | :--- |
| `0` | **SUCCESS / PASS** | Target passed all checks; zero Critical/High violations detected; $S_{\text{posture}} = 100$. |
| `1` | **FINDINGS / FAIL** | Target triggered one or more security rule violations; policy threshold breached. |
| `2` | **ERROR / USAGE** | Invalid CLI invocation, syntax error, missing input file, or fatal I/O failure. |

### 5.3 OASIS SARIF v2.1.0 Schema Compliance

Exported SARIF documents validate against the official OASIS schema (`sarif-schema-2.1.0.json`). Each result object maps:
- `ruleId`: Standardized identifier (`LH-TPM-001` .. `LH-TPM-010`).
- `level`: SARIF severity levels (`error` for Critical/High, `warning` for Medium, `note` for Low).
- `message.text`: Comprehensive explanation, CWE mapping, and actionable remediation steps.
- `locations[].physicalLocation.artifactLocation.uri`: Absolute or normalized relative path of target artifact.

---

## 6. Standalone Future Development Roadmap (`v0.2.0` — `v0.5.0`)

`lh-tpm2-provisioner` is developed as an independent, standalone open-source project. The following roadmap defines the planned architectural, algorithmic, and protocol enhancements for upcoming point releases of `lh-tpm2-provisioner`:

| Target Release | Milestone Focus | Planned Technical Deliverables for `lh-tpm2-provisioner` |
|---|---|---|
| **`v0.2.0`** | Parser & Protocol Expansion | Add TPM2_PolicyOR (supporting dual A/B kernel boot PCR policies), TPM2_PolicySigned (key-authorized PCR updates), and SHA-384/SHA-512 PCR banks. |
| **`v0.3.0`** | Deep Algorithmic & Stateful Analysis | Implement a TCG PC Client / UEFI canonical binary event-log parser (/sys/kernel/security/tpm0/binary_bios_measurements) with PCR replay verification. |
| **`v0.4.0`** | Remediation, Synthesis & Format Interop | Synthesize systemd-cryptsetup LUKS2 TPM2 JSON token headers and TPM2_NV_DefineSpace monotonic counter policies. |
| **`v0.5.0`** | High-Throughput Performance & Formal Verification | Add a direct /dev/tpmrm0 marshaling/unmarshaling command engine for hardware-in-the-loop provisioning without external TSS libraries. |

### 6.1 `v0.2.0` — Parser & Protocol Expansion
- **Format & Protocol Ingestion**: Add TPM2_PolicyOR (supporting dual A/B kernel boot PCR policies), TPM2_PolicySigned (key-authorized PCR updates), and SHA-384/SHA-512 PCR banks.
- **Zero-Dependency Architecture**: Pure standard library implementation with deterministic parsing guarantees and strict error handling.
- **Verification & Telemetry**: Regression test suites verifying schema edge-cases, malformed payload rejections, and SARIF v2.1.0 output fidelity.

### 6.2 `v0.3.0` — Deep Algorithmic & Stateful Analysis
- **Algorithmic Core**: Implement a TCG PC Client / UEFI canonical binary event-log parser (/sys/kernel/security/tpm0/binary_bios_measurements) with PCR replay verification.
- **State Machine & Analysis Engine**: High-fidelity state tracking, cycle detection, and invariant checking with minimal computational overhead.
- **Differential & Regression Verification**: Comprehensive test harnesses covering stateful transitions, edge conditions, and mathematical boundary constraints.

### 6.3 `v0.4.0` — Remediation, Synthesis & Format Interoperability
- **Synthesis & Interoperability**: Synthesize systemd-cryptsetup LUKS2 TPM2 JSON token headers and TPM2_NV_DefineSpace monotonic counter policies.
- **Automated Remediation Workflows**: Idempotent generation of verified configuration patches, policy rules, and standardized cross-format exports.
- **Contract & Artifact Validation**: Cryptographic baseline verification and end-to-end integration testing for synthesized deliverables.

### 6.4 `v0.5.0` — High-Throughput Performance & Formal Verification
- **High-Throughput Optimization**: Add a direct /dev/tpmrm0 marshaling/unmarshaling command engine for hardware-in-the-loop provisioning without external TSS libraries.
- **Hardware & Kernel Acceleration**: Vectorized SIMD/eBPF/sub-millisecond streaming execution with bounded memory allocation.
- **Formal Verification & Assurance**: Mathematical proof of invariant preservation, false-positive calibration, and high-assurance certification baselines.

---

## Section 7: Verification, Quality Assurance & Legal Attribution

### 7.1 Automated Verification Protocol

Prior to distribution, all builds must execute the standardized Logihertz test suite:
- Unit and mathematical property tests verifying all equations and edge cases.
- Static analysis with zero warnings under standard strict linters.
- Subprocess CLI verification covering exit codes `0`, `1`, and `2`.

### 7.2 Copyright & Governance Notice

```text
Copyright 2025-2026 Logihertz Systems (OPC) Private Limited.
Creator, Founder, Director & Sole Developer: Sameer Tawade <ops@logihertz.com> / <security@logihertz.com>
Official Corporate Portal: https://www.logihertz.com
```

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this software except in compliance with the License. You may obtain a copy of the License at `http://www.apache.org/licenses/LICENSE-2.0`.
