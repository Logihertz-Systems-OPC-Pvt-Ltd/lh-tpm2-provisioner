# Security Policy

## Supported Versions

Logihertz Systems (OPC) Private Limited maintains security updates and patch releases for the following versions of `lh-tpm2-provisioner`:

| Version | Supported          | Security Maintenance Status |
|---------|--------------------|-----------------------------|
| 0.1.x   | :white_check_mark: | Active Current Release      |
| < 0.1.0 | :x:                | Unsupported Initial Dev     |

---

## Threat Model & Hardware TPM 2.0 Security Posture

Trusted Platform Module (TPM) 2.0 cryptographic hardware (ISO/IEC 11889) provides hardware-rooted measurement, sealing, and remote attestation. However, improper configuration exposes the host operating system to critical hardware and bootloader vulnerabilities:
- **Evil-Maid & Unmeasured Boot Tampering**: If disk encryption secrets are sealed against an incomplete set of Platform Configuration Registers (e.g. omitting PCR0 for UEFI firmware, PCR4 for the bootloader, or PCR7 for Secure Boot state), an attacker with physical access can replace the kernel or bootloader to harvest unsealed encryption keys.
- **Physical SPI / I2C Bus Sniffing**: Without TPM 2.0 parameter encryption (AES-CFB) and salted HMAC session encryption, raw LUKS encryption keys and authorization values transmitted over exposed motherboard traces can be sniffed using cheap logic analyzers or interposers.
- **Dictionary Attack Lockout Denial-of-Service**: Weak or default DA lockout parameters (high trial counts or zero recovery timers) allow attackers to either brute-force PINs or permanently lock the device into a defensive denial-of-service lockout state.
- **Attestation Replay & Spoofing**: Remote attestation quotes (`TPM2_Quote`) that omit fresh cryptographic nonces or fail to validate Endorsement Key (EK) certificates allow adversaries to replay historical valid attestation evidence.

`lh-tpm2-provisioner` addresses these threats by providing:
1. **Mathematical PolicyPCR Sealing**: Enforces multi-register composite digests ($D_{\text{PCR}}$) and trial session hashing (`TPM_CC_PolicyPCR = 0x0000017F`).
2. **Authenticated Unsealing with Constant-Time Tag Verification**: Eliminates timing side-channels and wipes memory buffers on integrity failure.
3. **10-Rule TPM 2.0 Posture Auditor**: Audits TPM configuration manifests against rigorous defense-in-depth criteria.

---

## Reporting a Vulnerability

If you identify a security defect or cryptographic weakness in `lh-tpm2-provisioner`, please report it via coordinated disclosure:

- **Primary Contact**: Sameer Tawade <ops@logihertz.com>
- **Security Contact**: <security@logihertz.com>
- **Subject**: `[SECURITY VULNERABILITY] lh-tpm2-provisioner - <Component>`
- **Response Timeline**: Acknowledgment within 24 hours, triage within 48 hours, and patch availability within 14 business days.
