#include "tpm2_auditor.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

static void add_finding(tpm2_audit_report_t *rep,
                        const char *rule_id,
                        const char *title,
                        const char *severity,
                        int weight,
                        const char *cwe,
                        const char *description,
                        const char *remediation) {
    if (rep->finding_count >= 16) return;
    tpm2_finding_t *f = &rep->findings[rep->finding_count++];

    snprintf(f->rule_id, sizeof(f->rule_id), "%s", rule_id);
    snprintf(f->title, sizeof(f->title), "%s", title);
    snprintf(f->severity, sizeof(f->severity), "%s", severity);
    f->weight = weight;
    snprintf(f->cwe, sizeof(f->cwe), "%s", cwe);
    snprintf(f->description, sizeof(f->description), "%s", description);
    snprintf(f->remediation, sizeof(f->remediation), "%s", remediation);
}

tpm2_rc_t tpm2_audit_posture(const tpm2_policy_config_t *config,
                             tpm2_audit_report_t *report_out) {
    if (!config || !report_out) return TPM_RC_INVAL;

    memset(report_out, 0, sizeof(*report_out));
    snprintf(report_out->policy_name, sizeof(report_out->policy_name), "%s", config->policy_name);
    report_out->total_rules = 10;

    int total_deductions = 0;

    /* Get current timestamp */
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    if (tm_info) {
        strftime(report_out->audited_at, sizeof(report_out->audited_at), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    } else {
        snprintf(report_out->audited_at, sizeof(report_out->audited_at), "2026-11-13T00:00:00Z");
    }

    /* Rule 1: LH-TPM-001 */
    if (config->sha1_pcr_bank_enabled || strcmp(config->active_pcr_hash_alg, "SHA256") != 0) {
        total_deductions += 25;
        report_out->failed_rules++;
        add_finding(report_out, "LH-TPM-001",
                    "SHA-1 Deprecated PCR Bank Active",
                    "CRITICAL", 25, "CWE-328",
                    "Firmware or OS maintains an active SHA-1 PCR measurement bank susceptible to collision attacks.",
                    "Disable SHA-1 PCR bank in firmware setup; switch active measurement bank to SHA256.");
    } else {
        report_out->passed_rules++;
    }

    /* Rule 2: LH-TPM-002 */
    if (!config->pcr0_bound || !config->pcr4_bound || !config->pcr7_bound) {
        total_deductions += 25;
        report_out->failed_rules++;
        add_finding(report_out, "LH-TPM-002",
                    "Incomplete PCR Sealing Policy for Disk Encryption",
                    "CRITICAL", 25, "CWE-345",
                    "Storage key sealing policy omits mandatory boot stages (PCR 0 Core Root of Trust, PCR 4 Bootloader, or PCR 7 Secure Boot Policy).",
                    "Bind LUKS/dm-crypt master secret to PCR 0, PCR 4, and PCR 7.");
    } else {
        report_out->passed_rules++;
    }

    /* Rule 3: LH-TPM-003 */
    if (!config->owner_auth_configured || !config->endorsement_auth_configured || !config->lockout_auth_configured) {
        total_deductions += 25;
        report_out->failed_rules++;
        add_finding(report_out, "LH-TPM-003",
                    "Empty or Default TPM 2.0 Hierarchy Authorization Values",
                    "CRITICAL", 25, "CWE-306",
                    "Owner, Endorsement, or Lockout hierarchies operate with empty auth values, allowing unprivileged takeover.",
                    "Provision non-empty cryptographically strong authorization values for Owner, Endorsement, and Lockout hierarchies.");
    } else {
        report_out->passed_rules++;
    }

    /* Rule 4: LH-TPM-004 */
    if (config->da_max_tries > 10 || config->da_max_tries <= 0 ||
        config->da_recovery_time_sec < 600 || config->da_lockout_recovery_sec < 3600) {
        total_deductions += 10;
        report_out->failed_rules++;
        add_finding(report_out, "LH-TPM-004",
                    "Weak Dictionary Attack Defense Parameters",
                    "HIGH", 10, "CWE-307",
                    "Dictionary attack parameters allow excessive retry attempts or have insufficient recovery delays.",
                    "Configure TPM 2.0 DA parameters: maxTries <= 10, recoveryTime >= 600s, lockoutRecovery >= 3600s.");
    } else {
        report_out->passed_rules++;
    }

    /* Rule 5: LH-TPM-005 */
    if (!config->parameter_encryption_aes_cfb || !config->salted_hmac_session_required) {
        total_deductions += 10;
        report_out->failed_rules++;
        add_finding(report_out, "LH-TPM-005",
                    "Unencrypted CPU-to-TPM Bus Communication Session",
                    "HIGH", 10, "CWE-319",
                    "SPI/I2C/LPC communication between CPU and TPM operates without parameter encryption or salted HMAC sessions, exposing secrets to inter-chip bus sniffers.",
                    "Enforce encrypted authorization sessions (AES-128-CFB parameter encryption) and salted HMAC sessions.");
    } else {
        report_out->passed_rules++;
    }

    /* Rule 6: LH-TPM-006 */
    if (config->srk_key_bits < 2048 || !config->aik_restricted_signing) {
        total_deductions += 10;
        report_out->failed_rules++;
        add_finding(report_out, "LH-TPM-006",
                    "Insecure Storage Root Key or Attestation Identity Key Template",
                    "HIGH", 10, "CWE-326",
                    "Storage Root Key uses insufficient bit strength (< 2048) or Attestation Identity Key lacks restricted signing attributes.",
                    "Generate SRK using RSA 2048+ or ECC NIST P-256; enforce restricted signing attributes on Attestation Identity Keys (AIK).");
    } else {
        report_out->passed_rules++;
    }

    /* Rule 7: LH-TPM-007 */
    if (config->quote_nonce_min_bytes < 16 || !config->verify_ek_cert_chain) {
        total_deductions += 10;
        report_out->failed_rules++;
        add_finding(report_out, "LH-TPM-007",
                    "Weak Remote Attestation Quote Protocol",
                    "HIGH", 10, "CWE-294",
                    "Attestation quote verification allows short nonces (< 16 bytes) or fails to validate Endorsement Key (EK) manufacturer certificate chain.",
                    "Require minimum 16-byte cryptographically random freshness nonce for quotes; verify Endorsement Key (EK) certificate chain against manufacturer CA.");
    } else {
        report_out->passed_rules++;
    }

    /* Rule 8: LH-TPM-008 */
    if (!config->nv_rollback_index_locked || !config->require_tpm_pin_with_pcr) {
        total_deductions += 4;
        report_out->failed_rules++;
        add_finding(report_out, "LH-TPM-008",
                    "NVRAM Anti-Rollback Monotonic Counter Index Unlocked",
                    "MEDIUM", 4, "CWE-276",
                    "NVRAM monotonic anti-rollback index lacks write-locking or disk decryption policy omits user PIN factor alongside PCR policy.",
                    "Lock NVRAM monotonic counter indices with TPMA_NV_WRITEDEFINE; require user PIN authorization alongside PCR policy for secret unsealing.");
    } else {
        report_out->passed_rules++;
    }

    /* Rule 9: LH-TPM-009 */
    if (!config->use_kernel_tpmrm0 || config->device_permissions_octal != 600) {
        total_deductions += 4;
        report_out->failed_rules++;
        add_finding(report_out, "LH-TPM-009",
                    "Direct Unbrokered /dev/tpm0 Access in Userspace",
                    "MEDIUM", 4, "CWE-250",
                    "Applications directly access unbrokered character device /dev/tpm0 or device node permissions allow non-root/non-tss access.",
                    "Direct applications to in-kernel resource broker /dev/tpmrm0; restrict /dev/tpm0 permissions to root:tss 0600.");
    } else {
        report_out->passed_rules++;
    }

    /* Rule 10: LH-TPM-010 */
    if (!config->verify_tcg_event_log_replay) {
        total_deductions += 1;
        report_out->failed_rules++;
        add_finding(report_out, "LH-TPM-010",
                    "TCG Binary BIOS Event Log Replay Verification Missing",
                    "LOW", 1, "CWE-778",
                    "Boot sequence does not re-compute and verify binary BIOS event log against hardware PCR values.",
                    "Replay binary event log measurements against hardware PCR values to confirm boot integrity.");
    } else {
        report_out->passed_rules++;
    }

    report_out->score = 100 - total_deductions;
    if (report_out->score < 0) {
        report_out->score = 0;
    }

    if (report_out->score == 100) {
        snprintf(report_out->status, sizeof(report_out->status), "HARDENED");
    } else if (report_out->score >= 80) {
        snprintf(report_out->status, sizeof(report_out->status), "ACCEPTABLE");
    } else if (report_out->score >= 50) {
        snprintf(report_out->status, sizeof(report_out->status), "DEGRADED");
    } else {
        snprintf(report_out->status, sizeof(report_out->status), "NON-COMPLIANT");
    }

    return TPM_RC_SUCCESS;
}
