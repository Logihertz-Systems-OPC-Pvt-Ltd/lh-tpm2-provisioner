#include "tpm2_types.h"
#include "sha256_hmac.h"
#include "pcr_policy.h"
#include "seal_engine.h"
#include "json_parser.h"
#include "tpm2_auditor.h"
#include "exporters.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
    } else { \
        g_tests_failed++; \
        fprintf(stderr, "[-] ASSERTION FAILED: %s (Line %d): %s\n", __FILE__, __LINE__, msg); \
    } \
} while (0)

/* 1. SHA-256 Tests */
static void test_sha256(void) {
    uint8_t d[32];
    char hex[65];

    /* NIST vector: empty string */
    lh_sha256_digest("", 0, d);
    lh_bytes_to_hex(d, 32, hex);
    TEST_ASSERT(strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0,
                "SHA-256 empty string");

    /* NIST vector: "abc" */
    lh_sha256_digest("abc", 3, d);
    lh_bytes_to_hex(d, 32, hex);
    TEST_ASSERT(strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0,
                "SHA-256 'abc'");

    /* NIST vector: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" */
    const char *v3 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    lh_sha256_digest(v3, strlen(v3), d);
    lh_bytes_to_hex(d, 32, hex);
    TEST_ASSERT(strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1") == 0,
                "SHA-256 multi-block vector");
}

/* 2. HMAC-SHA256 Tests */
static void test_hmac_sha256(void) {
    uint8_t mac[32];
    char hex[65];

    /* RFC 4231 Test Case 1: Key: 20 bytes 0x0b, Data: "Hi There" */
    uint8_t key1[20];
    memset(key1, 0x0b, sizeof(key1));
    const char *data1 = "Hi There";
    lh_hmac_sha256(key1, sizeof(key1), data1, strlen(data1), mac);
    lh_bytes_to_hex(mac, 32, hex);
    TEST_ASSERT(strcmp(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7") == 0,
                "HMAC-SHA256 RFC 4231 TC1");

    /* RFC 4231 Test Case 2: Key: "Jefe", Data: "what do ya want for nothing?" */
    const char *key2 = "Jefe";
    const char *data2 = "what do ya want for nothing?";
    lh_hmac_sha256(key2, strlen(key2), data2, strlen(data2), mac);
    lh_bytes_to_hex(mac, 32, hex);
    TEST_ASSERT(strcmp(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0,
                "HMAC-SHA256 RFC 4231 TC2");
}

/* 3. Constant-Time & Zeroize */
static void test_security_helpers(void) {
    uint8_t a[32];
    uint8_t b[32];
    memset(a, 0xAA, 32);
    memset(b, 0xAA, 32);

    TEST_ASSERT(lh_constant_time_memcmp(a, b, 32) == 0, "constant_time_memcmp equal");
    b[31] = 0xAB;
    TEST_ASSERT(lh_constant_time_memcmp(a, b, 32) != 0, "constant_time_memcmp diff end");
    b[0] = 0x00;
    TEST_ASSERT(lh_constant_time_memcmp(a, b, 32) != 0, "constant_time_memcmp diff start");

    lh_secure_zero_memory(a, 32);
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (a[i] != 0) all_zero = false;
    }
    TEST_ASSERT(all_zero, "lh_secure_zero_memory cleans buffer");
}

/* 4. Hex conversions */
static void test_hex_conversion(void) {
    uint8_t in[4] = {0x12, 0xAB, 0xCD, 0xEF};
    char hex[9];
    lh_bytes_to_hex(in, 4, hex);
    TEST_ASSERT(strcmp(hex, "12abcdef") == 0, "bytes to hex");

    uint8_t out[4];
    size_t act = 0;
    bool ok = lh_hex_to_bytes("12abcdef", out, 4, &act);
    TEST_ASSERT(ok && act == 4 && memcmp(in, out, 4) == 0, "hex to bytes valid");

    ok = lh_hex_to_bytes("12abc", out, 4, &act);
    TEST_ASSERT(!ok, "hex to bytes reject odd length");

    ok = lh_hex_to_bytes("12zz", out, 4, &act);
    TEST_ASSERT(!ok, "hex to bytes reject invalid characters");
}

/* 5. PCR Bank Reset & Defaults */
static void test_pcr_bank_defaults(void) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    bool static_zeros = true;
    for (uint32_t i = 0; i <= 15; ++i) {
        for (int b = 0; b < 32; ++b) {
            if (bank.pcrs[i][b] != 0x00) static_zeros = false;
        }
    }
    TEST_ASSERT(static_zeros, "PCR 0-15 reset to 0x00");

    bool pcr16_zero = true;
    for (int b = 0; b < 32; ++b) {
        if (bank.pcrs[16][b] != 0x00) pcr16_zero = false;
    }
    TEST_ASSERT(pcr16_zero, "PCR 16 resets to 0x00");

    bool drtm_ones = true;
    for (uint32_t i = 17; i <= 22; ++i) {
        for (int b = 0; b < 32; ++b) {
            if (bank.pcrs[i][b] != 0xFF) drtm_ones = false;
        }
    }
    TEST_ASSERT(drtm_ones, "PCR 17-22 (DRTM) reset to 0xFF");

    bool pcr23_zero = true;
    for (int b = 0; b < 32; ++b) {
        if (bank.pcrs[23][b] != 0x00) pcr23_zero = false;
    }
    TEST_ASSERT(pcr23_zero, "PCR 23 resets to 0x00");
}

/* 6. PCR Extend Math & Progression */
static void test_pcr_extend(void) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    tpm2_rc_t rc = tpm2_pcr_extend_data(&bank, 0, "stage1_crtm", 11);
    TEST_ASSERT(rc == TPM_RC_SUCCESS, "PCR extend data returns success");

    /* Verify PCR 0 changed from 0x00 */
    bool is_zero = true;
    for (int b = 0; b < 32; ++b) {
        if (bank.pcrs[0][b] != 0) is_zero = false;
    }
    TEST_ASSERT(!is_zero, "PCR 0 non-zero after extend");

    /* Out of bounds extend */
    rc = tpm2_pcr_extend_data(&bank, 24, "overflow", 8);
    TEST_ASSERT(rc == TPM_RC_INVAL, "PCR extend rejects index >= 24");

    /* Determinism check */
    tpm2_pcr_bank_t bank2;
    tpm2_pcr_reset(&bank2);
    tpm2_pcr_extend_data(&bank2, 0, "stage1_crtm", 11);
    TEST_ASSERT(memcmp(bank.pcrs[0], bank2.pcrs[0], 32) == 0, "PCR extend is deterministic");

    /* Cumulative second extend */
    tpm2_pcr_extend_data(&bank2, 0, "stage2_uefi", 11);
    TEST_ASSERT(memcmp(bank.pcrs[0], bank2.pcrs[0], 32) != 0, "Cumulative extend alters PCR state");
}

/* 7. Composite PCR Digest */
static void test_composite_pcr_digest(void) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    uint8_t comp1[32];
    uint8_t comp2[32];

    tpm2_rc_t rc1 = tpm2_compute_composite_pcr_digest(&bank, 0x000001, comp1); /* PCR 0 */
    TEST_ASSERT(rc1 == TPM_RC_SUCCESS, "Composite digest PCR 0");

    tpm2_rc_t rc2 = tpm2_compute_composite_pcr_digest(&bank, 0x000091, comp2); /* PCR 0, 4, 7 */
    TEST_ASSERT(rc2 == TPM_RC_SUCCESS, "Composite digest PCR 0,4,7");
    TEST_ASSERT(memcmp(comp1, comp2, 32) != 0, "Different selection masks produce different digests");

    /* Extending a non-selected PCR does not affect composite digest */
    tpm2_pcr_extend_data(&bank, 1, "unrelated_pcr1", 14);
    uint8_t comp3[32];
    tpm2_compute_composite_pcr_digest(&bank, 0x000091, comp3);
    TEST_ASSERT(memcmp(comp2, comp3, 32) == 0, "Composite digest invariant to unselected PCR changes");

    /* Extending selected PCR 4 alters composite digest */
    tpm2_pcr_extend_data(&bank, 4, "bootloader_v2", 13);
    uint8_t comp4[32];
    tpm2_compute_composite_pcr_digest(&bank, 0x000091, comp4);
    TEST_ASSERT(memcmp(comp3, comp4, 32) != 0, "Composite digest sensitive to selected PCR changes");
}

/* 8. TPM2_PolicyPCR Trial Session */
static void test_policy_pcr_trial(void) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    tpm2_policy_pcr_t pol1;
    tpm2_policy_pcr_t pol2;

    uint32_t mask = 0x000095; /* PCR 0, 2, 4, 7 */
    tpm2_rc_t rc = tpm2_compute_policy_pcr(&bank, mask, &pol1);
    TEST_ASSERT(rc == TPM_RC_SUCCESS, "tpm2_compute_policy_pcr succeeds");
    TEST_ASSERT(pol1.pcr_selection_mask == mask, "Policy records selection mask");

    tpm2_compute_policy_pcr(&bank, mask, &pol2);
    TEST_ASSERT(memcmp(pol1.policy_digest, pol2.policy_digest, 32) == 0, "Policy digest deterministic");

    /* Alter PCR 7 (e.g. Secure Boot state change) */
    tpm2_pcr_extend_data(&bank, 7, "tampered_db_keys", 16);
    tpm2_policy_pcr_t pol3;
    tpm2_compute_policy_pcr(&bank, mask, &pol3);
    TEST_ASSERT(memcmp(pol1.policy_digest, pol3.policy_digest, 32) != 0, "Policy digest detects platform changes");
}

/* 9. Sealing & Unsealing Engine */
static void test_seal_unseal_engine(void) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    uint8_t srk_seed[32];
    memset(srk_seed, 0x42, sizeof(srk_seed));

    uint32_t mask = 0x000091; /* PCR 0, 4, 7 */
    tpm2_policy_pcr_t policy;
    tpm2_compute_policy_pcr(&bank, mask, &policy);

    const char *secret = "SUPER_SECRET_LUKS_KEY_DATA_0xDEADBEEF";
    const char *pin = "4815162342";

    tpm2_sealed_blob_t blob;
    tpm2_rc_t rc_seal = tpm2_seal_secret(srk_seed, &policy, pin, (const uint8_t *)secret, strlen(secret), &blob);
    TEST_ASSERT(rc_seal == TPM_RC_SUCCESS, "Secret sealing returns success");
    TEST_ASSERT(blob.pcr_mask == mask, "Sealed blob preserves PCR mask");
    TEST_ASSERT(blob.ciphertext_len == strlen(secret), "Ciphertext length matches plaintext");
    TEST_ASSERT(memcmp(blob.ciphertext, secret, strlen(secret)) != 0, "Ciphertext is properly encrypted");

    /* Valid Unseal */
    uint8_t recovered[256];
    size_t recovered_len = 0;
    tpm2_rc_t rc_unseal = tpm2_unseal_secret(srk_seed, &bank, pin, &blob, recovered, &recovered_len);
    TEST_ASSERT(rc_unseal == TPM_RC_SUCCESS, "Secret unsealing succeeds with valid state and PIN");
    TEST_ASSERT(recovered_len == strlen(secret), "Unsealed length matches");
    TEST_ASSERT(memcmp(recovered, secret, recovered_len) == 0, "Unsealed plaintext matches original secret");

    /* Evil Maid simulation: PCR 0 altered */
    tpm2_pcr_bank_t tampered_bank;
    tpm2_pcr_reset(&tampered_bank);
    tpm2_pcr_extend_data(&tampered_bank, 0, "malicious_rootkit_firmware", 26);

    uint8_t bad_buf[256];
    size_t bad_len = 0;
    tpm2_rc_t rc_evil = tpm2_unseal_secret(srk_seed, &tampered_bank, pin, &blob, bad_buf, &bad_len);
    TEST_ASSERT(rc_evil == TPM_RC_POLICY_FAIL, "Unseal DENIED with TPM_RC_POLICY_FAIL when PCR altered");

    /* Incorrect PIN simulation */
    tpm2_rc_t rc_bad_pin = tpm2_unseal_secret(srk_seed, &bank, "wrong_pin", &blob, bad_buf, &bad_len);
    TEST_ASSERT(rc_bad_pin == TPM_RC_TAMPER, "Unseal DENIED with TPM_RC_TAMPER when PIN incorrect");

    /* Ciphertext tampering */
    tpm2_sealed_blob_t tampered_blob = blob;
    tampered_blob.ciphertext[0] ^= 0x01;
    tpm2_rc_t rc_tamper = tpm2_unseal_secret(srk_seed, &bank, pin, &tampered_blob, bad_buf, &bad_len);
    TEST_ASSERT(rc_tamper == TPM_RC_TAMPER, "Unseal DENIED when ciphertext modified");

    /* Auth tag tampering */
    tampered_blob = blob;
    tampered_blob.auth_tag[0] ^= 0xFF;
    rc_tamper = tpm2_unseal_secret(srk_seed, &bank, pin, &tampered_blob, bad_buf, &bad_len);
    TEST_ASSERT(rc_tamper == TPM_RC_TAMPER, "Unseal DENIED when auth tag modified");

    /* File serialization roundtrip */
    const char *tmp_file = "/tmp/test_blob.sealed";
    bool save_ok = tpm2_save_sealed_blob_file(tmp_file, &blob);
    TEST_ASSERT(save_ok, "Save sealed blob to file");

    tpm2_sealed_blob_t loaded_blob;
    bool load_ok = tpm2_load_sealed_blob_file(tmp_file, &loaded_blob);
    TEST_ASSERT(load_ok, "Load sealed blob from file");
    TEST_ASSERT(loaded_blob.pcr_mask == blob.pcr_mask, "Loaded blob mask matches");
    TEST_ASSERT(loaded_blob.ciphertext_len == blob.ciphertext_len, "Loaded ciphertext length matches");
    TEST_ASSERT(memcmp(loaded_blob.auth_tag, blob.auth_tag, 32) == 0, "Loaded auth tag matches");

    remove(tmp_file);
}

/* 10. TPMS_ATTEST Quote Generation & Verification */
static void test_attestation_quote(void) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    uint8_t aik[32];
    uint8_t nonce[32];
    memset(aik, 0x77, sizeof(aik));
    memset(nonce, 0x33, sizeof(nonce));

    uint32_t mask = 0x000085; /* PCR 0, 2, 7 */
    tpm2_attest_quote_t quote;
    tpm2_rc_t rc = tpm2_generate_quote(&bank, mask, nonce, aik, 123456ULL, 2, &quote);
    TEST_ASSERT(rc == TPM_RC_SUCCESS, "Quote generation returns success");
    TEST_ASSERT(quote.magic == TPM_GENERATED_VALUE, "Quote magic is TPM_GENERATED_VALUE");
    TEST_ASSERT(quote.type == TPM_ST_ATTEST_QUOTE, "Quote type is TPM_ST_ATTEST_QUOTE");
    TEST_ASSERT(quote.pcr_selection_mask == mask, "Quote preserves PCR mask");

    /* Verification with correct parameters */
    tpm2_rc_t rc_v = tpm2_verify_quote(&quote, &bank, nonce, aik);
    TEST_ASSERT(rc_v == TPM_RC_SUCCESS, "Quote verification succeeds");

    /* Verification rejection: Nonce mismatch */
    uint8_t bad_nonce[32];
    memset(bad_nonce, 0x34, sizeof(bad_nonce));
    tpm2_rc_t rc_bad_nonce = tpm2_verify_quote(&quote, &bank, bad_nonce, aik);
    TEST_ASSERT(rc_bad_nonce == TPM_RC_TAMPER, "Quote verification rejects altered nonce");

    /* Verification rejection: PCR state mismatch */
    tpm2_pcr_bank_t bad_bank = bank;
    tpm2_pcr_extend_data(&bad_bank, 0, "tamper", 6);
    tpm2_rc_t rc_bad_pcr = tpm2_verify_quote(&quote, &bad_bank, nonce, aik);
    TEST_ASSERT(rc_bad_pcr == TPM_RC_POLICY_FAIL, "Quote verification rejects altered PCR bank");

    /* Verification rejection: Invalid AIK key */
    uint8_t bad_aik[32];
    memset(bad_aik, 0x88, sizeof(bad_aik));
    tpm2_rc_t rc_bad_aik = tpm2_verify_quote(&quote, &bank, nonce, bad_aik);
    TEST_ASSERT(rc_bad_aik == TPM_RC_AUTH_FAIL, "Quote verification rejects invalid AIK key");

    /* Quote JSON serialization roundtrip */
    char json_buf[1024];
    bool f_ok = tpm2_format_quote_json(&quote, json_buf, sizeof(json_buf));
    TEST_ASSERT(f_ok, "Format quote to JSON");

    tpm2_attest_quote_t parsed_quote;
    bool p_ok = tpm2_parse_quote_json_str(json_buf, &parsed_quote);
    TEST_ASSERT(p_ok, "Parse quote from JSON");
    TEST_ASSERT(parsed_quote.magic == quote.magic, "Parsed quote magic matches");
    TEST_ASSERT(parsed_quote.clock == quote.clock, "Parsed quote clock matches");
    TEST_ASSERT(memcmp(parsed_quote.signature, quote.signature, 32) == 0, "Parsed quote signature matches");
}

/* 11. JSON Parsing Tests */
static void test_json_manifest_parsing(void) {
    tpm2_policy_config_t config;

    bool ok_hardened = tpm2_parse_policy_json_file("fixtures/hardened_tpm2_policy.json", &config);
    TEST_ASSERT(ok_hardened, "Parse hardened policy fixture");
    TEST_ASSERT(!config.sha1_pcr_bank_enabled, "Hardened policy has sha1_pcr_bank_enabled == false");
    TEST_ASSERT(strcmp(config.active_pcr_hash_alg, "SHA256") == 0, "Hardened policy has active_pcr_hash_alg == SHA256");
    TEST_ASSERT(config.pcr0_bound && config.pcr4_bound && config.pcr7_bound, "Hardened policy binds PCR 0, 4, 7");
    TEST_ASSERT(config.owner_auth_configured && config.endorsement_auth_configured && config.lockout_auth_configured,
                "Hardened policy has hierarchy auth configured");
    TEST_ASSERT(config.da_max_tries == 5, "Hardened policy da_max_tries == 5");
    TEST_ASSERT(config.parameter_encryption_aes_cfb, "Hardened policy enables AES CFB bus encryption");
    TEST_ASSERT(config.srk_key_bits == 3072, "Hardened policy has SRK 3072 bits");
    TEST_ASSERT(config.use_kernel_tpmrm0, "Hardened policy uses kernel /dev/tpmrm0");
    TEST_ASSERT(config.device_permissions_octal == 600, "Hardened policy device permissions 600");

    tpm2_boot_log_t log;
    bool ok_boot = tpm2_parse_boot_log_json_file("fixtures/sample_pcr_boot_log.json", &log);
    TEST_ASSERT(ok_boot, "Parse sample boot log fixture");
    TEST_ASSERT(log.event_count == 5, "Boot log fixture has 5 events");
    TEST_ASSERT(log.events[0].pcr_index == 0, "Event 0 is on PCR 0");
    TEST_ASSERT(log.events[3].pcr_index == 4 && log.events[3].has_digest, "Event 3 has digest on PCR 4");
}

/* 12. 10 Posture Auditor Rules */
static void test_auditor_rules(void) {
    tpm2_policy_config_t cfg;
    tpm2_audit_report_t rep;

    /* Base clean config */
    tpm2_parse_policy_json_file("fixtures/hardened_tpm2_policy.json", &cfg);

    /* LH-TPM-001 */
    cfg.sha1_pcr_bank_enabled = true;
    tpm2_audit_posture(&cfg, &rep);
    TEST_ASSERT(rep.score == 75, "Rule LH-TPM-001 deducts 25 pts");
    TEST_ASSERT(strcmp(rep.findings[0].rule_id, "LH-TPM-001") == 0, "LH-TPM-001 finding created");
    cfg.sha1_pcr_bank_enabled = false;

    /* LH-TPM-002 */
    cfg.pcr7_bound = false;
    tpm2_audit_posture(&cfg, &rep);
    TEST_ASSERT(rep.score == 75, "Rule LH-TPM-002 deducts 25 pts");
    TEST_ASSERT(strcmp(rep.findings[0].rule_id, "LH-TPM-002") == 0, "LH-TPM-002 finding created");
    cfg.pcr7_bound = true;

    /* LH-TPM-003 */
    cfg.lockout_auth_configured = false;
    tpm2_audit_posture(&cfg, &rep);
    TEST_ASSERT(rep.score == 75, "Rule LH-TPM-003 deducts 25 pts");
    cfg.lockout_auth_configured = true;

    /* LH-TPM-004 */
    cfg.da_max_tries = 32;
    tpm2_audit_posture(&cfg, &rep);
    TEST_ASSERT(rep.score == 90, "Rule LH-TPM-004 deducts 10 pts");
    cfg.da_max_tries = 5;

    /* LH-TPM-005 */
    cfg.parameter_encryption_aes_cfb = false;
    tpm2_audit_posture(&cfg, &rep);
    TEST_ASSERT(rep.score == 90, "Rule LH-TPM-005 deducts 10 pts");
    cfg.parameter_encryption_aes_cfb = true;

    /* LH-TPM-006 */
    cfg.srk_key_bits = 1024;
    tpm2_audit_posture(&cfg, &rep);
    TEST_ASSERT(rep.score == 90, "Rule LH-TPM-006 deducts 10 pts");
    cfg.srk_key_bits = 3072;

    /* LH-TPM-007 */
    cfg.verify_ek_cert_chain = false;
    tpm2_audit_posture(&cfg, &rep);
    TEST_ASSERT(rep.score == 90, "Rule LH-TPM-007 deducts 10 pts");
    cfg.verify_ek_cert_chain = true;

    /* LH-TPM-008 */
    cfg.nv_rollback_index_locked = false;
    tpm2_audit_posture(&cfg, &rep);
    TEST_ASSERT(rep.score == 96, "Rule LH-TPM-008 deducts 4 pts");
    cfg.nv_rollback_index_locked = true;

    /* LH-TPM-009 */
    cfg.device_permissions_octal = 666;
    tpm2_audit_posture(&cfg, &rep);
    TEST_ASSERT(rep.score == 96, "Rule LH-TPM-009 deducts 4 pts");
    cfg.device_permissions_octal = 600;

    /* LH-TPM-010 */
    cfg.verify_tcg_event_log_replay = false;
    tpm2_audit_posture(&cfg, &rep);
    TEST_ASSERT(rep.score == 99, "Rule LH-TPM-010 deducts 1 pt");
    cfg.verify_tcg_event_log_replay = true;
}

/* 13. Hardened & Vulnerable Posture Evaluations */
static void test_posture_evaluations(void) {
    tpm2_policy_config_t hardened_cfg;
    tpm2_parse_policy_json_file("fixtures/hardened_tpm2_policy.json", &hardened_cfg);

    tpm2_audit_report_t hardened_rep;
    tpm2_audit_posture(&hardened_cfg, &hardened_rep);
    TEST_ASSERT(hardened_rep.score == 100, "Hardened policy receives score 100");
    TEST_ASSERT(strcmp(hardened_rep.status, "HARDENED") == 0, "Hardened status is HARDENED");
    TEST_ASSERT(hardened_rep.passed_rules == 10, "Hardened policy passes 10 rules");
    TEST_ASSERT(hardened_rep.failed_rules == 0, "Hardened policy has 0 failed rules");
    TEST_ASSERT(hardened_rep.finding_count == 0, "Hardened policy has 0 findings");

    tpm2_policy_config_t vuln_cfg;
    tpm2_parse_policy_json_file("fixtures/vulnerable_tpm2_policy.json", &vuln_cfg);

    tpm2_audit_report_t vuln_rep;
    tpm2_audit_posture(&vuln_cfg, &vuln_rep);
    TEST_ASSERT(vuln_rep.score == 0, "Vulnerable policy receives score 0");
    TEST_ASSERT(strcmp(vuln_rep.status, "NON-COMPLIANT") == 0, "Vulnerable status is NON-COMPLIANT");
    TEST_ASSERT(vuln_rep.passed_rules == 0, "Vulnerable policy passes 0 rules");
    TEST_ASSERT(vuln_rep.failed_rules == 10, "Vulnerable policy fails 10 rules");
    TEST_ASSERT(vuln_rep.finding_count == 10, "Vulnerable policy produces 10 findings");

    /* Test exports */
    FILE *tmp_json = fopen("/tmp/test_report.json", "w");
    bool json_ok = lh_export_audit_json(tmp_json, &vuln_rep);
    fclose(tmp_json);
    TEST_ASSERT(json_ok, "Audit JSON export executes successfully");
    remove("/tmp/test_report.json");

    FILE *tmp_sarif = fopen("/tmp/test_report.sarif", "w");
    bool sarif_ok = lh_export_audit_sarif(tmp_sarif, &vuln_rep);
    fclose(tmp_sarif);
    TEST_ASSERT(sarif_ok, "Audit SARIF export executes successfully");
    remove("/tmp/test_report.sarif");
}

int main(void) {
    printf("=====================================================\n");
    printf("   Logihertz TPM 2.0 Provisioner Verification Suite  \n");
    printf("=====================================================\n\n");

    test_sha256();
    test_hmac_sha256();
    test_security_helpers();
    test_hex_conversion();
    test_pcr_bank_defaults();
    test_pcr_extend();
    test_composite_pcr_digest();
    test_policy_pcr_trial();
    test_seal_unseal_engine();
    test_attestation_quote();
    test_json_manifest_parsing();
    test_auditor_rules();
    test_posture_evaluations();

    printf("\n-----------------------------------------------------\n");
    printf("Summary: %d assertions run | %d passed | %d failed\n",
           g_tests_run, g_tests_passed, g_tests_failed);
    printf("-----------------------------------------------------\n");

    return (g_tests_failed == 0) ? 0 : 1;
}
