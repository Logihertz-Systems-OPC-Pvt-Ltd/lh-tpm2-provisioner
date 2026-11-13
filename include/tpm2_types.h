#ifndef LH_TPM2_TYPES_H
#define LH_TPM2_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define LH_TOOL_NAME "lh-tpm2"
#define LH_VERSION   "0.1.0"
#define LH_AUTHOR_ORG "Logihertz Systems (OPC) Private Limited"

#define TPM2_NUM_PCRS 24
#define TPM2_SHA256_DIGEST_SIZE 32
#define TPM2_MAX_SECRET_SIZE 256
#define TPM2_NONCE_SIZE 16
#define TPM2_TAG_SIZE 32

/* TCG Standard Constants */
#define TPM_GENERATED_VALUE  0xFF544347U /* "\xFFTCG" magic bytes */
#define TPM_ST_ATTEST_QUOTE  0x8018U
#define TPM_CC_PolicyPCR     0x0000017FU

/* Return Codes */
typedef enum {
    TPM_RC_SUCCESS = 0,
    TPM_RC_POLICY_FAIL = 1,
    TPM_RC_AUTH_FAIL = 2,
    TPM_RC_PARSE_FAIL = 3,
    TPM_RC_INVAL = 4,
    TPM_RC_TAMPER = 5
} tpm2_rc_t;

/* PCR Bank State (24 registers, 32 bytes each) */
typedef struct {
    uint8_t pcrs[TPM2_NUM_PCRS][TPM2_SHA256_DIGEST_SIZE];
} tpm2_pcr_bank_t;

/* PolicyPCR Session State */
typedef struct {
    uint32_t pcr_selection_mask;
    uint8_t pcr_composite_digest[TPM2_SHA256_DIGEST_SIZE];
    uint8_t policy_digest[TPM2_SHA256_DIGEST_SIZE];
} tpm2_policy_pcr_t;

/* Sealed Secret Blob Structure */
typedef struct {
    uint32_t pcr_mask;
    uint8_t policy_digest[TPM2_SHA256_DIGEST_SIZE];
    uint8_t nonce[TPM2_NONCE_SIZE];
    uint32_t ciphertext_len;
    uint8_t ciphertext[TPM2_MAX_SECRET_SIZE];
    uint8_t auth_tag[TPM2_TAG_SIZE];
} tpm2_sealed_blob_t;

/* TPMS_ATTEST Attestation Quote Structure */
typedef struct {
    uint32_t magic;           /* TPM_GENERATED_VALUE = 0xFF544347 */
    uint16_t type;            /* TPM_ST_ATTEST_QUOTE = 0x8018 */
    uint8_t qualifying_data[TPM2_SHA256_DIGEST_SIZE]; /* Freshness Nonce */
    uint32_t pcr_selection_mask;
    uint8_t pcr_digest[TPM2_SHA256_DIGEST_SIZE];
    uint64_t clock;
    uint32_t reset_count;
    uint8_t signature[TPM2_SHA256_DIGEST_SIZE]; /* Signed under AIK Key */
} tpm2_attest_quote_t;

/* Auditor Finding */
typedef struct {
    char rule_id[16];
    char title[128];
    char severity[16]; /* CRITICAL, HIGH, MEDIUM, LOW */
    int weight;
    char cwe[128];
    char description[512];
    char remediation[512];
} tpm2_finding_t;

/* Auditor Report */
typedef struct {
    char policy_name[128];
    int score;
    char status[32];
    int total_rules;
    int passed_rules;
    int failed_rules;
    int finding_count;
    tpm2_finding_t findings[16];
    char audited_at[64];
} tpm2_audit_report_t;

#endif /* LH_TPM2_TYPES_H */
