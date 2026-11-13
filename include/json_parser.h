#ifndef LH_JSON_PARSER_H
#define LH_JSON_PARSER_H

#include "tpm2_types.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char policy_name[128];
    bool sha1_pcr_bank_enabled;
    char active_pcr_hash_alg[32];
    bool pcr0_bound;
    bool pcr4_bound;
    bool pcr7_bound;
    bool owner_auth_configured;
    bool endorsement_auth_configured;
    bool lockout_auth_configured;
    int da_max_tries;
    int da_recovery_time_sec;
    int da_lockout_recovery_sec;
    bool parameter_encryption_aes_cfb;
    bool salted_hmac_session_required;
    int srk_key_bits;
    bool aik_restricted_signing;
    int quote_nonce_min_bytes;
    bool verify_ek_cert_chain;
    bool nv_rollback_index_locked;
    bool require_tpm_pin_with_pcr;
    bool use_kernel_tpmrm0;
    int device_permissions_octal;
    bool verify_tcg_event_log_replay;
} tpm2_policy_config_t;

typedef struct {
    uint32_t pcr_index;
    char event_type[64];
    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    bool has_digest;
    char data[256];
} tpm2_boot_event_t;

typedef struct {
    size_t event_count;
    tpm2_boot_event_t events[64];
} tpm2_boot_log_t;

/* Parse policy config from JSON string or file */
bool tpm2_parse_policy_json_str(const char *json_str, tpm2_policy_config_t *config_out);
bool tpm2_parse_policy_json_file(const char *filepath, tpm2_policy_config_t *config_out);

/* Parse boot log from JSON string or file */
bool tpm2_parse_boot_log_json_str(const char *json_str, tpm2_boot_log_t *log_out);
bool tpm2_parse_boot_log_json_file(const char *filepath, tpm2_boot_log_t *log_out);

/* Quote JSON formatting and parsing */
bool tpm2_format_quote_json(const tpm2_attest_quote_t *quote, char *json_out, size_t max_len);
bool tpm2_parse_quote_json_str(const char *json_str, tpm2_attest_quote_t *quote_out);
bool tpm2_parse_quote_json_file(const char *filepath, tpm2_attest_quote_t *quote_out);

#ifdef __cplusplus
}
#endif

#endif /* LH_JSON_PARSER_H */
