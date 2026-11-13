#include "json_parser.h"
#include "sha256_hmac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char *skip_ws(const char *p) {
    while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        p++;
    }
    return p;
}

static const char *find_key(const char *json, const char *key) {
    if (!json || !key) return NULL;
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);

    const char *p = json;
    while ((p = strstr(p, needle)) != NULL) {
        const char *after = p + strlen(needle);
        after = skip_ws(after);
        if (*after == ':') {
            return after + 1;
        }
        p += strlen(needle);
    }
    return NULL;
}

static bool extract_bool_val(const char *val_start, bool default_val) {
    if (!val_start) return default_val;
    val_start = skip_ws(val_start);
    if (strncmp(val_start, "true", 4) == 0) return true;
    if (strncmp(val_start, "false", 5) == 0) return false;
    return default_val;
}

static int extract_int_val(const char *val_start, int default_val) {
    if (!val_start) return default_val;
    val_start = skip_ws(val_start);
    if (*val_start == '\"') val_start++;
    char *endptr = NULL;
    long val = strtol(val_start, &endptr, 0);
    if (endptr == val_start) {
        return default_val;
    }
    return (int)val;
}

static uint32_t extract_uint_val(const char *val_start, uint32_t default_val) {
    if (!val_start) return default_val;
    val_start = skip_ws(val_start);
    if (*val_start == '\"') val_start++;
    char *endptr = NULL;
    unsigned long val = strtoul(val_start, &endptr, 0);
    if (endptr == val_start) {
        return default_val;
    }
    return (uint32_t)val;
}

static uint64_t extract_uint64_val(const char *val_start, uint64_t default_val) {
    if (!val_start) return default_val;
    val_start = skip_ws(val_start);
    if (*val_start == '\"') val_start++;
    char *endptr = NULL;
    unsigned long long val = strtoull(val_start, &endptr, 0);
    if (endptr == val_start) {
        return default_val;
    }
    return (uint64_t)val;
}

static bool extract_string_val(const char *val_start, char *out, size_t max_len) {
    if (!val_start || !out || max_len == 0) return false;
    val_start = skip_ws(val_start);
    if (*val_start != '\"') return false;
    val_start++;

    size_t i = 0;
    while (*val_start && *val_start != '\"' && i < max_len - 1) {
        if (*val_start == '\\' && *(val_start + 1)) {
            val_start++;
        }
        out[i++] = *val_start++;
    }
    out[i] = '\0';
    return true;
}

static char *read_file_to_str(const char *filepath) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz < 0 || sz > 1024 * 1024) {
        fclose(f);
        return NULL;
    }

    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t read_bytes = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[read_bytes] = '\0';
    return buf;
}

bool tpm2_parse_policy_json_str(const char *json_str, tpm2_policy_config_t *config_out) {
    if (!json_str || !config_out) return false;
    memset(config_out, 0, sizeof(*config_out));

    const char *v;

    /* Policy Name */
    v = find_key(json_str, "policy_name");
    if (v) extract_string_val(v, config_out->policy_name, sizeof(config_out->policy_name));
    else snprintf(config_out->policy_name, sizeof(config_out->policy_name), "default_tpm2_policy");

    /* SHA-1 PCR Bank */
    v = find_key(json_str, "sha1_pcr_bank_enabled");
    config_out->sha1_pcr_bank_enabled = extract_bool_val(v, false);

    /* Active PCR Hash Alg */
    v = find_key(json_str, "active_pcr_hash_alg");
    if (v) extract_string_val(v, config_out->active_pcr_hash_alg, sizeof(config_out->active_pcr_hash_alg));
    else snprintf(config_out->active_pcr_hash_alg, sizeof(config_out->active_pcr_hash_alg), "SHA256");

    /* Bound PCRs */
    v = find_key(json_str, "pcr0_bound");
    config_out->pcr0_bound = extract_bool_val(v, false);
    v = find_key(json_str, "pcr4_bound");
    config_out->pcr4_bound = extract_bool_val(v, false);
    v = find_key(json_str, "pcr7_bound");
    config_out->pcr7_bound = extract_bool_val(v, false);

    /* Hierarchy Authorizations */
    v = find_key(json_str, "owner_auth_configured");
    config_out->owner_auth_configured = extract_bool_val(v, false);
    v = find_key(json_str, "endorsement_auth_configured");
    config_out->endorsement_auth_configured = extract_bool_val(v, false);
    v = find_key(json_str, "lockout_auth_configured");
    config_out->lockout_auth_configured = extract_bool_val(v, false);

    /* DA Lockout */
    v = find_key(json_str, "da_max_tries");
    config_out->da_max_tries = extract_int_val(v, 0);
    v = find_key(json_str, "da_recovery_time_sec");
    config_out->da_recovery_time_sec = extract_int_val(v, 0);
    v = find_key(json_str, "da_lockout_recovery_sec");
    config_out->da_lockout_recovery_sec = extract_int_val(v, 0);

    /* Bus Security */
    v = find_key(json_str, "parameter_encryption_aes_cfb");
    config_out->parameter_encryption_aes_cfb = extract_bool_val(v, false);
    v = find_key(json_str, "salted_hmac_session_required");
    config_out->salted_hmac_session_required = extract_bool_val(v, false);

    /* SRK & AIK */
    v = find_key(json_str, "srk_key_bits");
    config_out->srk_key_bits = extract_int_val(v, 0);
    v = find_key(json_str, "aik_restricted_signing");
    config_out->aik_restricted_signing = extract_bool_val(v, false);

    /* Attestation */
    v = find_key(json_str, "quote_nonce_min_bytes");
    config_out->quote_nonce_min_bytes = extract_int_val(v, 0);
    v = find_key(json_str, "verify_ek_cert_chain");
    config_out->verify_ek_cert_chain = extract_bool_val(v, false);

    /* Anti-Rollback & PIN */
    v = find_key(json_str, "nv_rollback_index_locked");
    config_out->nv_rollback_index_locked = extract_bool_val(v, false);
    v = find_key(json_str, "require_tpm_pin_with_pcr");
    config_out->require_tpm_pin_with_pcr = extract_bool_val(v, false);

    /* Access Broker & Permissions */
    v = find_key(json_str, "use_kernel_tpmrm0");
    config_out->use_kernel_tpmrm0 = extract_bool_val(v, false);
    v = find_key(json_str, "device_permissions_octal");
    config_out->device_permissions_octal = extract_int_val(v, 0);

    /* Event Log Replay */
    v = find_key(json_str, "verify_tcg_event_log_replay");
    config_out->verify_tcg_event_log_replay = extract_bool_val(v, false);

    return true;
}

bool tpm2_parse_policy_json_file(const char *filepath, tpm2_policy_config_t *config_out) {
    char *str = read_file_to_str(filepath);
    if (!str) return false;
    bool ok = tpm2_parse_policy_json_str(str, config_out);
    free(str);
    return ok;
}

bool tpm2_parse_boot_log_json_str(const char *json_str, tpm2_boot_log_t *log_out) {
    if (!json_str || !log_out) return false;
    memset(log_out, 0, sizeof(*log_out));

    const char *events_start = strstr(json_str, "\"events\"");
    if (!events_start) return false;

    const char *bracket = strchr(events_start, '[');
    if (!bracket) return false;

    const char *p = bracket + 1;
    while (*p && *p != ']') {
        const char *obj_start = strchr(p, '{');
        if (!obj_start) break;
        const char *obj_end = strchr(obj_start, '}');
        if (!obj_end) break;

        size_t obj_len = (size_t)(obj_end - obj_start + 1);
        char obj_buf[512];
        if (obj_len >= sizeof(obj_buf)) obj_len = sizeof(obj_buf) - 1;
        memcpy(obj_buf, obj_start, obj_len);
        obj_buf[obj_len] = '\0';

        if (log_out->event_count < 64) {
            tpm2_boot_event_t *ev = &log_out->events[log_out->event_count];
            const char *v;

            v = find_key(obj_buf, "pcr");
            ev->pcr_index = (uint32_t)extract_int_val(v, 0);

            v = find_key(obj_buf, "event_type");
            if (v) extract_string_val(v, ev->event_type, sizeof(ev->event_type));

            v = find_key(obj_buf, "digest");
            if (v) {
                char hex_str[128];
                if (extract_string_val(v, hex_str, sizeof(hex_str))) {
                    size_t actual = 0;
                    if (lh_hex_to_bytes(hex_str, ev->digest, TPM2_SHA256_DIGEST_SIZE, &actual) &&
                        actual == TPM2_SHA256_DIGEST_SIZE) {
                        ev->has_digest = true;
                    }
                }
            }

            v = find_key(obj_buf, "data");
            if (v) {
                extract_string_val(v, ev->data, sizeof(ev->data));
            }

            log_out->event_count++;
        }

        p = obj_end + 1;
    }

    return (log_out->event_count > 0);
}

bool tpm2_parse_boot_log_json_file(const char *filepath, tpm2_boot_log_t *log_out) {
    char *str = read_file_to_str(filepath);
    if (!str) return false;
    bool ok = tpm2_parse_boot_log_json_str(str, log_out);
    free(str);
    return ok;
}

bool tpm2_format_quote_json(const tpm2_attest_quote_t *quote, char *json_out, size_t max_len) {
    if (!quote || !json_out || max_len == 0) return false;

    char nonce_hex[65];
    char pcr_digest_hex[65];
    char sig_hex[65];

    lh_bytes_to_hex(quote->qualifying_data, TPM2_SHA256_DIGEST_SIZE, nonce_hex);
    lh_bytes_to_hex(quote->pcr_digest, TPM2_SHA256_DIGEST_SIZE, pcr_digest_hex);
    lh_bytes_to_hex(quote->signature, TPM2_SHA256_DIGEST_SIZE, sig_hex);

    int n = snprintf(json_out, max_len,
        "{\n"
        "  \"magic\": \"0x%08X\",\n"
        "  \"type\": \"0x%04X\",\n"
        "  \"qualifying_data\": \"%s\",\n"
        "  \"pcr_selection_mask\": \"0x%06X\",\n"
        "  \"pcr_digest\": \"%s\",\n"
        "  \"clock\": %llu,\n"
        "  \"reset_count\": %u,\n"
        "  \"signature\": \"%s\"\n"
        "}\n",
        quote->magic,
        quote->type,
        nonce_hex,
        quote->pcr_selection_mask,
        pcr_digest_hex,
        (unsigned long long)quote->clock,
        quote->reset_count,
        sig_hex
    );

    return (n > 0 && (size_t)n < max_len);
}

bool tpm2_parse_quote_json_str(const char *json_str, tpm2_attest_quote_t *quote_out) {
    if (!json_str || !quote_out) return false;
    memset(quote_out, 0, sizeof(*quote_out));

    const char *v;

    v = find_key(json_str, "magic");
    quote_out->magic = extract_uint_val(v, 0);

    v = find_key(json_str, "type");
    quote_out->type = (uint16_t)extract_uint_val(v, 0);

    v = find_key(json_str, "qualifying_data");
    if (v) {
        char hex[128];
        if (extract_string_val(v, hex, sizeof(hex))) {
            size_t act = 0;
            lh_hex_to_bytes(hex, quote_out->qualifying_data, TPM2_SHA256_DIGEST_SIZE, &act);
        }
    }

    v = find_key(json_str, "pcr_selection_mask");
    quote_out->pcr_selection_mask = extract_uint_val(v, 0);

    v = find_key(json_str, "pcr_digest");
    if (v) {
        char hex[128];
        if (extract_string_val(v, hex, sizeof(hex))) {
            size_t act = 0;
            lh_hex_to_bytes(hex, quote_out->pcr_digest, TPM2_SHA256_DIGEST_SIZE, &act);
        }
    }

    v = find_key(json_str, "clock");
    quote_out->clock = extract_uint64_val(v, 0);

    v = find_key(json_str, "reset_count");
    quote_out->reset_count = extract_uint_val(v, 0);

    v = find_key(json_str, "signature");
    if (v) {
        char hex[128];
        if (extract_string_val(v, hex, sizeof(hex))) {
            size_t act = 0;
            lh_hex_to_bytes(hex, quote_out->signature, TPM2_SHA256_DIGEST_SIZE, &act);
        }
    }

    return true;
}

bool tpm2_parse_quote_json_file(const char *filepath, tpm2_attest_quote_t *quote_out) {
    char *str = read_file_to_str(filepath);
    if (!str) return false;
    bool ok = tpm2_parse_quote_json_str(str, quote_out);
    free(str);
    return ok;
}
