#include "pcr_policy.h"
#include "sha256_hmac.h"
#include <string.h>

void tpm2_pcr_reset(tpm2_pcr_bank_t *bank) {
    if (!bank) return;

    for (uint32_t i = 0; i < TPM2_NUM_PCRS; ++i) {
        if (i >= 17 && i <= 22) {
            /* DRTM / Dynamic OS registers reset to 0xFF */
            memset(bank->pcrs[i], 0xFF, TPM2_SHA256_DIGEST_SIZE);
        } else {
            /* Standard static registers reset to 0x00 */
            memset(bank->pcrs[i], 0x00, TPM2_SHA256_DIGEST_SIZE);
        }
    }
}

tpm2_rc_t tpm2_pcr_extend_digest(tpm2_pcr_bank_t *bank, uint32_t pcr_index,
                                const uint8_t digest[TPM2_SHA256_DIGEST_SIZE]) {
    if (!bank || !digest || pcr_index >= TPM2_NUM_PCRS) {
        return TPM_RC_INVAL;
    }

    uint8_t buffer[TPM2_SHA256_DIGEST_SIZE * 2];
    memcpy(buffer, bank->pcrs[pcr_index], TPM2_SHA256_DIGEST_SIZE);
    memcpy(buffer + TPM2_SHA256_DIGEST_SIZE, digest, TPM2_SHA256_DIGEST_SIZE);

    lh_sha256_digest(buffer, sizeof(buffer), bank->pcrs[pcr_index]);
    lh_secure_zero_memory(buffer, sizeof(buffer));

    return TPM_RC_SUCCESS;
}

tpm2_rc_t tpm2_pcr_extend_data(tpm2_pcr_bank_t *bank, uint32_t pcr_index,
                              const void *data, size_t data_len) {
    if (!bank || (!data && data_len > 0) || pcr_index >= TPM2_NUM_PCRS) {
        return TPM_RC_INVAL;
    }

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    lh_sha256_digest(data, data_len, digest);

    tpm2_rc_t rc = tpm2_pcr_extend_digest(bank, pcr_index, digest);
    lh_secure_zero_memory(digest, sizeof(digest));
    return rc;
}

tpm2_rc_t tpm2_compute_composite_pcr_digest(const tpm2_pcr_bank_t *bank,
                                            uint32_t pcr_selection_mask,
                                            uint8_t composite_out[TPM2_SHA256_DIGEST_SIZE]) {
    if (!bank || !composite_out) {
        return TPM_RC_INVAL;
    }

    lh_sha256_ctx_t ctx;
    lh_sha256_init(&ctx);

    for (uint32_t i = 0; i < TPM2_NUM_PCRS; ++i) {
        if ((pcr_selection_mask & (1U << i)) != 0) {
            lh_sha256_update(&ctx, bank->pcrs[i], TPM2_SHA256_DIGEST_SIZE);
        }
    }

    lh_sha256_final(&ctx, composite_out);
    return TPM_RC_SUCCESS;
}

tpm2_rc_t tpm2_compute_policy_pcr(const tpm2_pcr_bank_t *bank,
                                  uint32_t pcr_selection_mask,
                                  tpm2_policy_pcr_t *policy_out) {
    if (!bank || !policy_out) {
        return TPM_RC_INVAL;
    }

    policy_out->pcr_selection_mask = pcr_selection_mask;

    tpm2_rc_t rc = tpm2_compute_composite_pcr_digest(bank, pcr_selection_mask,
                                                    policy_out->pcr_composite_digest);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* TCG PolicyPCR update:
     * policyDigest_0 = 32 bytes of zeroes
     * buffer: policyDigest_old (32) || TPM_CC_PolicyPCR (4 BE) || pcrSelection (3 bytes LE) || composite_digest (32)
     */
    uint8_t buffer[32 + 4 + 3 + 32];
    memset(buffer, 0, 32); /* policyDigest_old = 0 */

    /* uint32_be(0x0000017F) */
    buffer[32] = 0x00;
    buffer[33] = 0x00;
    buffer[34] = 0x01;
    buffer[35] = 0x7F;

    /* 3-byte selection bitmask */
    buffer[36] = (uint8_t)(pcr_selection_mask & 0xFF);
    buffer[37] = (uint8_t)((pcr_selection_mask >> 8) & 0xFF);
    buffer[38] = (uint8_t)((pcr_selection_mask >> 16) & 0xFF);

    /* Composite PCR Digest */
    memcpy(buffer + 39, policy_out->pcr_composite_digest, TPM2_SHA256_DIGEST_SIZE);

    lh_sha256_digest(buffer, sizeof(buffer), policy_out->policy_digest);
    lh_secure_zero_memory(buffer, sizeof(buffer));

    return TPM_RC_SUCCESS;
}

static size_t serialize_quote_payload(const tpm2_attest_quote_t *quote, uint8_t *out, size_t max_len) {
    if (max_len < 86) return 0;

    /* magic (4 bytes BE) */
    out[0] = (uint8_t)((quote->magic >> 24) & 0xFF);
    out[1] = (uint8_t)((quote->magic >> 16) & 0xFF);
    out[2] = (uint8_t)((quote->magic >> 8) & 0xFF);
    out[3] = (uint8_t)(quote->magic & 0xFF);

    /* type (2 bytes BE) */
    out[4] = (uint8_t)((quote->type >> 8) & 0xFF);
    out[5] = (uint8_t)(quote->type & 0xFF);

    /* qualifying_data (32 bytes) */
    memcpy(out + 6, quote->qualifying_data, TPM2_SHA256_DIGEST_SIZE);

    /* clock (8 bytes BE) */
    out[38] = (uint8_t)((quote->clock >> 56) & 0xFF);
    out[39] = (uint8_t)((quote->clock >> 48) & 0xFF);
    out[40] = (uint8_t)((quote->clock >> 40) & 0xFF);
    out[41] = (uint8_t)((quote->clock >> 32) & 0xFF);
    out[42] = (uint8_t)((quote->clock >> 24) & 0xFF);
    out[43] = (uint8_t)((quote->clock >> 16) & 0xFF);
    out[44] = (uint8_t)((quote->clock >> 8) & 0xFF);
    out[45] = (uint8_t)(quote->clock & 0xFF);

    /* reset_count (4 bytes BE) */
    out[46] = (uint8_t)((quote->reset_count >> 24) & 0xFF);
    out[47] = (uint8_t)((quote->reset_count >> 16) & 0xFF);
    out[48] = (uint8_t)((quote->reset_count >> 8) & 0xFF);
    out[49] = (uint8_t)(quote->reset_count & 0xFF);

    /* pcr_selection_mask (4 bytes BE) */
    out[50] = (uint8_t)((quote->pcr_selection_mask >> 24) & 0xFF);
    out[51] = (uint8_t)((quote->pcr_selection_mask >> 16) & 0xFF);
    out[52] = (uint8_t)((quote->pcr_selection_mask >> 8) & 0xFF);
    out[53] = (uint8_t)(quote->pcr_selection_mask & 0xFF);

    /* pcr_digest (32 bytes) */
    memcpy(out + 54, quote->pcr_digest, TPM2_SHA256_DIGEST_SIZE);

    return 86;
}

tpm2_rc_t tpm2_generate_quote(const tpm2_pcr_bank_t *bank,
                             uint32_t pcr_selection_mask,
                             const uint8_t nonce[TPM2_SHA256_DIGEST_SIZE],
                             const uint8_t aik_key[TPM2_SHA256_DIGEST_SIZE],
                             uint64_t clock,
                             uint32_t reset_count,
                             tpm2_attest_quote_t *quote_out) {
    if (!bank || !nonce || !aik_key || !quote_out) {
        return TPM_RC_INVAL;
    }

    quote_out->magic = TPM_GENERATED_VALUE;
    quote_out->type = TPM_ST_ATTEST_QUOTE;
    memcpy(quote_out->qualifying_data, nonce, TPM2_SHA256_DIGEST_SIZE);
    quote_out->pcr_selection_mask = pcr_selection_mask;
    quote_out->clock = clock;
    quote_out->reset_count = reset_count;

    tpm2_rc_t rc = tpm2_compute_composite_pcr_digest(bank, pcr_selection_mask, quote_out->pcr_digest);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    uint8_t payload[128];
    size_t payload_len = serialize_quote_payload(quote_out, payload, sizeof(payload));
    if (payload_len == 0) {
        return TPM_RC_INVAL;
    }

    lh_hmac_sha256(aik_key, TPM2_SHA256_DIGEST_SIZE, payload, payload_len, quote_out->signature);
    lh_secure_zero_memory(payload, sizeof(payload));

    return TPM_RC_SUCCESS;
}

tpm2_rc_t tpm2_verify_quote(const tpm2_attest_quote_t *quote,
                            const tpm2_pcr_bank_t *expected_bank,
                            const uint8_t expected_nonce[TPM2_SHA256_DIGEST_SIZE],
                            const uint8_t aik_key[TPM2_SHA256_DIGEST_SIZE]) {
    if (!quote || !expected_bank || !expected_nonce || !aik_key) {
        return TPM_RC_INVAL;
    }

    if (quote->magic != TPM_GENERATED_VALUE || quote->type != TPM_ST_ATTEST_QUOTE) {
        return TPM_RC_PARSE_FAIL;
    }

    /* Check freshness nonce in constant time */
    if (lh_constant_time_memcmp(quote->qualifying_data, expected_nonce, TPM2_SHA256_DIGEST_SIZE) != 0) {
        return TPM_RC_TAMPER;
    }

    /* Compute expected composite PCR digest */
    uint8_t expected_composite[TPM2_SHA256_DIGEST_SIZE];
    tpm2_rc_t rc = tpm2_compute_composite_pcr_digest(expected_bank, quote->pcr_selection_mask, expected_composite);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    if (lh_constant_time_memcmp(quote->pcr_digest, expected_composite, TPM2_SHA256_DIGEST_SIZE) != 0) {
        return TPM_RC_POLICY_FAIL;
    }

    /* Verify signature */
    uint8_t payload[128];
    size_t payload_len = serialize_quote_payload(quote, payload, sizeof(payload));
    if (payload_len == 0) {
        return TPM_RC_INVAL;
    }

    uint8_t expected_sig[TPM2_SHA256_DIGEST_SIZE];
    lh_hmac_sha256(aik_key, TPM2_SHA256_DIGEST_SIZE, payload, payload_len, expected_sig);
    lh_secure_zero_memory(payload, sizeof(payload));

    if (lh_constant_time_memcmp(quote->signature, expected_sig, TPM2_SHA256_DIGEST_SIZE) != 0) {
        lh_secure_zero_memory(expected_sig, sizeof(expected_sig));
        return TPM_RC_AUTH_FAIL;
    }

    lh_secure_zero_memory(expected_sig, sizeof(expected_sig));
    return TPM_RC_SUCCESS;
}
