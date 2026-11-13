#include "seal_engine.h"
#include "pcr_policy.h"
#include "sha256_hmac.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void generate_nonce(uint8_t nonce[TPM2_NONCE_SIZE]) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t n = fread(nonce, 1, TPM2_NONCE_SIZE, f);
        fclose(f);
        if (n == TPM2_NONCE_SIZE) {
            return;
        }
    }

    /* Fallback pseudo-random seed mixing */
    static uint64_t counter = 0;
    counter++;
    struct {
        uint64_t t;
        uint64_t c;
        void *p;
    } mix;
    mix.t = (uint64_t)time(NULL);
    mix.c = counter;
    mix.p = (void *)&mix;

    uint8_t d[TPM2_SHA256_DIGEST_SIZE];
    lh_sha256_digest(&mix, sizeof(mix), d);
    memcpy(nonce, d, TPM2_NONCE_SIZE);
    lh_secure_zero_memory(d, sizeof(d));
}

static void derive_keys(const uint8_t srk_seed[TPM2_SHA256_DIGEST_SIZE],
                        const uint8_t policy_digest[TPM2_SHA256_DIGEST_SIZE],
                        const char *auth_value,
                        uint8_t k_enc[TPM2_SHA256_DIGEST_SIZE],
                        uint8_t k_mac[TPM2_SHA256_DIGEST_SIZE]) {
    uint8_t auth_digest[TPM2_SHA256_DIGEST_SIZE];
    if (auth_value && strlen(auth_value) > 0) {
        lh_sha256_digest(auth_value, strlen(auth_value), auth_digest);
    } else {
        lh_sha256_digest("", 0, auth_digest);
    }

    /* Message format: Context String (11) || policy_digest (32) || auth_digest (32) */
    uint8_t msg[11 + TPM2_SHA256_DIGEST_SIZE * 2];

    /* Derive K_enc */
    memcpy(msg, "LH_TPM2_ENC", 11);
    memcpy(msg + 11, policy_digest, TPM2_SHA256_DIGEST_SIZE);
    memcpy(msg + 11 + TPM2_SHA256_DIGEST_SIZE, auth_digest, TPM2_SHA256_DIGEST_SIZE);
    lh_hmac_sha256(srk_seed, TPM2_SHA256_DIGEST_SIZE, msg, sizeof(msg), k_enc);

    /* Derive K_mac */
    memcpy(msg, "LH_TPM2_MAC", 11);
    memcpy(msg + 11, policy_digest, TPM2_SHA256_DIGEST_SIZE);
    memcpy(msg + 11 + TPM2_SHA256_DIGEST_SIZE, auth_digest, TPM2_SHA256_DIGEST_SIZE);
    lh_hmac_sha256(srk_seed, TPM2_SHA256_DIGEST_SIZE, msg, sizeof(msg), k_mac);

    lh_secure_zero_memory(msg, sizeof(msg));
    lh_secure_zero_memory(auth_digest, sizeof(auth_digest));
}

static void apply_keystream(const uint8_t k_enc[TPM2_SHA256_DIGEST_SIZE],
                            const uint8_t nonce[TPM2_NONCE_SIZE],
                            const uint8_t *in,
                            uint8_t *out,
                            size_t len) {
    uint8_t block_in[TPM2_NONCE_SIZE + 4];
    memcpy(block_in, nonce, TPM2_NONCE_SIZE);

    uint8_t ks_block[TPM2_SHA256_DIGEST_SIZE];
    size_t offset = 0;
    uint32_t block_idx = 0;

    while (offset < len) {
        block_in[TPM2_NONCE_SIZE]     = (uint8_t)((block_idx >> 24) & 0xFF);
        block_in[TPM2_NONCE_SIZE + 1] = (uint8_t)((block_idx >> 16) & 0xFF);
        block_in[TPM2_NONCE_SIZE + 2] = (uint8_t)((block_idx >> 8) & 0xFF);
        block_in[TPM2_NONCE_SIZE + 3] = (uint8_t)(block_idx & 0xFF);

        lh_hmac_sha256(k_enc, TPM2_SHA256_DIGEST_SIZE, block_in, sizeof(block_in), ks_block);

        size_t take = (len - offset > TPM2_SHA256_DIGEST_SIZE) ? TPM2_SHA256_DIGEST_SIZE : (len - offset);
        for (size_t i = 0; i < take; ++i) {
            out[offset + i] = in[offset + i] ^ ks_block[i];
        }

        offset += take;
        block_idx++;
    }

    lh_secure_zero_memory(ks_block, sizeof(ks_block));
    lh_secure_zero_memory(block_in, sizeof(block_in));
}

static void compute_tag(const uint8_t k_mac[TPM2_SHA256_DIGEST_SIZE],
                        const uint8_t nonce[TPM2_NONCE_SIZE],
                        uint32_t pcr_mask,
                        uint32_t ciphertext_len,
                        const uint8_t *ciphertext,
                        uint8_t tag_out[TPM2_TAG_SIZE]) {
    /* We can use HMAC-SHA256 directly by prefixing header */
    size_t header_len = TPM2_NONCE_SIZE + 4 + 4;
    size_t total_len = header_len + ciphertext_len;
    uint8_t *buf = (uint8_t *)malloc(total_len);
    if (!buf) return;

    memcpy(buf, nonce, TPM2_NONCE_SIZE);
    buf[TPM2_NONCE_SIZE]     = (uint8_t)((pcr_mask >> 24) & 0xFF);
    buf[TPM2_NONCE_SIZE + 1] = (uint8_t)((pcr_mask >> 16) & 0xFF);
    buf[TPM2_NONCE_SIZE + 2] = (uint8_t)((pcr_mask >> 8) & 0xFF);
    buf[TPM2_NONCE_SIZE + 3] = (uint8_t)(pcr_mask & 0xFF);

    buf[TPM2_NONCE_SIZE + 4] = (uint8_t)((ciphertext_len >> 24) & 0xFF);
    buf[TPM2_NONCE_SIZE + 5] = (uint8_t)((ciphertext_len >> 16) & 0xFF);
    buf[TPM2_NONCE_SIZE + 6] = (uint8_t)((ciphertext_len >> 8) & 0xFF);
    buf[TPM2_NONCE_SIZE + 7] = (uint8_t)(ciphertext_len & 0xFF);

    if (ciphertext_len > 0 && ciphertext) {
        memcpy(buf + header_len, ciphertext, ciphertext_len);
    }

    lh_hmac_sha256(k_mac, TPM2_SHA256_DIGEST_SIZE, buf, total_len, tag_out);

    lh_secure_zero_memory(buf, total_len);
    free(buf);
}

tpm2_rc_t tpm2_seal_secret(const uint8_t srk_seed[TPM2_SHA256_DIGEST_SIZE],
                           const tpm2_policy_pcr_t *policy,
                           const char *auth_value,
                           const uint8_t *secret,
                           size_t secret_len,
                           tpm2_sealed_blob_t *blob_out) {
    if (!srk_seed || !policy || !secret || !blob_out) {
        return TPM_RC_INVAL;
    }
    if (secret_len > TPM2_MAX_SECRET_SIZE) {
        return TPM_RC_INVAL;
    }

    blob_out->pcr_mask = policy->pcr_selection_mask;
    memcpy(blob_out->policy_digest, policy->policy_digest, TPM2_SHA256_DIGEST_SIZE);
    blob_out->ciphertext_len = (uint32_t)secret_len;

    generate_nonce(blob_out->nonce);

    uint8_t k_enc[TPM2_SHA256_DIGEST_SIZE];
    uint8_t k_mac[TPM2_SHA256_DIGEST_SIZE];
    derive_keys(srk_seed, policy->policy_digest, auth_value, k_enc, k_mac);

    apply_keystream(k_enc, blob_out->nonce, secret, blob_out->ciphertext, secret_len);
    compute_tag(k_mac, blob_out->nonce, blob_out->pcr_mask, blob_out->ciphertext_len,
                blob_out->ciphertext, blob_out->auth_tag);

    lh_secure_zero_memory(k_enc, sizeof(k_enc));
    lh_secure_zero_memory(k_mac, sizeof(k_mac));

    return TPM_RC_SUCCESS;
}

tpm2_rc_t tpm2_unseal_secret(const uint8_t srk_seed[TPM2_SHA256_DIGEST_SIZE],
                             const tpm2_pcr_bank_t *current_bank,
                             const char *auth_value,
                             const tpm2_sealed_blob_t *blob,
                             uint8_t *secret_out,
                             size_t *secret_len_out) {
    if (!srk_seed || !current_bank || !blob || !secret_out || !secret_len_out) {
        return TPM_RC_INVAL;
    }
    if (blob->ciphertext_len > TPM2_MAX_SECRET_SIZE) {
        return TPM_RC_PARSE_FAIL;
    }

    /* Compute current policy from live PCR bank */
    tpm2_policy_pcr_t current_policy;
    tpm2_rc_t rc = tpm2_compute_policy_pcr(current_bank, blob->pcr_mask, &current_policy);
    if (rc != TPM_RC_SUCCESS) {
        return rc;
    }

    /* Verify PCR Policy Digest in constant-time */
    if (lh_constant_time_memcmp(current_policy.policy_digest, blob->policy_digest, TPM2_SHA256_DIGEST_SIZE) != 0) {
        return TPM_RC_POLICY_FAIL;
    }

    /* Derive encryption and MAC keys using verified policy digest and provided auth PIN */
    uint8_t k_enc[TPM2_SHA256_DIGEST_SIZE];
    uint8_t k_mac[TPM2_SHA256_DIGEST_SIZE];
    derive_keys(srk_seed, blob->policy_digest, auth_value, k_enc, k_mac);

    /* Verify Authentication Tag */
    uint8_t expected_tag[TPM2_TAG_SIZE];
    compute_tag(k_mac, blob->nonce, blob->pcr_mask, blob->ciphertext_len,
                blob->ciphertext, expected_tag);

    if (lh_constant_time_memcmp(blob->auth_tag, expected_tag, TPM2_TAG_SIZE) != 0) {
        lh_secure_zero_memory(k_enc, sizeof(k_enc));
        lh_secure_zero_memory(k_mac, sizeof(k_mac));
        lh_secure_zero_memory(expected_tag, sizeof(expected_tag));
        return TPM_RC_TAMPER;
    }

    /* Decrypt ciphertext */
    apply_keystream(k_enc, blob->nonce, blob->ciphertext, secret_out, blob->ciphertext_len);
    *secret_len_out = blob->ciphertext_len;

    lh_secure_zero_memory(k_enc, sizeof(k_enc));
    lh_secure_zero_memory(k_mac, sizeof(k_mac));
    lh_secure_zero_memory(expected_tag, sizeof(expected_tag));

    return TPM_RC_SUCCESS;
}

size_t tpm2_serialize_sealed_blob(const tpm2_sealed_blob_t *blob,
                                  uint8_t *out_buf,
                                  size_t max_len) {
    if (!blob || !out_buf) return 0;
    size_t needed = 4 + 2 + 4 + TPM2_SHA256_DIGEST_SIZE + TPM2_NONCE_SIZE + 4 + blob->ciphertext_len + TPM2_TAG_SIZE;
    if (max_len < needed) return 0;

    size_t p = 0;
    /* Magic: 0x54504D53 */
    out_buf[p++] = 0x54;
    out_buf[p++] = 0x50;
    out_buf[p++] = 0x4D;
    out_buf[p++] = 0x53;

    /* Version: 0x0001 */
    out_buf[p++] = 0x00;
    out_buf[p++] = 0x01;

    /* PCR mask (4 BE) */
    out_buf[p++] = (uint8_t)((blob->pcr_mask >> 24) & 0xFF);
    out_buf[p++] = (uint8_t)((blob->pcr_mask >> 16) & 0xFF);
    out_buf[p++] = (uint8_t)((blob->pcr_mask >> 8) & 0xFF);
    out_buf[p++] = (uint8_t)(blob->pcr_mask & 0xFF);

    /* Policy digest (32) */
    memcpy(out_buf + p, blob->policy_digest, TPM2_SHA256_DIGEST_SIZE);
    p += TPM2_SHA256_DIGEST_SIZE;

    /* Nonce (16) */
    memcpy(out_buf + p, blob->nonce, TPM2_NONCE_SIZE);
    p += TPM2_NONCE_SIZE;

    /* Ciphertext len (4 BE) */
    out_buf[p++] = (uint8_t)((blob->ciphertext_len >> 24) & 0xFF);
    out_buf[p++] = (uint8_t)((blob->ciphertext_len >> 16) & 0xFF);
    out_buf[p++] = (uint8_t)((blob->ciphertext_len >> 8) & 0xFF);
    out_buf[p++] = (uint8_t)(blob->ciphertext_len & 0xFF);

    /* Ciphertext */
    if (blob->ciphertext_len > 0) {
        memcpy(out_buf + p, blob->ciphertext, blob->ciphertext_len);
        p += blob->ciphertext_len;
    }

    /* Auth tag (32) */
    memcpy(out_buf + p, blob->auth_tag, TPM2_TAG_SIZE);
    p += TPM2_TAG_SIZE;

    return p;
}

tpm2_rc_t tpm2_deserialize_sealed_blob(const uint8_t *in_buf,
                                       size_t in_len,
                                       tpm2_sealed_blob_t *blob_out) {
    if (!in_buf || !blob_out) return TPM_RC_INVAL;

    size_t header_len = 4 + 2 + 4 + TPM2_SHA256_DIGEST_SIZE + TPM2_NONCE_SIZE + 4;
    if (in_len < header_len + TPM2_TAG_SIZE) {
        return TPM_RC_PARSE_FAIL;
    }

    size_t p = 0;
    if (in_buf[0] != 0x54 || in_buf[1] != 0x50 || in_buf[2] != 0x4D || in_buf[3] != 0x53) {
        return TPM_RC_PARSE_FAIL;
    }
    p += 4;

    uint16_t ver = (uint16_t)(((uint16_t)in_buf[p] << 8) | in_buf[p + 1]);
    p += 2;
    if (ver != LH_SEALED_VERSION) {
        return TPM_RC_PARSE_FAIL;
    }

    blob_out->pcr_mask = ((uint32_t)in_buf[p] << 24) |
                         ((uint32_t)in_buf[p + 1] << 16) |
                         ((uint32_t)in_buf[p + 2] << 8) |
                         ((uint32_t)in_buf[p + 3]);
    p += 4;

    memcpy(blob_out->policy_digest, in_buf + p, TPM2_SHA256_DIGEST_SIZE);
    p += TPM2_SHA256_DIGEST_SIZE;

    memcpy(blob_out->nonce, in_buf + p, TPM2_NONCE_SIZE);
    p += TPM2_NONCE_SIZE;

    blob_out->ciphertext_len = ((uint32_t)in_buf[p] << 24) |
                               ((uint32_t)in_buf[p + 1] << 16) |
                               ((uint32_t)in_buf[p + 2] << 8) |
                               ((uint32_t)in_buf[p + 3]);
    p += 4;

    if (blob_out->ciphertext_len > TPM2_MAX_SECRET_SIZE) {
        return TPM_RC_PARSE_FAIL;
    }
    if (in_len < p + blob_out->ciphertext_len + TPM2_TAG_SIZE) {
        return TPM_RC_PARSE_FAIL;
    }

    if (blob_out->ciphertext_len > 0) {
        memcpy(blob_out->ciphertext, in_buf + p, blob_out->ciphertext_len);
        p += blob_out->ciphertext_len;
    }

    memcpy(blob_out->auth_tag, in_buf + p, TPM2_TAG_SIZE);

    return TPM_RC_SUCCESS;
}

bool tpm2_save_sealed_blob_file(const char *filepath, const tpm2_sealed_blob_t *blob) {
    if (!filepath || !blob) return false;

    uint8_t buf[1024];
    size_t len = tpm2_serialize_sealed_blob(blob, buf, sizeof(buf));
    if (len == 0) return false;

    FILE *f = fopen(filepath, "wb");
    if (!f) return false;

    size_t written = fwrite(buf, 1, len, f);
    fclose(f);
    lh_secure_zero_memory(buf, sizeof(buf));

    return (written == len);
}

bool tpm2_load_sealed_blob_file(const char *filepath, tpm2_sealed_blob_t *blob_out) {
    if (!filepath || !blob_out) return false;

    FILE *f = fopen(filepath, "rb");
    if (!f) return false;

    uint8_t buf[1024];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    if (n == 0) return false;

    tpm2_rc_t rc = tpm2_deserialize_sealed_blob(buf, n, blob_out);
    lh_secure_zero_memory(buf, sizeof(buf));

    return (rc == TPM_RC_SUCCESS);
}
