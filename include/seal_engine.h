#ifndef LH_SEAL_ENGINE_H
#define LH_SEAL_ENGINE_H

#include "tpm2_types.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* File format magic and version for .sealed blobs */
#define LH_SEALED_MAGIC   0x54504D53U /* "TPMS" */
#define LH_SEALED_VERSION 1U

/* Seal secret under SRK seed, PCR policy, and optional PIN */
tpm2_rc_t tpm2_seal_secret(const uint8_t srk_seed[TPM2_SHA256_DIGEST_SIZE],
                           const tpm2_policy_pcr_t *policy,
                           const char *auth_value,
                           const uint8_t *secret,
                           size_t secret_len,
                           tpm2_sealed_blob_t *blob_out);

/* Unseal secret with live PCR bank, SRK seed, and PIN */
tpm2_rc_t tpm2_unseal_secret(const uint8_t srk_seed[TPM2_SHA256_DIGEST_SIZE],
                             const tpm2_pcr_bank_t *current_bank,
                             const char *auth_value,
                             const tpm2_sealed_blob_t *blob,
                             uint8_t *secret_out,
                             size_t *secret_len_out);

/* Serialize sealed blob to binary buffer */
size_t tpm2_serialize_sealed_blob(const tpm2_sealed_blob_t *blob,
                                  uint8_t *out_buf,
                                  size_t max_len);

/* Deserialize sealed blob from binary buffer */
tpm2_rc_t tpm2_deserialize_sealed_blob(const uint8_t *in_buf,
                                       size_t in_len,
                                       tpm2_sealed_blob_t *blob_out);

/* Save sealed blob to file */
bool tpm2_save_sealed_blob_file(const char *filepath, const tpm2_sealed_blob_t *blob);

/* Load sealed blob from file */
bool tpm2_load_sealed_blob_file(const char *filepath, tpm2_sealed_blob_t *blob_out);

#ifdef __cplusplus
}
#endif

#endif /* LH_SEAL_ENGINE_H */
