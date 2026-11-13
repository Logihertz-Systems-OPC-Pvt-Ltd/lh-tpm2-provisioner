#ifndef LH_PCR_POLICY_H
#define LH_PCR_POLICY_H

#include "tpm2_types.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize PCR bank with TCG default reset states:
 * PCR 0-15 and 23 reset to 0x00...00
 * PCR 16 resets to 0x00...00 (Debug)
 * PCR 17-22 reset to 0xFF...FF (DRTM / Dynamic OS registers)
 */
void tpm2_pcr_reset(tpm2_pcr_bank_t *bank);

/* Extend PCR register: PCR_new[idx] = SHA256(PCR_old[idx] || digest32) */
tpm2_rc_t tpm2_pcr_extend_digest(tpm2_pcr_bank_t *bank, uint32_t pcr_index,
                                const uint8_t digest[TPM2_SHA256_DIGEST_SIZE]);

/* Extend PCR register with raw data: PCR_new[idx] = SHA256(PCR_old[idx] || SHA256(data)) */
tpm2_rc_t tpm2_pcr_extend_data(tpm2_pcr_bank_t *bank, uint32_t pcr_index,
                              const void *data, size_t data_len);

/* Calculate composite PCR digest over selected PCRs in ascending order:
 * D_pcr = SHA256(PCR_{i_1} || PCR_{i_2} || ... || PCR_{i_k})
 */
tpm2_rc_t tpm2_compute_composite_pcr_digest(const tpm2_pcr_bank_t *bank,
                                            uint32_t pcr_selection_mask,
                                            uint8_t composite_out[TPM2_SHA256_DIGEST_SIZE]);

/* Calculate TPM2_PolicyPCR trial session digest:
 * policyDigest_0 = 0x00...00 (32 bytes)
 * policyDigest_new = SHA256(policyDigest_old || uint32_be(0x0000017F) || tpml_pcr_selection (3 bytes) || composite_digest)
 */
tpm2_rc_t tpm2_compute_policy_pcr(const tpm2_pcr_bank_t *bank,
                                  uint32_t pcr_selection_mask,
                                  tpm2_policy_pcr_t *policy_out);

/* Generate TPMS_ATTEST Attestation Quote signed with AIK key */
tpm2_rc_t tpm2_generate_quote(const tpm2_pcr_bank_t *bank,
                             uint32_t pcr_selection_mask,
                             const uint8_t nonce[TPM2_SHA256_DIGEST_SIZE],
                             const uint8_t aik_key[TPM2_SHA256_DIGEST_SIZE],
                             uint64_t clock,
                             uint32_t reset_count,
                             tpm2_attest_quote_t *quote_out);

/* Verify TPMS_ATTEST Attestation Quote */
tpm2_rc_t tpm2_verify_quote(const tpm2_attest_quote_t *quote,
                            const tpm2_pcr_bank_t *expected_bank,
                            const uint8_t expected_nonce[TPM2_SHA256_DIGEST_SIZE],
                            const uint8_t aik_key[TPM2_SHA256_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* LH_PCR_POLICY_H */
