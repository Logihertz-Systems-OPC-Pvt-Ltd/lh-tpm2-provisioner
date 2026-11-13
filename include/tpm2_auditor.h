#ifndef LH_TPM2_AUDITOR_H
#define LH_TPM2_AUDITOR_H

#include "tpm2_types.h"
#include "json_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Run full 10-rule posture audit on a TPM2 configuration */
tpm2_rc_t tpm2_audit_posture(const tpm2_policy_config_t *config,
                             tpm2_audit_report_t *report_out);

#ifdef __cplusplus
}
#endif

#endif /* LH_TPM2_AUDITOR_H */
