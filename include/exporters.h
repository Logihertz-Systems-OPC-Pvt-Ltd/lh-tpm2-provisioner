#ifndef LH_EXPORTERS_H
#define LH_EXPORTERS_H

#include "tpm2_types.h"
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Print formatted ANSI table of audit report */
void lh_render_audit_table(FILE *out, const tpm2_audit_report_t *report, bool use_color);

/* Print formatted ANSI table of PCR bank registers */
void lh_render_pcr_table(FILE *out, const tpm2_pcr_bank_t *bank, uint32_t highlight_mask, bool use_color);

/* Export audit report to Canonical JSON */
bool lh_export_audit_json(FILE *out, const tpm2_audit_report_t *report);

/* Export audit report to OASIS SARIF v2.1.0 */
bool lh_export_audit_sarif(FILE *out, const tpm2_audit_report_t *report);

#ifdef __cplusplus
}
#endif

#endif /* LH_EXPORTERS_H */
