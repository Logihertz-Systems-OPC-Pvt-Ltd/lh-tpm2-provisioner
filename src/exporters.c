#include "exporters.h"
#include "sha256_hmac.h"
#include <string.h>

#define ANSI_RESET   "\033[0m"
#define ANSI_BOLD    "\033[1m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN    "\033[36m"

static const char *get_pcr_purpose(uint32_t idx) {
    switch (idx) {
        case 0:  return "Core System Firmware / CRTM";
        case 1:  return "Host Platform Configuration";
        case 2:  return "Option ROM Code";
        case 3:  return "Option ROM Configuration";
        case 4:  return "Master Boot Record / IPL Code";
        case 5:  return "IPL Partition Table & Configuration";
        case 6:  return "State Transitions & Resumption";
        case 7:  return "Secure Boot Policy & Platform Certificates";
        case 8:  return "GRUB / Kernel Command Line";
        case 9:  return "Initramfs / Linux Kernel Image";
        case 10: return "IMA Integrity Measurements";
        case 11: return "Unified Kernel Image (UKI)";
        case 12: return "Kernel Extension Modules";
        case 13: return "System Security Extensions";
        case 14: return "Boot Loader Extensions";
        case 15: return "OS Runtime Applications";
        case 16: return "Debug Measurements";
        case 17: return "DRTM Dynamic Launch";
        case 18: return "DRTM Trusted OS";
        case 19: return "DRTM Kernel & Hypervisor";
        case 20: return "DRTM Security Modules";
        case 21: return "DRTM Attestation Agent";
        case 22: return "DRTM Authority Validation";
        case 23: return "Application Specific Parameters";
        default: return "Reserved";
    }
}

void lh_render_pcr_table(FILE *out, const tpm2_pcr_bank_t *bank, uint32_t highlight_mask, bool use_color) {
    if (!out || !bank) return;

    const char *b = use_color ? ANSI_BOLD : "";
    const char *r = use_color ? ANSI_RESET : "";
    const char *c = use_color ? ANSI_CYAN : "";

    fprintf(out, "\n%s+----+------------------------------------------------------------------+------------------------------------------+%s\n", b, r);
    fprintf(out, "%s|PCR | SHA-256 Digest (Bank: SHA256)                                     | Standard TCG Role / Target Measurement    |%s\n", b, r);
    fprintf(out, "%s+----+------------------------------------------------------------------+------------------------------------------+%s\n", b, r);

    for (uint32_t i = 0; i < TPM2_NUM_PCRS; ++i) {
        char hex[65];
        lh_bytes_to_hex(bank->pcrs[i], TPM2_SHA256_DIGEST_SIZE, hex);

        bool is_selected = (highlight_mask & (1U << i)) != 0;
        const char *marker_color = is_selected ? (use_color ? ANSI_YELLOW : "") : "";
        const char *star = is_selected ? "*" : " ";

        fprintf(out, "| %s%02u%s%s | %s%s%s | %-40.40s |\n",
                marker_color, i, star, r,
                is_selected ? (use_color ? ANSI_GREEN : "") : c, hex, r,
                get_pcr_purpose(i));
    }
    fprintf(out, "%s+----+------------------------------------------------------------------+------------------------------------------+%s\n\n", b, r);
}

void lh_render_audit_table(FILE *out, const tpm2_audit_report_t *report, bool use_color) {
    if (!out || !report) return;

    const char *b = use_color ? ANSI_BOLD : "";
    const char *r = use_color ? ANSI_RESET : "";
    const char *c_status = use_color ? ANSI_GREEN : "";

    if (report->score < 50) {
        c_status = use_color ? ANSI_RED : "";
    } else if (report->score < 80) {
        c_status = use_color ? ANSI_YELLOW : "";
    } else if (report->score < 100) {
        c_status = use_color ? ANSI_CYAN : "";
    }

    fprintf(out, "\n%s========================================================================================%s\n", b, r);
    fprintf(out, "%s              LOGIHERTZ TPM 2.0 HARDWARE SECURITY POSTURE AUDITOR                      %s\n", b, r);
    fprintf(out, "%s========================================================================================%s\n", b, r);
    fprintf(out, "  Policy Manifest : %s%s%s\n", b, report->policy_name, r);
    fprintf(out, "  Audited At      : %s\n", report->audited_at);
    fprintf(out, "  Rules Evaluated : %d total (%d passed, %d failed)\n",
            report->total_rules, report->passed_rules, report->failed_rules);
    fprintf(out, "  Security Score  : %s%d/100 (%s)%s\n", c_status, report->score, report->status, r);
    fprintf(out, "----------------------------------------------------------------------------------------\n");

    if (report->finding_count == 0) {
        fprintf(out, "\n  %s[PASS]%s No security posture deficiencies detected! TPM 2.0 policy is HARDENED.\n\n",
                use_color ? ANSI_GREEN : "", r);
    } else {
        fprintf(out, "\n%sFINDINGS (%d detected):%s\n\n", b, report->finding_count, r);
        for (int i = 0; i < report->finding_count; ++i) {
            const tpm2_finding_t *f = &report->findings[i];
            const char *c_sev = use_color ? ANSI_RED : "";
            if (strcmp(f->severity, "HIGH") == 0) c_sev = use_color ? ANSI_RED : "";
            else if (strcmp(f->severity, "MEDIUM") == 0) c_sev = use_color ? ANSI_YELLOW : "";
            else if (strcmp(f->severity, "LOW") == 0) c_sev = use_color ? ANSI_CYAN : "";

            fprintf(out, "  %s[%s]%s %s%s%s: %s\n",
                    c_sev, f->severity, r,
                    b, f->rule_id, r, f->title);
            fprintf(out, "      CWE         : %s (Weight: -%d pts)\n", f->cwe, f->weight);
            fprintf(out, "      Description : %s\n", f->description);
            fprintf(out, "      Remediation : %s%s%s\n\n",
                    use_color ? ANSI_CYAN : "", f->remediation, r);
        }
    }
    fprintf(out, "%s========================================================================================%s\n\n", b, r);
}

bool lh_export_audit_json(FILE *out, const tpm2_audit_report_t *report) {
    if (!out || !report) return false;

    fprintf(out, "{\n");
    fprintf(out, "  \"tool\": \"%s\",\n", LH_TOOL_NAME);
    fprintf(out, "  \"version\": \"%s\",\n", LH_VERSION);
    fprintf(out, "  \"policy_name\": \"%s\",\n", report->policy_name);
    fprintf(out, "  \"audited_at\": \"%s\",\n", report->audited_at);
    fprintf(out, "  \"score\": %d,\n", report->score);
    fprintf(out, "  \"status\": \"%s\",\n", report->status);
    fprintf(out, "  \"total_rules\": %d,\n", report->total_rules);
    fprintf(out, "  \"passed_rules\": %d,\n", report->passed_rules);
    fprintf(out, "  \"failed_rules\": %d,\n", report->failed_rules);
    fprintf(out, "  \"findings\": [\n");

    for (int i = 0; i < report->finding_count; ++i) {
        const tpm2_finding_t *f = &report->findings[i];
        fprintf(out, "    {\n");
        fprintf(out, "      \"rule_id\": \"%s\",\n", f->rule_id);
        fprintf(out, "      \"title\": \"%s\",\n", f->title);
        fprintf(out, "      \"severity\": \"%s\",\n", f->severity);
        fprintf(out, "      \"weight\": %d,\n", f->weight);
        fprintf(out, "      \"cwe\": \"%s\",\n", f->cwe);
        fprintf(out, "      \"description\": \"%s\",\n", f->description);
        fprintf(out, "      \"remediation\": \"%s\"\n", f->remediation);
        fprintf(out, "    }%s\n", (i + 1 < report->finding_count) ? "," : "");
    }

    fprintf(out, "  ]\n");
    fprintf(out, "}\n");
    return true;
}

bool lh_export_audit_sarif(FILE *out, const tpm2_audit_report_t *report) {
    if (!out || !report) return false;

    fprintf(out, "{\n");
    fprintf(out, "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n");
    fprintf(out, "  \"version\": \"2.1.0\",\n");
    fprintf(out, "  \"runs\": [\n");
    fprintf(out, "    {\n");
    fprintf(out, "      \"tool\": {\n");
    fprintf(out, "        \"driver\": {\n");
    fprintf(out, "          \"name\": \"%s\",\n", LH_TOOL_NAME);
    fprintf(out, "          \"version\": \"%s\",\n", LH_VERSION);
    fprintf(out, "          \"informationUri\": \"https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-tpm2-provisioner\",\n");
    fprintf(out, "          \"rules\": [\n");

    static const struct {
        const char *id;
        const char *name;
        const char *desc;
    } known_rules[10] = {
        {"LH-TPM-001", "SHA-1 Deprecated PCR Bank Active", "Active SHA-1 PCR measurement bank susceptible to collision attacks."},
        {"LH-TPM-002", "Incomplete PCR Sealing Policy for Disk Encryption", "Sealing policy omits mandatory boot stages PCR 0, 4, or 7."},
        {"LH-TPM-003", "Empty or Default TPM 2.0 Hierarchy Authorization Values", "Owner, Endorsement, or Lockout hierarchies have empty auth values."},
        {"LH-TPM-004", "Weak Dictionary Attack Defense Parameters", "DA parameters allow excessive retry attempts or insufficient delay."},
        {"LH-TPM-005", "Unencrypted CPU-to-TPM Bus Communication Session", "SPI/I2C communication lacks AES-CFB encryption or salted HMAC session."},
        {"LH-TPM-006", "Insecure Storage Root Key or Attestation Identity Key Template", "SRK has < 2048 bits or AIK lacks restricted signing attribute."},
        {"LH-TPM-007", "Weak Remote Attestation Quote Protocol", "Quote freshness nonce is < 16 bytes or EK cert chain validation is disabled."},
        {"LH-TPM-008", "NVRAM Anti-Rollback Monotonic Counter Index Unlocked", "NVRAM anti-rollback index unlocked or user PIN unsealing factor omitted."},
        {"LH-TPM-009", "Direct Unbrokered /dev/tpm0 Access in Userspace", "Direct access to unbrokered /dev/tpm0 or insecure device permissions."},
        {"LH-TPM-010", "TCG Binary BIOS Event Log Replay Verification Missing", "TCG binary event log replay verification not enforced."}
    };

    for (size_t i = 0; i < 10; ++i) {
        fprintf(out, "            {\n");
        fprintf(out, "              \"id\": \"%s\",\n", known_rules[i].id);
        fprintf(out, "              \"name\": \"%s\",\n", known_rules[i].name);
        fprintf(out, "              \"shortDescription\": { \"text\": \"%s\" }\n", known_rules[i].desc);
        fprintf(out, "            }%s\n", (i + 1 < 10) ? "," : "");
    }

    fprintf(out, "          ]\n");
    fprintf(out, "        }\n");
    fprintf(out, "      },\n");
    fprintf(out, "      \"results\": [\n");

    for (int i = 0; i < report->finding_count; ++i) {
        const tpm2_finding_t *f = &report->findings[i];
        const char *level = "error";
        if (strcmp(f->severity, "MEDIUM") == 0) level = "warning";
        else if (strcmp(f->severity, "LOW") == 0) level = "note";

        fprintf(out, "        {\n");
        fprintf(out, "          \"ruleId\": \"%s\",\n", f->rule_id);
        fprintf(out, "          \"level\": \"%s\",\n", level);
        fprintf(out, "          \"message\": { \"text\": \"%s. %s\" },\n", f->description, f->remediation);
        fprintf(out, "          \"locations\": [\n");
        fprintf(out, "            {\n");
        fprintf(out, "              \"physicalLocation\": {\n");
        fprintf(out, "                \"artifactLocation\": { \"uri\": \"%s\" }\n", report->policy_name);
        fprintf(out, "              }\n");
        fprintf(out, "            }\n");
        fprintf(out, "          ]\n");
        fprintf(out, "        }%s\n", (i + 1 < report->finding_count) ? "," : "");
    }

    fprintf(out, "      ]\n");
    fprintf(out, "    }\n");
    fprintf(out, "  ]\n");
    fprintf(out, "}\n");

    return true;
}
