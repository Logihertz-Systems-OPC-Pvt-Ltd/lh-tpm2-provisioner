#define _POSIX_C_SOURCE 200809L
#include "tpm2_types.h"
#include "sha256_hmac.h"
#include "pcr_policy.h"
#include "seal_engine.h"
#include "json_parser.h"
#include "tpm2_auditor.h"
#include "exporters.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_banner(void) {
    printf("Logihertz TPM 2.0 Provisioner & Hardware Security Auditor (%s v%s)\n", LH_TOOL_NAME, LH_VERSION);
    printf("Copyright (C) 2026 %s\n\n", LH_AUTHOR_ORG);
}

static void print_help(const char *prog) {
    print_banner();
    printf("Usage:\n");
    printf("  %s <command> [options]\n\n", prog);
    printf("Commands:\n");
    printf("  scan <policy.json>         Audit TPM 2.0 policy manifest against 10 posture rules\n");
    printf("    --format=table|json|sarif Output format (default: table)\n");
    printf("    --output=<file>          Write report to file instead of stdout\n");
    printf("    --no-color               Disable ANSI color escapes\n\n");

    printf("  pcr-extend                 Extend PCR registers or simulate boot log\n");
    printf("    --pcr=<index>            PCR register index (0..23)\n");
    printf("    --data=<string>          ASCII event data to hash and extend\n");
    printf("    --digest=<hex32>         Pre-computed SHA-256 digest to extend\n");
    printf("    --boot-log=<file.json>   JSON event log file with measurements\n");
    printf("    --bank-in=<file>         Load initial PCR bank state\n");
    printf("    --bank-out=<file>        Save updated PCR bank state\n");
    printf("    --mask=<hex>             Highlight PCRs in table output\n\n");

    printf("  policy-pcr                 Calculate composite PCR digest and PolicyPCR trial session\n");
    printf("    --mask=<hex>             24-bit PCR selection mask (e.g. 0x000091 for PCR 0,4,7)\n");
    printf("    --bank-in=<file>         PCR bank state file (default: clean reset bank)\n\n");

    printf("  seal                       Seal secret under SRK seed, PCR policy, and optional PIN\n");
    printf("    --srk-seed=<hex32>       32-byte Storage Root Key primary seed\n");
    printf("    --mask=<hex>             24-bit PCR selection mask\n");
    printf("    --secret=<text>          Secret text string to seal\n");
    printf("    --auth=<pin>             Optional authorization PIN\n");
    printf("    --bank-in=<file>         PCR bank state file\n");
    printf("    --out=<file.sealed>      Output destination for sealed secret blob\n\n");

    printf("  unseal                     Unseal secret with live PCR bank, SRK seed, and PIN\n");
    printf("    --srk-seed=<hex32>       32-byte Storage Root Key primary seed\n");
    printf("    --in=<file.sealed>       Sealed secret blob to unlock\n");
    printf("    --auth=<pin>             Optional authorization PIN\n");
    printf("    --bank-in=<file>         PCR bank state file (default: clean reset bank)\n\n");

    printf("  quote                      Generate signed TPMS_ATTEST attestation quote\n");
    printf("    --aik-key=<hex32>        32-byte Attestation Identity Key (AIK)\n");
    printf("    --nonce=<hex32>          32-byte freshness challenge nonce\n");
    printf("    --mask=<hex>             24-bit PCR selection mask\n");
    printf("    --bank-in=<file>         PCR bank state file\n");
    printf("    --out=<file.json>        Output quote destination (default: stdout)\n\n");

    printf("  verify-quote               Verify TPMS_ATTEST attestation quote\n");
    printf("    --aik-key=<hex32>        32-byte Attestation Identity Key (AIK)\n");
    printf("    --nonce=<hex32>          Expected 32-byte freshness challenge nonce\n");
    printf("    --quote=<file.json>      Quote JSON file to verify\n");
    printf("    --bank-in=<file>         Expected PCR bank state file\n\n");

    printf("Global Options:\n");
    printf("  --version                  Show version and exit\n");
    printf("  --help, -h                 Show this help message and exit\n\n");
}

static bool save_bank_to_file(const char *filepath, const tpm2_pcr_bank_t *bank) {
    FILE *f = fopen(filepath, "wb");
    if (!f) return false;
    size_t w = fwrite(bank, 1, sizeof(*bank), f);
    fclose(f);
    return (w == sizeof(*bank));
}

static bool load_bank_from_file(const char *filepath, tpm2_pcr_bank_t *bank) {
    FILE *f = fopen(filepath, "rb");
    if (!f) return false;
    size_t r = fread(bank, 1, sizeof(*bank), f);
    fclose(f);
    return (r == sizeof(*bank));
}

/* Subcommand: scan */
static int cmd_scan(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Error: Missing policy manifest file path for 'scan'.\n");
        return 2;
    }

    const char *policy_path = argv[2];
    const char *format = "table";
    const char *out_file = NULL;
    bool use_color = isatty(fileno(stdout));

    for (int i = 3; i < argc; ++i) {
        if (strncmp(argv[i], "--format=", 9) == 0) {
            format = argv[i] + 9;
        } else if (strncmp(argv[i], "--output=", 9) == 0) {
            out_file = argv[i] + 9;
        } else if (strcmp(argv[i], "--no-color") == 0) {
            use_color = false;
        }
    }

    tpm2_policy_config_t config;
    if (!tpm2_parse_policy_json_file(policy_path, &config)) {
        fprintf(stderr, "Error: Failed to parse policy manifest: %s\n", policy_path);
        return 2;
    }

    tpm2_audit_report_t report;
    tpm2_audit_posture(&config, &report);

    FILE *out = stdout;
    if (out_file) {
        out = fopen(out_file, "w");
        if (!out) {
            fprintf(stderr, "Error: Cannot open output file %s\n", out_file);
            return 2;
        }
        use_color = false;
    }

    if (strcmp(format, "json") == 0) {
        lh_export_audit_json(out, &report);
    } else if (strcmp(format, "sarif") == 0) {
        lh_export_audit_sarif(out, &report);
    } else {
        lh_render_audit_table(out, &report, use_color);
    }

    if (out_file) {
        fclose(out);
    }

    return (report.score == 100) ? 0 : 1;
}

/* Subcommand: pcr-extend */
static int cmd_pcr_extend(int argc, char **argv) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    const char *bank_in = NULL;
    const char *bank_out = NULL;
    const char *boot_log = NULL;
    const char *data_str = NULL;
    const char *digest_hex = NULL;
    int pcr_idx = -1;
    uint32_t mask = 0;

    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], "--bank-in=", 10) == 0) {
            bank_in = argv[i] + 10;
        } else if (strncmp(argv[i], "--bank-out=", 11) == 0) {
            bank_out = argv[i] + 11;
        } else if (strncmp(argv[i], "--boot-log=", 11) == 0) {
            boot_log = argv[i] + 11;
        } else if (strncmp(argv[i], "--data=", 7) == 0) {
            data_str = argv[i] + 7;
        } else if (strncmp(argv[i], "--digest=", 9) == 0) {
            digest_hex = argv[i] + 9;
        } else if (strncmp(argv[i], "--pcr=", 6) == 0) {
            pcr_idx = atoi(argv[i] + 6);
        } else if (strncmp(argv[i], "--mask=", 7) == 0) {
            mask = (uint32_t)strtoul(argv[i] + 7, NULL, 0);
        }
    }

    if (bank_in) {
        if (!load_bank_from_file(bank_in, &bank)) {
            fprintf(stderr, "Error: Could not load PCR bank from %s\n", bank_in);
            return 2;
        }
    }

    if (boot_log) {
        tpm2_boot_log_t log;
        if (!tpm2_parse_boot_log_json_file(boot_log, &log)) {
            fprintf(stderr, "Error: Could not parse boot log %s\n", boot_log);
            return 2;
        }
        for (size_t i = 0; i < log.event_count; ++i) {
            tpm2_boot_event_t *ev = &log.events[i];
            if (ev->has_digest) {
                tpm2_pcr_extend_digest(&bank, ev->pcr_index, ev->digest);
            } else {
                tpm2_pcr_extend_data(&bank, ev->pcr_index, ev->data, strlen(ev->data));
            }
            mask |= (1U << ev->pcr_index);
        }
        printf("[+] Replayed %zu event log measurements into PCR bank.\n", log.event_count);
    }

    if (pcr_idx >= 0 && pcr_idx < TPM2_NUM_PCRS) {
        if (digest_hex) {
            uint8_t d[32];
            size_t act = 0;
            if (!lh_hex_to_bytes(digest_hex, d, 32, &act) || act != 32) {
                fprintf(stderr, "Error: Invalid 32-byte hex digest for --digest\n");
                return 2;
            }
            tpm2_pcr_extend_digest(&bank, (uint32_t)pcr_idx, d);
            mask |= (1U << pcr_idx);
        } else if (data_str) {
            tpm2_pcr_extend_data(&bank, (uint32_t)pcr_idx, data_str, strlen(data_str));
            mask |= (1U << pcr_idx);
        }
    }

    lh_render_pcr_table(stdout, &bank, mask, isatty(fileno(stdout)));

    if (bank_out) {
        if (!save_bank_to_file(bank_out, &bank)) {
            fprintf(stderr, "Error: Could not save PCR bank to %s\n", bank_out);
            return 2;
        }
        printf("[+] PCR bank state saved to %s\n", bank_out);
    }

    return 0;
}

/* Subcommand: policy-pcr */
static int cmd_policy_pcr(int argc, char **argv) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    const char *bank_in = NULL;
    uint32_t mask = 0;
    bool mask_given = false;

    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], "--mask=", 7) == 0) {
            mask = (uint32_t)strtoul(argv[i] + 7, NULL, 0);
            mask_given = true;
        } else if (strncmp(argv[i], "--bank-in=", 10) == 0) {
            bank_in = argv[i] + 10;
        }
    }

    if (!mask_given) {
        fprintf(stderr, "Error: Missing required argument --mask=<hex>\n");
        return 2;
    }

    if (bank_in) {
        if (!load_bank_from_file(bank_in, &bank)) {
            fprintf(stderr, "Error: Could not load PCR bank from %s\n", bank_in);
            return 2;
        }
    }

    tpm2_policy_pcr_t policy;
    tpm2_rc_t rc = tpm2_compute_policy_pcr(&bank, mask, &policy);
    if (rc != TPM_RC_SUCCESS) {
        fprintf(stderr, "Error: PolicyPCR computation failed (rc=%d)\n", rc);
        return 2;
    }

    char comp_hex[65];
    char pol_hex[65];
    lh_bytes_to_hex(policy.pcr_composite_digest, 32, comp_hex);
    lh_bytes_to_hex(policy.policy_digest, 32, pol_hex);

    printf("TPM 2.0 PolicyPCR Calculation (Trial Session TPM_CC_PolicyPCR = 0x0000017F):\n");
    printf("  Selection Mask   : 0x%06X\n", mask);
    printf("  Composite Digest : %s\n", comp_hex);
    printf("  Policy Digest    : %s\n", pol_hex);

    return 0;
}

/* Subcommand: seal */
static int cmd_seal(int argc, char **argv) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    const char *srk_hex = NULL;
    const char *secret_str = NULL;
    const char *auth_val = NULL;
    const char *out_file = NULL;
    const char *bank_in = NULL;
    uint32_t mask = 0;
    bool mask_given = false;

    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], "--srk-seed=", 11) == 0) {
            srk_hex = argv[i] + 11;
        } else if (strncmp(argv[i], "--mask=", 7) == 0) {
            mask = (uint32_t)strtoul(argv[i] + 7, NULL, 0);
            mask_given = true;
        } else if (strncmp(argv[i], "--secret=", 9) == 0) {
            secret_str = argv[i] + 9;
        } else if (strncmp(argv[i], "--auth=", 7) == 0) {
            auth_val = argv[i] + 7;
        } else if (strncmp(argv[i], "--out=", 6) == 0) {
            out_file = argv[i] + 6;
        } else if (strncmp(argv[i], "--bank-in=", 10) == 0) {
            bank_in = argv[i] + 10;
        }
    }

    if (!srk_hex || !mask_given || !secret_str || !out_file) {
        fprintf(stderr, "Error: seal requires --srk-seed=<hex32>, --mask=<hex>, --secret=<text>, and --out=<file.sealed>\n");
        return 2;
    }

    uint8_t srk_seed[32];
    size_t act = 0;
    if (!lh_hex_to_bytes(srk_hex, srk_seed, 32, &act) || act != 32) {
        fprintf(stderr, "Error: Invalid 32-byte hex for --srk-seed\n");
        return 2;
    }

    if (bank_in) {
        if (!load_bank_from_file(bank_in, &bank)) {
            fprintf(stderr, "Error: Could not load PCR bank from %s\n", bank_in);
            return 2;
        }
    }

    tpm2_policy_pcr_t policy;
    tpm2_compute_policy_pcr(&bank, mask, &policy);

    tpm2_sealed_blob_t blob;
    tpm2_rc_t rc = tpm2_seal_secret(srk_seed, &policy, auth_val, (const uint8_t *)secret_str, strlen(secret_str), &blob);
    if (rc != TPM_RC_SUCCESS) {
        fprintf(stderr, "Error: Sealing failed (rc=%d)\n", rc);
        return 2;
    }

    if (!tpm2_save_sealed_blob_file(out_file, &blob)) {
        fprintf(stderr, "Error: Failed to write sealed secret blob to %s\n", out_file);
        return 2;
    }

    char pol_hex[65];
    char tag_hex[65];
    char nonce_hex[33];
    lh_bytes_to_hex(blob.policy_digest, 32, pol_hex);
    lh_bytes_to_hex(blob.auth_tag, 32, tag_hex);
    lh_bytes_to_hex(blob.nonce, 16, nonce_hex);

    printf("[+] Successfully sealed secret (%u bytes) to %s\n", blob.ciphertext_len, out_file);
    printf("    PCR Mask      : 0x%06X\n", blob.pcr_mask);
    printf("    Policy Digest : %s\n", pol_hex);
    printf("    Nonce         : %s\n", nonce_hex);
    printf("    Auth Tag      : %s\n", tag_hex);

    lh_secure_zero_memory(srk_seed, sizeof(srk_seed));
    return 0;
}

/* Subcommand: unseal */
static int cmd_unseal(int argc, char **argv) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    const char *srk_hex = NULL;
    const char *in_file = NULL;
    const char *auth_val = NULL;
    const char *bank_in = NULL;

    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], "--srk-seed=", 11) == 0) {
            srk_hex = argv[i] + 11;
        } else if (strncmp(argv[i], "--in=", 5) == 0) {
            in_file = argv[i] + 5;
        } else if (strncmp(argv[i], "--auth=", 7) == 0) {
            auth_val = argv[i] + 7;
        } else if (strncmp(argv[i], "--bank-in=", 10) == 0) {
            bank_in = argv[i] + 10;
        }
    }

    if (!srk_hex || !in_file) {
        fprintf(stderr, "Error: unseal requires --srk-seed=<hex32> and --in=<file.sealed>\n");
        return 2;
    }

    uint8_t srk_seed[32];
    size_t act = 0;
    if (!lh_hex_to_bytes(srk_hex, srk_seed, 32, &act) || act != 32) {
        fprintf(stderr, "Error: Invalid 32-byte hex for --srk-seed\n");
        return 2;
    }

    if (bank_in) {
        if (!load_bank_from_file(bank_in, &bank)) {
            fprintf(stderr, "Error: Could not load PCR bank from %s\n", bank_in);
            return 2;
        }
    }

    tpm2_sealed_blob_t blob;
    if (!tpm2_load_sealed_blob_file(in_file, &blob)) {
        fprintf(stderr, "Error: Failed to load sealed blob from %s\n", in_file);
        return 2;
    }

    uint8_t unsealed[TPM2_MAX_SECRET_SIZE + 1];
    size_t unsealed_len = 0;

    tpm2_rc_t rc = tpm2_unseal_secret(srk_seed, &bank, auth_val, &blob, unsealed, &unsealed_len);
    lh_secure_zero_memory(srk_seed, sizeof(srk_seed));

    if (rc == TPM_RC_POLICY_FAIL) {
        fprintf(stderr, "[-] UNSEAL DENIED: PCR Policy Digest Mismatch! Measured platform state differs from sealing policy.\n");
        return 1;
    } else if (rc == TPM_RC_TAMPER) {
        fprintf(stderr, "[-] UNSEAL DENIED: Authentication Tag Mismatch / Incorrect PIN or Tampered Ciphertext.\n");
        return 1;
    } else if (rc != TPM_RC_SUCCESS) {
        fprintf(stderr, "[-] UNSEAL DENIED: TPM error code %d\n", rc);
        return 1;
    }

    unsealed[unsealed_len] = '\0';
    printf("[+] UNSEAL GRANTED: Secret recovered successfully:\n%s\n", (char *)unsealed);
    lh_secure_zero_memory(unsealed, sizeof(unsealed));

    return 0;
}

/* Subcommand: quote */
static int cmd_quote(int argc, char **argv) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    const char *aik_hex = NULL;
    const char *nonce_hex = NULL;
    const char *out_file = NULL;
    const char *bank_in = NULL;
    uint32_t mask = 0;
    bool mask_given = false;

    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], "--aik-key=", 10) == 0) {
            aik_hex = argv[i] + 10;
        } else if (strncmp(argv[i], "--nonce=", 8) == 0) {
            nonce_hex = argv[i] + 8;
        } else if (strncmp(argv[i], "--mask=", 7) == 0) {
            mask = (uint32_t)strtoul(argv[i] + 7, NULL, 0);
            mask_given = true;
        } else if (strncmp(argv[i], "--out=", 6) == 0) {
            out_file = argv[i] + 6;
        } else if (strncmp(argv[i], "--bank-in=", 10) == 0) {
            bank_in = argv[i] + 10;
        }
    }

    if (!aik_hex || !nonce_hex || !mask_given) {
        fprintf(stderr, "Error: quote requires --aik-key=<hex32>, --nonce=<hex32>, and --mask=<hex>\n");
        return 2;
    }

    uint8_t aik[32];
    uint8_t nonce[32];
    size_t act = 0;
    if (!lh_hex_to_bytes(aik_hex, aik, 32, &act) || act != 32) {
        fprintf(stderr, "Error: Invalid 32-byte hex for --aik-key\n");
        return 2;
    }
    if (!lh_hex_to_bytes(nonce_hex, nonce, 32, &act) || act != 32) {
        fprintf(stderr, "Error: Invalid 32-byte hex for --nonce\n");
        return 2;
    }

    if (bank_in) {
        if (!load_bank_from_file(bank_in, &bank)) {
            fprintf(stderr, "Error: Could not load PCR bank from %s\n", bank_in);
            return 2;
        }
    }

    tpm2_attest_quote_t quote;
    tpm2_rc_t rc = tpm2_generate_quote(&bank, mask, nonce, aik, 1000000ULL, 1, &quote);
    lh_secure_zero_memory(aik, sizeof(aik));

    if (rc != TPM_RC_SUCCESS) {
        fprintf(stderr, "Error: Quote generation failed (rc=%d)\n", rc);
        return 2;
    }

    char json_buf[1024];
    tpm2_format_quote_json(&quote, json_buf, sizeof(json_buf));

    if (out_file) {
        FILE *f = fopen(out_file, "w");
        if (!f) {
            fprintf(stderr, "Error: Failed to write quote to %s\n", out_file);
            return 2;
        }
        fputs(json_buf, f);
        fclose(f);
        printf("[+] Quote generated and saved to %s\n", out_file);
    } else {
        fputs(json_buf, stdout);
    }

    return 0;
}

/* Subcommand: verify-quote */
static int cmd_verify_quote(int argc, char **argv) {
    tpm2_pcr_bank_t bank;
    tpm2_pcr_reset(&bank);

    const char *aik_hex = NULL;
    const char *nonce_hex = NULL;
    const char *quote_file = NULL;
    const char *bank_in = NULL;

    for (int i = 2; i < argc; ++i) {
        if (strncmp(argv[i], "--aik-key=", 10) == 0) {
            aik_hex = argv[i] + 10;
        } else if (strncmp(argv[i], "--nonce=", 8) == 0) {
            nonce_hex = argv[i] + 8;
        } else if (strncmp(argv[i], "--quote=", 8) == 0) {
            quote_file = argv[i] + 8;
        } else if (strncmp(argv[i], "--bank-in=", 10) == 0) {
            bank_in = argv[i] + 10;
        }
    }

    if (!aik_hex || !nonce_hex || !quote_file) {
        fprintf(stderr, "Error: verify-quote requires --aik-key=<hex32>, --nonce=<hex32>, and --quote=<file.json>\n");
        return 2;
    }

    uint8_t aik[32];
    uint8_t nonce[32];
    size_t act = 0;
    if (!lh_hex_to_bytes(aik_hex, aik, 32, &act) || act != 32) {
        fprintf(stderr, "Error: Invalid 32-byte hex for --aik-key\n");
        return 2;
    }
    if (!lh_hex_to_bytes(nonce_hex, nonce, 32, &act) || act != 32) {
        fprintf(stderr, "Error: Invalid 32-byte hex for --nonce\n");
        return 2;
    }

    if (bank_in) {
        if (!load_bank_from_file(bank_in, &bank)) {
            fprintf(stderr, "Error: Could not load expected PCR bank from %s\n", bank_in);
            return 2;
        }
    }

    tpm2_attest_quote_t quote;
    if (!tpm2_parse_quote_json_file(quote_file, &quote)) {
        fprintf(stderr, "Error: Failed to parse quote from %s\n", quote_file);
        return 2;
    }

    tpm2_rc_t rc = tpm2_verify_quote(&quote, &bank, nonce, aik);
    lh_secure_zero_memory(aik, sizeof(aik));

    if (rc == TPM_RC_SUCCESS) {
        printf("[+] QUOTE VALIDATED: Platform measurements and signature verified under AIK.\n");
        return 0;
    } else if (rc == TPM_RC_TAMPER) {
        fprintf(stderr, "[-] QUOTE REJECTED: Nonce mismatch or replay attempt detected.\n");
        return 1;
    } else if (rc == TPM_RC_POLICY_FAIL) {
        fprintf(stderr, "[-] QUOTE REJECTED: PCR composite digest mismatch against expected bank.\n");
        return 1;
    } else if (rc == TPM_RC_AUTH_FAIL) {
        fprintf(stderr, "[-] QUOTE REJECTED: Cryptographic AIK signature verification failed.\n");
        return 1;
    } else {
        fprintf(stderr, "[-] QUOTE REJECTED: Validation failed with rc=%d\n", rc);
        return 1;
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_help(argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
        printf("%s v%s\n", LH_TOOL_NAME, LH_VERSION);
        return 0;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "help") == 0) {
        print_help(argv[0]);
        return 0;
    }

    if (strcmp(argv[1], "scan") == 0) {
        return cmd_scan(argc, argv);
    } else if (strcmp(argv[1], "pcr-extend") == 0) {
        return cmd_pcr_extend(argc, argv);
    } else if (strcmp(argv[1], "policy-pcr") == 0) {
        return cmd_policy_pcr(argc, argv);
    } else if (strcmp(argv[1], "seal") == 0) {
        return cmd_seal(argc, argv);
    } else if (strcmp(argv[1], "unseal") == 0) {
        return cmd_unseal(argc, argv);
    } else if (strcmp(argv[1], "quote") == 0) {
        return cmd_quote(argc, argv);
    } else if (strcmp(argv[1], "verify-quote") == 0) {
        return cmd_verify_quote(argc, argv);
    } else {
        fprintf(stderr, "Error: Unknown command '%s'. Run '%s --help' for usage.\n", argv[1], argv[0]);
        return 2;
    }
}
