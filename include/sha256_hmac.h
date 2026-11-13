#ifndef LH_SHA256_HMAC_H
#define LH_SHA256_HMAC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define LH_SHA256_BLOCK_SIZE 64
#define LH_SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buffer[LH_SHA256_BLOCK_SIZE];
} lh_sha256_ctx_t;

void lh_sha256_init(lh_sha256_ctx_t *ctx);
void lh_sha256_update(lh_sha256_ctx_t *ctx, const void *data, size_t len);
void lh_sha256_final(lh_sha256_ctx_t *ctx, uint8_t digest[LH_SHA256_DIGEST_SIZE]);
void lh_sha256_digest(const void *data, size_t len, uint8_t digest[LH_SHA256_DIGEST_SIZE]);

void lh_hmac_sha256(const void *key, size_t key_len,
                    const void *msg, size_t msg_len,
                    uint8_t out[LH_SHA256_DIGEST_SIZE]);

int lh_constant_time_memcmp(const void *a, const void *b, size_t len);
void lh_secure_zero_memory(void *v, size_t n);

void lh_bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out);
bool lh_hex_to_bytes(const char *hex_str, uint8_t *bytes_out, size_t max_len, size_t *actual_len);

#endif /* LH_SHA256_HMAC_H */
