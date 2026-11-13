#include "sha256_hmac.h"
#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static void sha256_transform(lh_sha256_ctx_t *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    size_t i, j;

    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = ((uint32_t)data[j] << 24) |
               ((uint32_t)data[j + 1] << 16) |
               ((uint32_t)data[j + 2] << 8) |
               ((uint32_t)data[j + 3]);
    }
    for (; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void lh_sha256_init(lh_sha256_ctx_t *ctx) {
    ctx->count = 0;
    ctx->state[0] = 0x6a09e667U;
    ctx->state[1] = 0xbb67ae85U;
    ctx->state[2] = 0x3c6ef372U;
    ctx->state[3] = 0xa54ff53aU;
    ctx->state[4] = 0x510e527fU;
    ctx->state[5] = 0x9b05688cU;
    ctx->state[6] = 0x1f83d9abU;
    ctx->state[7] = 0x5be0cd19U;
}

void lh_sha256_update(lh_sha256_ctx_t *ctx, const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t buffer_idx = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    while (len > 0) {
        size_t to_copy = 64 - buffer_idx;
        if (to_copy > len) {
            to_copy = len;
        }
        memcpy(&ctx->buffer[buffer_idx], p, to_copy);
        buffer_idx += to_copy;
        p += to_copy;
        len -= to_copy;

        if (buffer_idx == 64) {
            sha256_transform(ctx, ctx->buffer);
            buffer_idx = 0;
        }
    }
}

void lh_sha256_final(lh_sha256_ctx_t *ctx, uint8_t digest[LH_SHA256_DIGEST_SIZE]) {
    uint8_t pad = 0x80;
    uint64_t total_bits = ctx->count * 8;
    uint8_t len_bytes[8];
    size_t i;

    for (i = 0; i < 8; ++i) {
        len_bytes[7 - i] = (uint8_t)(total_bits >> (i * 8));
    }

    lh_sha256_update(ctx, &pad, 1);
    while ((ctx->count & 0x3F) != 56) {
        uint8_t zero = 0;
        lh_sha256_update(ctx, &zero, 1);
    }
    lh_sha256_update(ctx, len_bytes, 8);

    for (i = 0; i < 4; ++i) {
        digest[i]      = (uint8_t)(ctx->state[0] >> (24 - i * 8));
        digest[i + 4]  = (uint8_t)(ctx->state[1] >> (24 - i * 8));
        digest[i + 8]  = (uint8_t)(ctx->state[2] >> (24 - i * 8));
        digest[i + 12] = (uint8_t)(ctx->state[3] >> (24 - i * 8));
        digest[i + 16] = (uint8_t)(ctx->state[4] >> (24 - i * 8));
        digest[i + 20] = (uint8_t)(ctx->state[5] >> (24 - i * 8));
        digest[i + 24] = (uint8_t)(ctx->state[6] >> (24 - i * 8));
        digest[i + 28] = (uint8_t)(ctx->state[7] >> (24 - i * 8));
    }
}

void lh_sha256_digest(const void *data, size_t len, uint8_t digest[LH_SHA256_DIGEST_SIZE]) {
    lh_sha256_ctx_t ctx;
    lh_sha256_init(&ctx);
    lh_sha256_update(&ctx, data, len);
    lh_sha256_final(&ctx, digest);
    lh_secure_zero_memory(&ctx, sizeof(ctx));
}

void lh_hmac_sha256(const void *key, size_t key_len,
                    const void *msg, size_t msg_len,
                    uint8_t out[LH_SHA256_DIGEST_SIZE]) {
    uint8_t k_pad[LH_SHA256_BLOCK_SIZE];
    uint8_t tk[LH_SHA256_DIGEST_SIZE];
    uint8_t inner_hash[LH_SHA256_DIGEST_SIZE];
    lh_sha256_ctx_t ctx;
    size_t i;

    if (key_len > LH_SHA256_BLOCK_SIZE) {
        lh_sha256_digest(key, key_len, tk);
        key = tk;
        key_len = LH_SHA256_DIGEST_SIZE;
    }

    memset(k_pad, 0, sizeof(k_pad));
    memcpy(k_pad, key, key_len);

    /* Inner hash: SHA256(k_pad ^ 0x36 || msg) */
    for (i = 0; i < LH_SHA256_BLOCK_SIZE; ++i) {
        k_pad[i] ^= 0x36;
    }
    lh_sha256_init(&ctx);
    lh_sha256_update(&ctx, k_pad, LH_SHA256_BLOCK_SIZE);
    lh_sha256_update(&ctx, msg, msg_len);
    lh_sha256_final(&ctx, inner_hash);

    /* Outer hash: SHA256(k_pad ^ 0x5C || inner_hash) */
    for (i = 0; i < LH_SHA256_BLOCK_SIZE; ++i) {
        k_pad[i] ^= (0x36 ^ 0x5C);
    }
    lh_sha256_init(&ctx);
    lh_sha256_update(&ctx, k_pad, LH_SHA256_BLOCK_SIZE);
    lh_sha256_update(&ctx, inner_hash, LH_SHA256_DIGEST_SIZE);
    lh_sha256_final(&ctx, out);

    /* Clean sensitive keys from stack */
    lh_secure_zero_memory(k_pad, sizeof(k_pad));
    lh_secure_zero_memory(tk, sizeof(tk));
    lh_secure_zero_memory(inner_hash, sizeof(inner_hash));
    lh_secure_zero_memory(&ctx, sizeof(ctx));
}

int lh_constant_time_memcmp(const void *a, const void *b, size_t len) {
    const uint8_t *p1 = (const uint8_t *)a;
    const uint8_t *p2 = (const uint8_t *)b;
    uint8_t diff = 0;
    size_t i;

    for (i = 0; i < len; ++i) {
        diff |= (p1[i] ^ p2[i]);
    }
    return (int)diff;
}

void lh_secure_zero_memory(void *v, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) {
        *p++ = 0;
    }
}

void lh_bytes_to_hex(const uint8_t *bytes, size_t len, char *hex_out) {
    static const char hex_chars[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; ++i) {
        hex_out[i * 2]     = hex_chars[(bytes[i] >> 4) & 0x0F];
        hex_out[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex_out[len * 2] = '\0';
}

bool lh_hex_to_bytes(const char *hex_str, uint8_t *bytes_out, size_t max_len, size_t *actual_len) {
    size_t str_len;
    size_t count;
    size_t i;

    if (!hex_str || !bytes_out) {
        return false;
    }
    if (hex_str[0] == '0' && (hex_str[1] == 'x' || hex_str[1] == 'X')) {
        hex_str += 2;
    }

    str_len = strlen(hex_str);
    if (str_len % 2 != 0) {
        return false;
    }
    count = str_len / 2;
    if (count > max_len) {
        return false;
    }

    for (i = 0; i < count; ++i) {
        char c1 = hex_str[i * 2];
        char c2 = hex_str[i * 2 + 1];
        uint8_t v1, v2;

        if (c1 >= '0' && c1 <= '9') v1 = (uint8_t)(c1 - '0');
        else if (c1 >= 'a' && c1 <= 'f') v1 = (uint8_t)(c1 - 'a' + 10);
        else if (c1 >= 'A' && c1 <= 'F') v1 = (uint8_t)(c1 - 'A' + 10);
        else return false;

        if (c2 >= '0' && c2 <= '9') v2 = (uint8_t)(c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f') v2 = (uint8_t)(c2 - 'a' + 10);
        else if (c2 >= 'A' && c2 <= 'F') v2 = (uint8_t)(c2 - 'A' + 10);
        else return false;

        bytes_out[i] = (uint8_t)((v1 << 4) | v2);
    }

    if (actual_len) {
        *actual_len = count;
    }
    return true;
}
