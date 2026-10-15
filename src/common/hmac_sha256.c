// Minimal SHA-256 and HMAC-SHA256 (FIPS 180-4, RFC 2104).

#include <string.h>

#include "common/hmac_sha256.h"

typedef struct {
	uint32_t h[8];
	uint64_t len;
	unsigned char buf[64];
	size_t n;
} Sha256;

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
	0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
	0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
	0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
	0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
	0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
	0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void block(Sha256 *s, const unsigned char *p) {
	uint32_t w[64], a, b, c, d, e, f, g, h;
	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t) p[4 * i] << 24 | (uint32_t) p[4 * i + 1] << 16
			| (uint32_t) p[4 * i + 2] << 8 | p[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
	e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
	for (int i = 0; i < 64; i++) {
		uint32_t t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g))
			+ K[i] + w[i];
		uint32_t t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
		h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
	}
	s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
	s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void init(Sha256 *s) {
	static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
	memcpy(s->h, iv, sizeof(iv));
	s->len = 0;
	s->n = 0;
}

static void update(Sha256 *s, const unsigned char *p, size_t len) {
	s->len += len;
	while (len > 0) {
		size_t take = 64 - s->n < len ? 64 - s->n : len;
		memcpy(s->buf + s->n, p, take);
		s->n += take;
		p += take;
		len -= take;
		if (s->n == 64) {
			block(s, s->buf);
			s->n = 0;
		}
	}
}

static void final(Sha256 *s, unsigned char out[SHA256_LEN]) {
	uint64_t bits = s->len * 8;
	unsigned char pad = 0x80, zero = 0x00, lenb[8];
	update(s, &pad, 1);
	while (s->n != 56)
		update(s, &zero, 1);
	for (int i = 0; i < 8; i++)
		lenb[i] = (unsigned char) (bits >> (56 - 8 * i));
	update(s, lenb, 8);
	for (int i = 0; i < 8; i++) {
		out[4 * i] = (unsigned char) (s->h[i] >> 24);
		out[4 * i + 1] = (unsigned char) (s->h[i] >> 16);
		out[4 * i + 2] = (unsigned char) (s->h[i] >> 8);
		out[4 * i + 3] = (unsigned char) s->h[i];
	}
}

void sha256(const unsigned char *data, size_t len, unsigned char out[SHA256_LEN]) {
	Sha256 s;
	init(&s);
	update(&s, data, len);
	final(&s, out);
}

void hmac_sha256(const unsigned char *key, size_t keylen,
	const unsigned char *msg1, size_t len1,
	const unsigned char *msg2, size_t len2,
	unsigned char out[SHA256_LEN]) {
	unsigned char k[64], pad[64], inner[SHA256_LEN];
	memset(k, 0, sizeof(k));
	if (keylen > 64)
		sha256(key, keylen, k);
	else
		memcpy(k, key, keylen);
	Sha256 s;
	for (int i = 0; i < 64; i++)
		pad[i] = k[i] ^ 0x36;
	init(&s);
	update(&s, pad, 64);
	update(&s, msg1, len1);
	update(&s, msg2, len2);
	final(&s, inner);
	for (int i = 0; i < 64; i++)
		pad[i] = k[i] ^ 0x5c;
	init(&s);
	update(&s, pad, 64);
	update(&s, inner, SHA256_LEN);
	final(&s, out);
}
