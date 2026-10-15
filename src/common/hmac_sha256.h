// Minimal SHA-256 and HMAC-SHA256 (FIPS 180-4, RFC 2104) for the socket audio
// device handshake.  Public domain style implementation, no dependencies.

#ifndef HMAC_SHA256_H
#define HMAC_SHA256_H

#include <stddef.h>
#include <stdint.h>

#define SHA256_LEN 32

void sha256(const unsigned char *data, size_t len, unsigned char out[SHA256_LEN]);

// HMAC-SHA256(key, msg1 || msg2)
void hmac_sha256(const unsigned char *key, size_t keylen,
	const unsigned char *msg1, size_t len1,
	const unsigned char *msg2, size_t len2,
	unsigned char out[SHA256_LEN]);

#endif
