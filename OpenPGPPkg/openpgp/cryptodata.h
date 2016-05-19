#pragma once

#include "iobuffer.h"

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

/* RSA public key data parsed from public key packet */

struct RSA_pubkey {
	uint32_t rsa_nlen;
	uint32_t rsa_elen;
	uint8_t keyhash[20];
	uint8_t RSA_n[1024];
	uint8_t RSA_e[1024];
};

/* signature data parsed from signature packet */

struct parse_data {
	uint32_t hashlen;
	uint8_t hashdata[1024];
	uint32_t siglen;
	uint8_t sigdata[1024];
	uint8_t issuer[8];
	uint8_t hashleft[2];
	uint8_t hashalgo;
};

enum HashAlgo {
	HASH_MD5=1,
	HASH_SHA1,
	HASH_RIPEMD160,
	HASH_SHA256=8,
	HASH_SHA384,
	HASH_SHA512,
	HASH_SHA224
};

int parse_pubkey(uint8_t *buff, struct RSA_pubkey *rsa_info);
int find_pubkey(uint8_t *buff, int bufflen, struct RSA_pubkey *rsa_info, const uint8_t *keyid);
int parse_pgpdata(uint8_t *buffer, struct parse_data *pgpdata);
/* verify RSA signature */
int sigverify(
	const uint8_t *sigdata, uint32_t siglen_bytes,
	uint8_t hashalgo, const uint8_t *digest_toverify,
	struct RSA_pubkey *pubkey);
int pgpverify(struct RSA_pubkey*, struct parse_data*, struct IO_buffer*);
