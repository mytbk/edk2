#ifdef EFIAPI
#include <Library/UefiLib.h>
#else
#include <stdio.h>
#define AsciiPrint printf
#endif

#include <string.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include "cryptodata.h"
#include "iobuffer.h"

union shactx {
	SHA_CTX shactx;
	SHA256_CTX sha256ctx;
	SHA512_CTX sha512ctx;
};

uint8_t md5_header[] = {
	0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00,
	0x04, 0x10};
uint8_t sha1_header[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
	0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
};
uint8_t sha256_header[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
	0x00, 0x04, 0x20
};
uint8_t sha512_header[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
	0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
	0x00, 0x04, 0x40
};
/*
uint8_t *hash_headers[] = {
	.HASH_MD5 = md5_header,
	.HASH_SHA1 = sha1_header,
	.HASH_SHA256 = sha256_header,
	.HASH_SHA512 = sha512_header
};
*/
static int
digest_len(uint8_t algo)
{
	switch (algo) {
	case HASH_SHA1:
		return SHA_DIGEST_LENGTH;
	case HASH_SHA256:
		return SHA256_DIGEST_LENGTH;
	case HASH_SHA512:
		return SHA512_DIGEST_LENGTH;
	default:
		return -1;
	}
}
static int
pkcs1_emsa_encode(uint8_t hashalgo, const uint8_t *hash, uint32_t hashlen, uint32_t emLen,
	uint8_t *EM)
{
	uint8_t *hash_header = NULL;
	uint32_t tLen = hashlen;
	uint32_t psLen;

	switch (hashalgo) {
	case HASH_MD5:
		hash_header = md5_header;
		tLen += sizeof(md5_header);
		break;
	case HASH_SHA1:
		hash_header = sha1_header;
		tLen += sizeof(sha1_header);
		break;
	case HASH_SHA256:
		hash_header = sha256_header;
		tLen += sizeof(sha256_header);
		break;
	case HASH_SHA512:
		hash_header = sha512_header;
		tLen += sizeof(sha512_header);
		break;
	default:
		AsciiPrint("pkcs1_emsa_encode: hash algorithm unsupported!\n");
		return -1;
	}

	memcpy(EM+emLen-hashlen, hash, hashlen);
	memcpy(EM+emLen-tLen, hash_header, tLen-hashlen);

	psLen = emLen-tLen-3;
	EM[0] = 0;
	EM[1] = 1;
	EM[psLen+2] = 0;
	while (psLen) {
		psLen--;
		EM[psLen+2] = 0xff;
	}
	return 0;
}

int sha_init(union shactx *ctx, uint8_t algo)
{
	switch (algo) {
	case HASH_SHA1:
		return SHA1_Init(&ctx->shactx);
	case HASH_SHA256:
		return SHA256_Init(&ctx->sha256ctx);
	case HASH_SHA512:
		return SHA512_Init(&ctx->sha512ctx);
	default:
		AsciiPrint("Hash algorithm not supported!\n");
		return -1;
	}
}

int sha_update(union shactx *ctx, const void *d, size_t l, uint8_t algo)
{
	switch (algo) {
	case HASH_SHA1:
		return SHA1_Update(&ctx->shactx, d, l);
	case HASH_SHA256:
		return SHA256_Update(&ctx->sha256ctx, d, l);
	case HASH_SHA512:
		return SHA512_Update(&ctx->sha512ctx, d, l);
	default:
		AsciiPrint("Hash algorithm not supported!\n");
		return -1;
	}
}

int sha_final(unsigned char *md, union shactx *ctx, uint8_t algo)
{
	switch (algo) {
	case HASH_SHA1:
		return SHA1_Final(md, &ctx->shactx);
	case HASH_SHA256:
		return SHA256_Final(md, &ctx->sha256ctx);
	case HASH_SHA512:
		return SHA512_Final(md, &ctx->sha512ctx);
	default:
		AsciiPrint("Hash algorithm not supported!\n");
		return -1;
	}
}

int sigverify(
	const uint8_t *sigdata, uint32_t siglen_bytes,
	uint8_t hashalgo, const uint8_t *digest_toverify,
	struct RSA_pubkey *pubkey)
{
	int result = 0;

	BIGNUM *sigmsg = BN_bin2bn(sigdata, siglen_bytes, NULL);
	BIGNUM *rsa_e = BN_bin2bn(pubkey->RSA_e, (pubkey->rsa_elen+7)/8, NULL);
	BIGNUM *rsa_n = BN_bin2bn(pubkey->RSA_n, (pubkey->rsa_nlen+7)/8, NULL);
	BIGNUM *em = BN_new();
	BN_CTX *bnctx = BN_CTX_new();
	BN_mod_exp(em, sigmsg, rsa_e, rsa_n, bnctx);

	uint8_t em2str[1024];
	uint32_t emLen = siglen_bytes;

	if (pkcs1_emsa_encode(hashalgo,
								 digest_toverify,
								 digest_len(hashalgo),
								 emLen,
								 em2str)<0) {
		AsciiPrint("PKCS#1_EMSA_Encode error!\n");
		result = 0;
		goto finish;
	}
	BIGNUM *em2 = BN_bin2bn(em2str, emLen, NULL);
	/* compare em and em2, if equal then verify success */
	if (BN_cmp(em,em2)==0) {
		result = 1;
	} else {
		result = 0;
	}

	BN_free(em2);
finish:
	BN_free(sigmsg);
	BN_free(rsa_e);
	BN_free(rsa_n);
	BN_free(em);
	BN_CTX_free(bnctx);

	return result;
}

/* pgpverify:
	@input parsed public key, signature data, an IO buffer
	@output 1 if success and 0 if fail
*/
int
pgpverify(struct RSA_pubkey *pubkey,
			 struct parse_data *sigdata,
			 struct IO_buffer *buffer)
{
	union shactx ctx;
	size_t len;
	uint8_t trailer[6];
	uint8_t digest_toverify[100];

	sha_init(&ctx, sigdata->hashalgo);
	while (!buffer->ioeof(buffer)) {
		len = buffer->ioread(buffer);
		sha_update(&ctx, buffer->buffer, len, sigdata->hashalgo);
	}
	buffer->ioclose(buffer);
	sha_update(&ctx, sigdata->hashdata, sigdata->hashlen, sigdata->hashalgo);
	/* a trailer is needed to hash */
	trailer[0] = 0x04;
	trailer[1] = 0xff;
	trailer[2] = sigdata->hashlen >> 24;
	trailer[3] = sigdata->hashlen >> 16;
	trailer[4] = sigdata->hashlen >> 8;
	trailer[5] = sigdata->hashlen;
	sha_update(&ctx, trailer, 6, sigdata->hashalgo);
	sha_final(digest_toverify, &ctx, sigdata->hashalgo);

	if (digest_toverify[0]==sigdata->hashleft[0] &&
		 digest_toverify[1]==sigdata->hashleft[1]) {
		AsciiPrint("hashleft verify success!\n");
	} else {
		AsciiPrint("hashleft bad!\n");
		return 0;
	}

	return sigverify(
		sigdata->sigdata, (sigdata->siglen+7)/8,
		sigdata->hashalgo, digest_toverify,
		pubkey);
}
