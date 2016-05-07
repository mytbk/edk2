#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>
#include "cryptodata.h"

#define puts(x) {}

struct PGP_pubkeypkt {
	uint8_t ver; /* must be 4 */
	uint8_t time[4];
	uint8_t algo;
	uint8_t keyvalue[0]; /* for RSA, it's MPI n, and MPI e */
};

int
MPI_parse(const uint8_t *buff, uint32_t *len, uint8_t *mpi_store)
{
	uint32_t l = buff[0]*256+buff[1];
	uint32_t l_in_byte = (l+7)/8;

	if (len!=NULL && mpi_store!=NULL) {
		*len = l;
		memcpy(mpi_store, buff+2, l_in_byte);
		return 2+l_in_byte;
	} else {
		return -1;
	}
}
/* parse_pubkey: parse public key packet
	@input buff: the whole packet, PTag==0x99
	@output rsa_info: RSA key info
*/
int
parse_pubkey(uint8_t *buff, struct RSA_pubkey *rsa_info)
{
	uint32_t pktlen;
	SHA_CTX ctx;
	struct PGP_pubkeypkt *keypkt;
	int l;

	if (rsa_info==NULL) {
		puts("NULL pointer received!\n");
		return -1;
	}

	if (buff[0]!=0x99) {
		puts("Not a supported public key packet!\n");
		return -1;
	}

	pktlen = buff[1]*256+buff[2];
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, buff, pktlen+3);
	SHA1_Final(rsa_info->keyhash, &ctx);

	keypkt = (struct PGP_pubkeypkt*)(buff+3);

	if (keypkt->ver!=4) {
		puts("Not a version 4 packet!\n");
		return -1;
	}

	l = MPI_parse(keypkt->keyvalue, &rsa_info->rsa_nlen, rsa_info->RSA_n);
	if (l<0) {
		puts("MPI RSA modulus n parse error!\n");
		return -1;
	}
	if (MPI_parse(keypkt->keyvalue+l, &rsa_info->rsa_elen, rsa_info->RSA_e)<0) {
		puts("MPI RSA encryption exponent e parse error!\n");
		return -1;
	}

	return 0;
}
