#ifdef EFIAPI
#include <Uefi.h>
#include <Library/UefiLib.h>
#else
#include <stdio.h>
#define AsciiPrint printf
#endif

#include <openssl/sha.h>
#include <string.h>
#include "cryptodata.h"

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
	struct PGP_pubkeypkt *keypkt;
	int l;

	if (rsa_info==NULL) {
		AsciiPrint("NULL pointer received!\n");
		return -1;
	}

	switch ((buff[0]>>2)&0xf) {
	case 6: /* primary key */
	case 14: /* subkey */
		break;
	default:
		AsciiPrint("Not a supported public key packet!\n");
		return -1;
	}

	/* to compute fingerprint, the first byte should be 0x99 */
	buff[0] = 0x99;
	pktlen = buff[1]*256+buff[2];
	SHA1(buff, pktlen+3, rsa_info->keyhash);

	keypkt = (struct PGP_pubkeypkt*)(buff+3);

	if (keypkt->ver!=4) {
		AsciiPrint("Not a version 4 packet!\n");
		return -1;
	}

	l = MPI_parse(keypkt->keyvalue, &rsa_info->rsa_nlen, rsa_info->RSA_n);
	if (l<0) {
		AsciiPrint("MPI RSA modulus n parse error!\n");
		return -1;
	}
	if (MPI_parse(keypkt->keyvalue+l, &rsa_info->rsa_elen, rsa_info->RSA_e)<0) {
		AsciiPrint("MPI RSA encryption exponent e parse error!\n");
		return -1;
	}

	return 0;
}

/* use parse_pubkey to find a primary/sub key with keyid */
int
find_pubkey(uint8_t *buff, int bufflen, struct RSA_pubkey *rsa_info, uint8_t *keyid)
{
	uint8_t tag = buff[0];
	uint32_t length;
	if (parse_pubkey(buff, rsa_info)==0) {
		if (*(unsigned long long*)keyid ==
			 *(unsigned long long*)(rsa_info->keyhash+12)) {
			return 0;
		} else {
			AsciiPrint("incorrect key fingerprint:\n");
			for (int i=0; i<20; i++) {
				AsciiPrint("%02x ", rsa_info->keyhash[i]);
			}
			AsciiPrint("\n");
		}
	}
	switch (tag&3) {
	case 0:
		length = buff[1];
		buff += 2+length;
		bufflen -= 2+length;
		break;
	case 1:
		length = (buff[1]<<8)|buff[2];
		buff += 3+length;
		bufflen -= 3+length;
		break;
	case 2:
		length = (buff[1]<<24)|(buff[2]<<16)|(buff[3]<<8)|(buff[4]);
		buff += 5+length;
		bufflen -= 5+length;
		break;
	default: /* unsupported */
		return -1;
	}
	if (bufflen>0) {
		return find_pubkey(buff, bufflen, rsa_info, keyid);
	} else {
		return -1;
	}
}
