#include <stdio.h>
#include <string.h>
#include "cryptodata.h"

#define perror(x) {}

struct sigpktv4 {
	uint8_t ver; /* should be 4*/
	uint8_t sigtype;
	uint8_t pubalgo;
	uint8_t hashalgo;
	uint8_t hashsublen[2];
	uint8_t hashsub[0];
};

static uint32_t
imm32be(const uint8_t *buff, int len)
{
	int i;
	uint32_t sum=0;

	for (i=0; i<len; i++) {
		sum = sum*256+buff[i];
	}
	return sum;
}

/* parse signature subpacket,
	return the length parsed
*/
int
parse_subpacket(const uint8_t *buff, uint8_t *issuer)
{
	uint32_t packlen;
	uint8_t packtype;

	if (buff[0]<192) {
		packlen = buff[0];
		buff += 1;
	} else {
		perror("Unsupported signature subpacket length.\n");
		return -1;
	}

	packtype = *buff;

	if (packtype==16) {
		/* issuer type */
		if (packlen!=9) {
			perror("Incorrect length of issuer subpacket type.\n");
			return -1;
		}
		*(unsigned long long*)issuer = *(unsigned long long*)(buff+1);
	}

	return packlen+1;
}

int
parse_pgpdata(uint8_t *buffer, struct parse_data *pgpdata)
{
	uint8_t PTag = buffer[0];
	uint8_t packettag = 0;
	uint8_t *parse_buf = buffer;
	// uint32_t packetlen = 0;
	uint32_t hashlen = 0;
	uint32_t unhashlen = 0;

	if (pgpdata==NULL) {
		perror("pgpdata==NULL\n");
		return -1;
	}

	if ((PTag&0x80)==0) {
		perror("Invalid packet.\n");
		return -1;
	}

	if ((PTag&0x40)==1) {
		perror("New packet format not supported.\n");
		return -1;
	} else {
		/* old format */
		packettag = (PTag>>2)&0xf;
		switch (PTag&0x3) {
		case 0:
			// packetlen = buffer[1];
			parse_buf += 2;
			break;
		case 1:
			// packetlen = imm32be(buffer+1, 2);
			parse_buf += 3;
			break;
		case 2:
			// packetlen = imm32be(buffer+1, 4);
			parse_buf += 5;
			break;
		case 3:
		default:
			perror("Indeterminate length packet not supported!\n");
			return -1;
		}
	}

	if (packettag!=2) {
		perror("Not a signature packet!\n");
		return -1;
	}

	struct sigpktv4 *sigpkt = (struct sigpktv4*)parse_buf;

	if (sigpkt->ver!=4) {
		perror("Not a version 4 signature packet!\n");
		return -1;
	}

	if (sigpkt->sigtype!=0) {
		perror("Not a binary document signature!\n");
		return -1;
	}

	hashlen = imm32be(sigpkt->hashsublen, 2);
	parse_buf += 6+hashlen;
	pgpdata->hashlen = (void*)parse_buf-(void*)sigpkt;
	memcpy(pgpdata->hashdata, (uint8_t*)sigpkt, pgpdata->hashlen);
	pgpdata->hashalgo = sigpkt->hashalgo;

	/* to parse unhashed part */
	unhashlen = imm32be(parse_buf, 2);
	parse_buf += 2;

	while (unhashlen>0) {
		int parselen = parse_subpacket(parse_buf, pgpdata->issuer);
		if (parselen==-1) {
			perror("Parse subpacket error.\n");
			return -1;
		}
		parse_buf += parselen;
		unhashlen -= parselen;
	}

	pgpdata->hashleft[0] = parse_buf[0];
	pgpdata->hashleft[1] = parse_buf[1];
	parse_buf += 2;

	/* to parse the signature */
	pgpdata->siglen = imm32be(parse_buf, 2);
	memcpy(pgpdata->sigdata, parse_buf+2, (pgpdata->siglen+7)/8);

	return 0;
}

#ifdef SIMPLE_TEST
int
main(int argc, char* argv[])
{
	FILE *fp=NULL;
	char buffer[1024];
	int flen;
	struct parse_data pgpdata;

	if (argc>1) {
		fp = fopen(argv[1], "r");
	}
	if (fp==NULL) {
		return 1;
	}

	flen = fread(buffer, 1, 1024, fp);
	if (flen==1024) {
		return 1;
	}

	parse_pgpdata(buffer, &pgpdata);

	printf("length of hashed data: %d\n", pgpdata.hashlen);
	printf("bits of signature: %d\n", pgpdata.siglen);
	printf("issuer: ");
	for (int i=0; i<8; i++) {
		printf("%02x", pgpdata.issuer[i]);
	}
	printf("\n");

	return 0;
}
#endif
