#include "cryptodata.h"
#include <stdio.h>

/* usage: <prog> pubkey.gpg signature.sig data */

int
main(int argc, char* argv[])
{
	FILE *fpub, *fsig, *fdata;
	struct RSA_pubkey pubkey;
	struct parse_data sigdata;
	uint8_t buffer[4096];
	int len;

	if (argc<4) {
		perror("usage: <prog> pubkey.gpg signature.sig data\n");
		return 1;
	}

	fpub = fopen(argv[1], "r");
	if (fpub==NULL) {
		perror("Open public key file error!\n");
		return 1;
	}
	len = fread(buffer, 1, 4096, fpub);
	if (len>=4096) {
		perror("Public key file too large.\n");
		return 1;
	}
	if (parse_pubkey(buffer, &pubkey)<0) {
		perror("Parse public key packet error!\n");
		return 1;
	}
	fclose(fpub);

	fsig = fopen(argv[2], "r");
	if (fsig==NULL) {
		perror("Open signature file error!\n");
		return 1;
	}
	len = fread(buffer, 1, 4096, fsig);
	if (len>=4096) {
		perror("Signature file too large.\n");
		return 1;
	}
	if (parse_pgpdata(buffer, &sigdata)<0) {
		perror("Parse signature data error!\n");
		return 1;
	}
	fclose(fsig);

	fdata = fopen(argv[3], "r");
	if (fdata==NULL) {
		perror("Open signed file error!\n");
		return 1;
	}
	struct IO_buffer buf;
	buf.handle = (void*)fdata;
	buf.buffer = buffer;
	buf.ioread = c_file_buffer.ioread;
	buf.ioeof = c_file_buffer.ioeof;
	buf.ioclose = c_file_buffer.ioclose;

	pgpverify(&pubkey, &sigdata, &buf);

	return 0;
}
