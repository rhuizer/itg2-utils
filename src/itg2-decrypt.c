#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include "itg2-file.h"

#define MIN(x, y)	((x) <= (y) ? (x) : (y))

static inline uint8_t __hex_decode_nybble(char c)
{
        uint8_t ret = 0;

        if (c >= '0' && c <= '9')
                ret |= (c - '0');
        else if (c >= 'a' && c <= 'f')
                ret |= (c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
                ret |= (c - 'A' + 10);

        return ret;
}

/* Caller must ensure dest can hold src. */
void hex_decode(uint8_t *dest, const char *src)
{
	while (src[0] != '\0' && src[1] != '\0') {
		*dest++ = (__hex_decode_nybble(src[0]) << 4) |
		           __hex_decode_nybble(src[1]);
		src += 2;
	}
}

int main(int argc, char **argv)
{
	unsigned char block[16];
	unsigned char ivec[16];
	struct itg2_file *file;
	unsigned char pt[16];
	uint8_t aes_key[24];
	uint32_t count;
	uint8_t *key;
	int b, i;

	if (argc < 2) {
		fprintf(stderr, "Use as: %s <filename> [aes key]\n",
		        argv[0] ?: "");
		exit(EXIT_FAILURE);
	}

	/* Verify if the provided key is sane. */
	if (argv[2] && strlen(argv[2]) != 48) {
		fprintf(stderr, "Key should be a hex string of 48 bytes.\n");
		exit(EXIT_FAILURE);
	}

	/* Decode the provided key. */
	if (argv[2]) {
		hex_decode(aes_key, argv[2]);
		key = aes_key;
	} else {
		key = NULL;
	}

	if ( (file = itg2_file_open(argv[1], "r", key)) == NULL) {
		itg2_file_perror();
		exit(EXIT_FAILURE);
	}

	itg2_file_fprint(stderr, file);

	b = 0;
	count = 0;
	memset(ivec, 0, 16);
	while (!feof(file->fp) || count >= file->header.file_size) {
		uint32_t left;

		/* Read the ciphertext. */
		if (fread(block, 1, sizeof(block), file->fp) != sizeof(block))
			exit(EXIT_FAILURE);

		/* Reset the IV every 255 blocks to avoid fault propagation. */
		if (b % 255 == 0)
			memset(ivec, 0, 16);
		b = (b + 1) % 255;

		/* Now reintroduce the subtraction used in ITG2 CBC mode. */
		for (i = 0; i < 16; i++)
			ivec[i] -= i;

		/* Decrypt it. */
		AES_cbc_encrypt(block, pt, 16, &file->key, ivec, 0);

		/* Determine the bytes left. */
		left = MIN(16, file->header.file_size - count);

		if (fwrite(pt, 1, left, stdout) != left)
			exit(EXIT_FAILURE);

		count += left;
	}
}
