/* itg2-file.c
 *
 * ITG2 data and patch file encryption and decryption routines.
 *
 * Dedicated to Yuzuyu Arielle Huizer.
 *
 * Copyright (C) 2011-2016 Ronald Huizer <r.huizer@xs4all.nl>
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/sha.h>
#include "getput.h"
#include "itg2-file.h"

#define ITG2_PATCH_KEY "58691958710496814910943867304986071324198643072"
#define ITG2_DATA_VERIFICATION_BLOCK ":D"
#define ITG2_PATCH_VERIFICATION_BLOCK ":DGROWBALLZPLEEZ"

enum error_code {
	ERROR_SUCCESS,
	ERROR_ALLOCATION,
	ERROR_OPEN,
	ERROR_INVALID_HEADER,
	ERROR_SHA512,
	ERROR_AES_KEY,
	ERROR_AES_KEY_SCHEDULING,
	ERROR_VERIFICATION_BLOCK
};

static char *__errors[] = {
	"Success",
	"Failed to allocate memory",
	"Failed to open file",
	"Invalid crypted file header",
	"Failed to calculate SHA512 hash",
	"Decrypting data file, but no AES key provided",
	"Failed to initialize AES-192 encryption key",
	"Invalid verification block"
};

/* XXX: not thread safe or reentrant. */
static int __error = 0;

static int __get_patch_file_key(struct itg2_file *file)
{
	unsigned char hash[SHA512_DIGEST_LENGTH];
	SHA512_CTX ctx;

	if (SHA512_Init(&ctx) == 0)
		return -1;

	if (SHA512_Update(&ctx, file->header.subkey,
	                  file->header.subkey_size) == 0)
		return -1;

	if (SHA512_Update(&ctx, ITG2_PATCH_KEY,
	                  sizeof(ITG2_PATCH_KEY) - 1) == 0)
		return -1;

	if (SHA512_Final(hash, &ctx) == 0)
		return -1;

	memcpy(file->aes_key, hash, sizeof(file->aes_key));

	return 0;
}

struct itg2_file *
itg2_file_open(const char *pathname, const char *mode, const uint8_t *key)
{
	struct itg2_file *file;
	char buf[4];
	size_t ret;
	int i;

	if ( (file = malloc(sizeof(*file))) == NULL) {
		__error = ERROR_ALLOCATION;
		goto error;
	}

	if ( (file->fp = fopen(pathname, mode)) == NULL) {
		__error = ERROR_OPEN;
		goto error_free;
	}

	if (itg2_file_header_get(file->fp, &file->header) == -1) {
		__error = ERROR_INVALID_HEADER;
		goto error_close;
	}

	/* We should have the magic header. */
	if (file->header.magic[0] == ':' && file->header.magic[1] == '|') {
		file->type = ITG2_FILE_TYPE_DATA;
	} else if (file->header.magic[0] == '8' &&
	           file->header.magic[1] == 'O') {
		file->type = ITG2_FILE_TYPE_PATCH;
	}

	/* Set up the AES key. */
	if (file->type == ITG2_FILE_TYPE_PATCH) {
		if (__get_patch_file_key(file) == -1) {
			__error = ERROR_SHA512;
			goto error_header;
		}
	} else if (key != NULL) {
		memcpy(file->aes_key, key, sizeof(file->aes_key));
	} else {
		__error = ERROR_AES_KEY;
		goto error_header;
	}

	/* Set up the decryption context. */
	i = AES_set_decrypt_key(file->aes_key, sizeof(file->aes_key) * 8,
	                        &file->key);
	if (i != 0) {
		__error = ERROR_AES_KEY_SCHEDULING;
		goto error_header;
	}

	/* Decrypt the verification block. */
	AES_decrypt(file->header.verify_block,
	            file->verify_block_plain, &file->key);

	/* Check the verification block. */
	if (file->type == ITG2_FILE_TYPE_PATCH) {
		i = memcmp(file->verify_block_plain,
		           ITG2_PATCH_VERIFICATION_BLOCK,
		           sizeof(ITG2_PATCH_VERIFICATION_BLOCK) - 1);
	} else {
		i = memcmp(file->verify_block_plain,
		           ITG2_DATA_VERIFICATION_BLOCK,
		           sizeof(ITG2_DATA_VERIFICATION_BLOCK) - 1);
	}

	if (i) {
		__error = ERROR_VERIFICATION_BLOCK;
		goto error_header;
	}

	return file;

error_header:
	itg2_file_header_destroy(&file->header);
error_close:
	fclose(file->fp);
error_free:
	free(file);
error:
	return NULL;
}

void itg2_file_close(struct itg2_file *file)
{
	itg2_file_header_destroy(&file->header);
	fclose(file->fp);
	free(file);
}

void itg2_file_print(struct itg2_file *file)
{
	itg2_file_fprint(stdout, file);
}


void itg2_file_fprint(FILE *fp, struct itg2_file *file)
{
	int i;

	itg2_file_header_fprint(fp, &file->header);

	fprintf(fp, "  * Type:               %s\n",
		file->type == ITG2_FILE_TYPE_DATA ? "data" : "patch");

	fprintf(fp, "  * AES key:            ");

	for (i = 0; i < sizeof(file->aes_key); i++)
		fprintf(fp, "%.2x", file->aes_key[i]);
	fprintf(fp, "\n");

	fprintf(fp, "  * Plain verify block: %.*s\n",
		sizeof(file->verify_block_plain), file->verify_block_plain);
}

static inline int __is_magic(struct itg2_file_header *header)
{
	if (header->magic[0] == ':' && header->magic[1] == '|')
		return 1;

	if (header->magic[0] == '8' && header->magic[1] == 'O')
		return 1;

	return 0;
}

int itg2_file_header_get(FILE *fp, struct itg2_file_header *header)
{
	uint8_t buf[4];
	size_t ret;

	/* Read the header. */
	ret = fread(header->magic, 1, sizeof(header->magic), fp);
	if (ret != sizeof(header->magic)) {
		if (feof(fp))
			errno = EINVAL;
		goto error;
	}

	if (!__is_magic(header)) {
		errno = EINVAL;
		goto error;
	}

	/* Read the file size. */
	if (fread(buf, 1, sizeof(buf), fp) != sizeof(buf)) {
		if (feof(fp))
			errno = EINVAL;
		goto error;
	}

	header->file_size = GET_32BIT_LSB(buf);

	/* Read the subkey size. */
	if (fread(buf, 1, sizeof(buf), fp) != sizeof(buf)) {
		if (feof(fp))
			errno = EINVAL;
		goto error;
	}

	header->subkey_size = GET_32BIT_LSB(buf);

	/* Allocate subkey space. */
	if ( (header->subkey = malloc(header->subkey_size)) == NULL)
		goto error;
		
	/* Read the subkey. */
	ret = fread(header->subkey, 1, header->subkey_size, fp);
	if (ret != header->subkey_size) {
		if (feof(fp))
			errno = EINVAL;
		goto error_subkey;
	}

	/* Read the verify block. */
	ret = fread(header->verify_block, 1, sizeof(header->verify_block), fp);
	if (ret != sizeof(header->verify_block)) {
		if (feof(fp))
			errno = EINVAL;
		goto error_subkey;
	}

	return 0;

error_subkey:
	free(header->subkey);
error:
	return -1;
}

void itg2_file_header_destroy(struct itg2_file_header *header)
{
	free(header->subkey);
}

void itg2_file_header_print(struct itg2_file_header *header)
{
	itg2_file_header_fprint(stdout, header);
}

void itg2_file_header_fprint(FILE *fp, struct itg2_file_header *header)
{
	int i;

	fprintf(fp, "  * Magic:              %.*s\n", 2, header->magic);
	fprintf(fp, "  * File size:          %"PRIu32"\n", header->file_size);
	fprintf(fp, "  * Subkey size:        %"PRIu32"\n", header->subkey_size);
	fprintf(fp, "  * Verify block:       ");

	for (i = 0; i < sizeof(header->verify_block); i++)
		fprintf(fp, "%.2x", header->verify_block[i]);
	fprintf(fp, "\n");
}

void itg2_file_perror(void)
{
	fprintf(stderr, "%s\n", __errors[__error]);
}
