#ifndef __ITG2_FILE_H
#define __ITG2_FILE_H

#include <stdio.h>
#include <stdint.h>
#include <openssl/aes.h>

#define ITG2_FILE_TYPE_PATCH	0
#define ITG2_FILE_TYPE_DATA	1

struct itg2_file_header
{
	char			magic[2];
	uint32_t		file_size;
	uint32_t		subkey_size;
	uint8_t			*subkey;
	uint8_t			verify_block[16];
};

struct itg2_file
{
	int			type;

	struct itg2_file_header	header;
	uint8_t			verify_block_plain[16];
	uint8_t			aes_key[24];

	/* Internal data. */
	FILE			*fp;
	AES_KEY			key;
};

#ifdef __cplusplus
extern "C" {
#endif

struct itg2_file *
itg2_file_open(const char *pathname, const char *mode, const uint8_t *key);
void itg2_file_close(struct itg2_file *file);
void itg2_file_print(struct itg2_file *file);
void itg2_file_fprint(FILE *fp, struct itg2_file *file);
void itg2_file_perror(void);

int  itg2_file_header_get(FILE *fp, struct itg2_file_header *header);
void itg2_file_header_destroy(struct itg2_file_header *header);
void itg2_file_header_print(struct itg2_file_header *header);
void itg2_file_header_fprint(FILE *fp, struct itg2_file_header *header);

#ifdef __cplusplus
}
#endif

#endif
