/*
 * Copyright (C)2012 by Jan-Piet Mens <jpmens () gmail.com>
 *
 * This file is part of "DV" (DNS file verification)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 *	The above copyright notice and this permission notice shall be included
 *	in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <stdint.h>
#include "githash.h"
#include "sha1.h"

#define BLEN	5120

static void digest_to_hex(const uint8_t digest[SHA1_DIGEST_SIZE], char *output)
{
	int             i, j;
	char           *c = output;

	for (i = 0; i < SHA1_DIGEST_SIZE / 4; i++) {
		for (j = 0; j < 4; j++) {
			sprintf(c, "%02x", digest[i * 4 + j]);
			c += 2;
		}
		/* sprintf(c, " "); 
		c += 1; */
	}
	/*   *(c - 1) = '\0'; */
	*c = '\0';
}

int githash_file(char *filename, char *digest_out)
{
	int             fd, n;
	unsigned char   buf[BLEN], header[128];
	unsigned char   digest[SHA1_DIGEST_SIZE];
	SHA1_CTX        sha;
	struct stat     sb;


	if (stat(filename, &sb) != 0) {
		return (-1);
	}

	if ((fd = open(filename, O_RDONLY)) == -1) {
		return (-1);
	}

	/*
	 * Python: 
	 *	def githash(data):
	 *		s = sha1()
	 *		s.update("blob %u\0" % len(data))
	 *		s.update(data)
	 *		return s.hexdigest()
	 */

	memset(header, 0, sizeof(header));		/* Ensure contains trailing '\0' */
	SHA1_Init(&sha);
	sprintf((char *)header, "blob %llu", sb.st_size);
	SHA1_Update(&sha, (uint8_t *) header, strlen((char *)header) + 1);

	while ((n = read(fd, buf, sizeof(buf))) > 0) {
		SHA1_Update(&sha, (uint8_t *) buf, n);
	}
	SHA1_Final(&sha, (uint8_t *) digest);

	close(fd);

	digest_to_hex(digest, digest_out);

	return (0);
}
