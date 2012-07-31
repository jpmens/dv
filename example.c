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
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "dv.h"

int main(int argc, char **argv)
{
	char *filename;
	int rc;
	struct dvinfo *dvi;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s file\n", *argv);
		exit(1);
	}
	
	dvset_resolvconf("./resolv.conf");
	/* dvset_bits(~DV_FORCE_AD); */ /* Disable DNSSEC check */

#if TESTSELF
	dvi = dv_alloc(argv[0]);
	rc = dv_valid(dvi);
	if (rc != F_SIG_OK) {
		fprintf(stderr, "Program file %s has been modified. ABORT\n", *argv);
		exit(2);
	}
	dv_free(dvi);
#endif

	filename = argv[1];

	dvi = dv_alloc(filename);

	rc = dv_valid(dvi);

	printf("\tfilename....: %s\n",  dvi->filename);
	printf("\tsha1........: %s\n",  dvi->sha1);
	printf("\tttl.........: %u\n",  dvi->ttl);
	printf("\trdata.......: %s\n",  dvi->rdata);
	printf("\treason......: %s\n",  dvi->reason);

	if (rc == F_SIG_OK) {
		fprintf(stderr, "file `%s' is valid\n", filename);
	} else if (rc == F_SIG_NO) {
		fprintf(stderr, "file `%s' is NOT valid: %s\n", filename, dvi->reason);
	} else if (rc == F_SIG_BAD) {
		fprintf(stderr, "file `%s' signature-state BAD (githash in DNS but filename not in rdata)\n", filename);
	} else {
		fprintf(stderr, "file `%s' %s\n",
			filename, dvi->reason);
	}

	dv_free(dvi);

	return (rc);
}
