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
#include <errno.h>
#include <memory.h>

#include "githash.h"
#include "dns.h"
#include "dv.h"

static struct dvparams {
	char *resolvconf;	/* Pointer to resolv.conf file -- NULL is default */
	int bits;		/* See dns.h */
} dvparams = {
	NULL, DV_FORCE_AD
};

void dvset_resolvconf(char *resolvconf)
{
	dvparams.resolvconf = resolvconf;
}

void dvset_bits(int bits)
{
	dvparams.bits = bits;
}

struct dvinfo *dv_alloc(char *filename)
{
	struct dvinfo *fi;

	if ((fi = malloc(sizeof(struct dvinfo))) == NULL)
		return (NULL);

	fi->filename = strdup(filename);
	fi->reasonlen = 64;
	fi->reason = calloc(sizeof(char), fi->reasonlen);
	fi->rdatalen = 256;
	fi->rdata = calloc(sizeof(char), fi->rdatalen);
	fi->ttl = 0;
	fi->sha1 = malloc(HEX_DIGEST_SIZE + 1);;

	return (fi);
}

void dv_free(struct dvinfo *fi)
{
	if (fi) {
		free(fi->filename);
		free(fi->reason);
		free(fi->rdata);
		free(fi->sha1);
		free(fi);
	}
}

int dv_valid(struct dvinfo *fi)
{
	char *qname;
	int rc;
	
	if (githash_file(fi->filename, fi->sha1)) {
		strerror_r(errno, fi->reason, fi->reasonlen);
		return (F_SIG_ERR);
	}

	qname = fi->sha1;

	rc = txt_from_dns(dvparams.bits, dvparams.resolvconf, qname, &fi->ttl, fi->rdata, fi->rdatalen, fi->reason, fi->reasonlen);
	if (rc == 0) {
		/* We have a valid DNS reply, so requested githash is in the DNS.
		 * rdata must contain filename */

		if ((*fi->filename != *fi->rdata) || (strcmp(fi->filename, fi->rdata) != 0)) {
			rc = F_SIG_BAD;
			goto out;
		}
		rc = F_SIG_OK;
		goto out;
	}

	/* qname not found in DNS */
	rc = F_SIG_NO;
	
  out:
	return (rc);
}
