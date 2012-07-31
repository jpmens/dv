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

#define F_SIG_ERR -1		/* Error, e.g. can't SHA1, no memory */
#define F_SIG_OK  0		/* DNS OK and githash matches */
#define F_SIG_NO  1		/* DNS OK and githash does NOT match */
#define F_SIG_UNKNOWN 2		/* DNS state unknown: can't verify */
#define F_SIG_BAD	3	/* DNS OK, rdata of TXT doesn't match filename */

#define DV_FORCE_AD	0x01
#define DV_CD_OK	0x02

struct dvinfo {
	char *filename;
	char *sha1;
	char *rdata;
	long rdatalen;
	char *reason;
	long reasonlen;
	unsigned int ttl;
};

void dvset_resolvconf(char *resolvconf);
void dvset_bits(int bits);
struct dvinfo *dv_alloc(char *filename);
void dv_free(struct dvinfo *fi);
int dv_valid(struct dvinfo *fi);

