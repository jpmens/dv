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
