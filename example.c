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
