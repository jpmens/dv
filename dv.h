
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

