
#ifndef TRUE
# define FALSE 0
# define TRUE 1
#endif

#define DV_FORCE_AD	0x01
#define DV_CD_OK	0x02

int txt_from_dns(int bits, char *resolvconf, char *qname, unsigned int *ttl, char *rdata, long rdatalen, char *reason, long reasonlen);
