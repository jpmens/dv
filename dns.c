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
#include <stdio.h>
#include <stdlib.h>
#include <ldns/ldns.h>

#include "dns.h"

/* Lots of this swiped from ldns-mx.c by NLnetLabs */


static ldns_resolver *init_resolver(char *resolvconf)
{
	static ldns_resolver *res;
	
	res = malloc(sizeof(ldns_resolver));

	if (ldns_resolver_new_frm_file(&res, resolvconf) != LDNS_STATUS_OK) {
		return (NULL);
	}
	/* ldns_resolver_set_debug(res, true); */
	return (res);
}



/*
 * If ttl is not NULL, store TTL
 */

int txt_from_dns(int bits, char *resolvconf, char *qname, unsigned int *ttl, char *rdata, long rdatalen, char *reason, long reasonlen)
{
	static ldns_resolver *res = NULL;
	ldns_rdf *domain = NULL;
	ldns_pkt *p = NULL;
	ldns_rr_list *txt_rrs = NULL;
	int rc = -1;
	
	*reason = 0;

	if (res == NULL)
		res = init_resolver(resolvconf);
	if (res == NULL) {
		snprintf(reason, reasonlen, "ldns cannot init resolver");
		return (-1);
	}

	if ((domain = ldns_dname_new_frm_str(qname)) == NULL) {
		snprintf(reason, reasonlen, "ldns cannot convert qname %s", qname);
		return (-1);
	}

	/* Set DO bit for DNSSEC */
	ldns_resolver_set_dnssec(res, true);

	if (ldns_resolver_dnssec(res) == false) {
		puts("NO DNSSEC");
	}


	if ((bits & DV_CD_OK) == DV_CD_OK) {
		ldns_resolver_set_dnssec_cd(res, true);
	}


	/* Use the resolver to send a query for the TXT RRSet
	 * TODO: keep this as _search(), which uses domain in resolv.conf
	 * or return to _query() ?
	 */
	ldns_resolver_set_defnames(res, true);
	p = ldns_resolver_search(res,
	                        domain,
	                        LDNS_RR_TYPE_TXT,
	                        LDNS_RR_CLASS_IN,
	                        LDNS_RD);

	
        if (!p)  {
		fprintf(stderr, "No packet received from ldns_resolver_query\n");
		return (-1);
        } else {
		
		snprintf(reason, reasonlen, "%s", ldns_pkt_rcode2str(ldns_pkt_get_rcode(p)));
		if (ldns_pkt_get_rcode(p) != LDNS_RCODE_NOERROR) {
			goto out;
		}
			
		/* retrieve the TXT records from the answer section of the packet */
		txt_rrs = ldns_pkt_rr_list_by_type(p,
		                              LDNS_RR_TYPE_TXT,
		                              LDNS_SECTION_ANSWER);
		if ((bits & DV_FORCE_AD) == DV_FORCE_AD) {
			if (!ldns_pkt_ad(p)) {
				snprintf(reason, reasonlen, "INVALID (no +AD)");
				goto out;
			}
		}
		if (!txt_rrs) {
			fprintf(stderr, "%s NXDOMAIN or NODATA\n", qname);
			goto out;
		} else {
			long n, i;
			char *str, *bp, *tp = rdata;
			ldns_rdf *t;

			if (ttl)
				*ttl = ldns_rr_ttl(ldns_rr_list_rr(txt_rrs, 0));

			/*
			ldns_rr_list_sort(txt_rrs); 
			ldns_rr_list_print(stdout, txt_rrs);
			*/

			if ((n = ldns_rr_list_rr_count(txt_rrs)) != 1) {
				printf("Expecting 1 answer: got %ld\n", n);
				goto out;
			}

			for (i = 0; i < ldns_rr_list_rr_count(txt_rrs); i++) {
				t = ldns_rr_rdf(ldns_rr_list_rr(txt_rrs, i), 0);
				if (!t)
					continue;

				str = ldns_rdf2str(t);
				for (bp = (*str == '"') ? str + 1 : str, n = 0;
					bp && *bp && n < rdatalen; bp++, n++) {
					*tp++ = *bp;

				}
				*tp = 0;
				if (*(tp - 1) == '"')
					*(tp - 1) = 0;
				free(str);

				/* Use first RR only, so get out here */
				rc = 0;
				break;

			}

			ldns_rr_list_deep_free(txt_rrs);
		}
        }
   out:
        ldns_pkt_free(p);
	ldns_rdf_deep_free(domain);
        /* ldns_resolver_deep_free(res); */
        return (rc);
}
