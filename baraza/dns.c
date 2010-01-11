/*
 * Baraza - Open  Source IMPS/Wireless Village Server
 * 
 * 
 * 
 * Copyright (C) 2007 - , Digital Solutions Ltd. - http://www.dsmagic.com
 *
 * admin@baraza.im
 * 
 * This program is free software, distributed under the terms of
 * the GNU General Public License, with a few exceptions granted (see LICENSE)
 */ 
/* DNS lookup stuff. */
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>

#include "dns.h"

#if PACKETSZ > 1024
# define MAX_PACKET PACKETSZ
#else
# define MAX_PACKET 1024
#endif


/* We use the newer DNS query interface. Much nicer. */
static int compare_srv(SrvRecord_t a, SrvRecord_t b);

#if 0
SrvRecord_t dns_find_srv(char *domain, char *service, int *count)
{
     unsigned char pkt[MAX_PACKET];     
     long i, dlen,  n_ans;
     SrvRecord_t resp = NULL;
     struct __res_state res = {0};
     ns_msg msg;
     
     res.options = 0;
     if (res_ninit(&res) < 0) 
	  goto done;

     if ((dlen = res_nquerydomain(&res, service, domain, ns_c_in, ns_t_srv, pkt, sizeof pkt)) < 0 ||
	 ns_initparse(pkt, dlen, &msg) < 0 ||
	 (n_ans = ns_msg_count(msg, ns_s_an)) <= 0) {
	  *count = 0;
	  goto done;
     }
          
     resp = gw_malloc(n_ans*sizeof resp[0]);
     memset(resp, 0, n_ans*sizeof resp[0]);

     for (i = 0; i < n_ans; i++) {
	  ns_rr rr;
	  unsigned char *srv_data;

	  /* Now parse the answer section. */	  
	  if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
	       break; /* we are done. */
	  
	  if (ns_rr_type(rr) != ns_t_srv)  /* skip it: We only want SRV records*/
	       continue;

	  srv_data = (void *)ns_rr_rdata(rr);
	  
	  /* parse SRV record from srv data field*/
	  NS_GET16(resp[i].priority, srv_data);
	  NS_GET16(resp[i].weight, srv_data);
	  NS_GET16(resp[i].port, srv_data);
	  /* name follows immediately... */
	  if (ns_name_ntop(srv_data, resp[i].host, sizeof resp[i].host) < 0)
	       break;
	  
	  resp[i].rweight =  (resp[i].weight != 0) ?
	       1 + gw_rand() % (10000 * resp[i].weight) : 0;
	  
     }
     
     /* sort them. */
     qsort(resp, i, sizeof resp[0], (void *)compare_srv);
     *count = i;
     
 done:
     res_nclose(&res);
     return resp;
}

#else

SrvRecord_t dns_find_srv(char *domain, char *service, int *count)
{
     unsigned char pkt[MAX_PACKET];     
     long i, dlen,  n_ans;
     SrvRecord_t resp = NULL;
     struct __res_state res = {0};
     ns_msg msg;
     
     
     res.options &= (~RES_INIT);
     
     if (res_ninit(&res)  < 0)
	  return NULL;
     
     if ((dlen = res_nquerydomain(&res, service, domain, ns_c_in, ns_t_srv, pkt, sizeof pkt)) < 0 ||
	 ns_initparse(pkt, dlen, &msg) < 0 ||
	 (n_ans = ns_msg_count(msg, ns_s_an)) <= 0) {
	  *count = 0;
	  goto done;
     }
          
     resp = gw_malloc(n_ans*sizeof resp[0]);
     memset(resp, 0, n_ans*sizeof resp[0]);

     for (i = 0; i < n_ans; i++) {
	  ns_rr rr;
	  unsigned char *srv_data;

	  /* Now parse the answer section. */	  
	  if (ns_parserr(&msg, ns_s_an, i, &rr) < 0)
	       break; /* we are done. */
	  
	  if (ns_rr_type(rr) != ns_t_srv)  /* skip it: We only want SRV records*/
	       continue;

	  srv_data = (void *)ns_rr_rdata(rr);
	  
	  /* parse SRV record from srv data field*/
	  NS_GET16(resp[i].priority, srv_data);
	  NS_GET16(resp[i].weight, srv_data);
	  NS_GET16(resp[i].port, srv_data);
	  /* name follows immediately... */
	  if (ns_name_ntop(srv_data, resp[i].host, sizeof resp[i].host) < 0)
	       break;
	  
	  resp[i].rweight =  (resp[i].weight != 0) ?
	       1 + gw_rand() % (10000 * resp[i].weight) : 0;
	  
     }
     
     /* sort them. */
     qsort(resp, i, sizeof resp[0], (void *)compare_srv);
     *count = i;
     
 done:
#ifdef __linux__
     res_nclose(&res);
#else
     res_ndestroy(&res);
#endif
     return resp;
}

#endif

static int compare_srv(SrvRecord_t a, SrvRecord_t b)
{
     if (a->priority > b->priority) return 1;
     if (a->priority < b->priority) return -1;

     if (a->rweight > b->rweight) return -1;
     if (a->rweight < b->rweight) return 1;
     
     return 0;
}

SrvRecord_t dns_make_srv_rec_from_domain(char *domain, int port)
{
     SrvRecord_t s = gw_malloc(sizeof *s);

     strncpy(s->host, domain, sizeof s->host);
     s->port = port;
     s->weight = s->priority = s->rweight = 0;
     
     return s;
}
