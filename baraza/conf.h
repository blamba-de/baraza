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
#ifndef __HAVE_BARAZACONF_H__
#define __HAVE_BARAZACONF_H__

#include "gwlib/gwlib.h"
#include "utils.h"

#define CONFFILE "/etc/imps.conf"


struct imps_conf_t {
     /* DB settings. */
     char dbhost[128], dbuser[64], dbpass[64], dbname[64];
     int dbport;
#if 0
     char connstr[1024];
#endif
     char cir_ip[128]; /* IP address for CIR. */

     int  http_port; /* IMPS CSP, SSP, Shared Content and HTTP CIR port. */
     int external_http_port;

     int cir_stcp_port; /* cir port. */
     
     int use_ssl;
     
     int num_threads;
     char logdir[128];
     
     char myhostname[128];
     char mydomain[128];


     short xmpp_server_port;
     short xmpp_client_port;

     char xmpp_salt[64]; /* used in generating dialback key. */

     char http_interface[32];
     char s2s_interface[32];
     
     int no_s2s, no_c2s;
     int auto_reg;
     
     float qrun_interval;

     char ssl_certkeyfile[256];
     char ssl_ca_file[256];
     char ssl_crlfile[256];

     char nonce_salt[256];
     char mm_txt[512];
     char send_sms_url[512];

     char ip_headers[MAXLIST][64];
     char msisdn_headers[MAXLIST][64];
     
     int use_request_ip;
     unsigned long min_ttl, max_ttl; /* min and max Time-to-live */
     enum cir_methods_t {CIR_NONE=0, CIR_WAPSMS, CIR_WAPUDP, CIR_SUDP} cir_methods[MAXLIST];

     /* additionals */
     char webroot[256]; /* Web root, for when Baraza web server is used */     
     char mime_types_file[256]; /* Location of mime types file */
};

extern char test_pfile[128], test_logdir[128];
extern int test_harness;
int decode_switches(int argc, char *argv[], struct imps_conf_t **config);
#if 0
struct imps_conf_t *readconfig(char *conffile);
#endif
int parse_conf(FILE * f, struct imps_conf_t *config);

/* test harness stuff. */

void *test_harness_new_request(char tlog_dir[], Octstr *ip, List *req_hdrs, Octstr *body);
void test_harness_log_info(void *thandle, char *fname, char *value);
void test_harness_end_log(void *thandle);

#define test_harness_log_sessid(t, sessid) do { if (test_harness)  { \
	       if (sessid) test_harness_log_info((t), "Session-ID", (sessid)); \
} } while (0)

#define test_harness_log_req_type(t, typ) do { if (test_harness)  {	\
	       char *_xtype = (char *)csp_obj_name(typ);		\
	       test_harness_log_info((t), "Request-Type", (_xtype));	\
	  } } while (0)


#define test_harness_log_response_packet(t, xbytes) do { if (test_harness) { \
         Octstr *_xbytes = octstr_format("%H", (xbytes)); \
         test_harness_log_info((t), "Response", octstr_get_cstr(_xbytes)); \
         octstr_destroy(_xbytes); \
} } while (0)

#endif
