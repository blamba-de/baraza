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
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#include "conf.h"
#include "utils.h"

/* Year 2000 bug. */
#define ynorm(year) ((year) < 50 ? (year) + 2000 : (year) > 1900 ? (year) : (year) + 1900)

/* Make date in format yyYYmmdd.*/
#define mkdate(tm) (ynorm((tm)->tm_year)*10000 + (1+(tm)->tm_mon)*100 + (tm)->tm_mday)

#define DEFAULT_CONFIG_FILE "/etc/imps.conf"
#define MAX_TTL 10*60 /* Maximum time-to-live. */
#define MIN_TTL 2
#define MIN_THREADS 5
static int conf_init(struct imps_conf_t * config);
#if 0
struct imps_conf_t * readconfig(char *conffile)
{
    FILE *f;
    struct imps_conf_t *config;

    assert(conffile);
    
    config = (struct imps_conf_t *) gw_malloc(sizeof *config);
    if (config == NULL) {
	error(0, "readconfig: %s\n", strerror(errno));
	return NULL;
    }
    if (conf_init(config) < 0)
	return NULL;
    if (conffile) {
	f = fopen(conffile, "r");
	if (!f) {
	    error(0, "readconfig: %s: %s\n", conffile,
		   strerror(errno));
	    return NULL;
	}
	info(0, "Reading configuration file: %s\n", conffile);
	if (parse_conf(f, config) < 0) {
	    error(0, "readconfig: error parsing conf file.\n");
	    return NULL;
	}
	fclose(f);
    }

    info(1, "readconfig: dbhost [%s], dbname [%s] dbuser[%s] \n", 
	 config->dbhost, 
	 config->dbuser, 
	 config->dbpass);

    return config;
}

#endif
static int conf_init(struct imps_conf_t * config)
{
     time_t t = time(NULL);
     memset(config, 0, sizeof config);
     
     strncpy(config->dbhost, "localhost", sizeof config->dbhost);
     strncpy(config->dbuser, "postgres", sizeof config->dbuser);
     strncpy(config->dbpass, "", sizeof config->dbpass);
     strncpy(config->dbname, "imps", sizeof config->dbname);
     config->dbport = 5432;
     /*      snprintf(config->connstr, sizeof config->connstr, "host=localhost dbname=imps user=postgres"); */
     snprintf(config->logdir, sizeof config->logdir, "/var/log");

     config->http_port = 80;
     strcpy(config->myhostname, "localhost");
     config->cir_stcp_port = 8080;
     config->external_http_port = -1;
     ctime_r(&t, config->nonce_salt);
     strncpy(config->mm_txt, "Your have received a multimedia message from a baraza.im user. Click to view: ",
	     sizeof config->mm_txt);
     config->min_ttl = MIN_TTL;
     config->max_ttl = MAX_TTL;

     config->num_threads = MIN_THREADS;
     return 0;
}

static char *strip_space(char x[])
{
     
     char *p = x, *q;

     while (*p && isspace(*p))
	  p++;
     q = p + strlen(p);

     while (--q > p && isspace(*q))
	  *q = 0;
     
     return p;
}

int parse_conf(FILE *f, struct imps_conf_t *config)
{
     char field[32], xvalue[200], buf[256], *xbuf;
     int loglevel = 0;

     Octstr *proxy_host = NULL, *proxy_user = NULL, *proxy_pass = NULL;
     Octstr *proxy_except_regexp = NULL;
     List  *proxy_except = NULL;
     int proxy_port = -1;

     conf_init(config);
     while(fgets(buf, sizeof buf, f) != NULL && 
	   (xbuf = strip_space(buf)) != NULL &&
	   (xbuf[0] == 0 || xbuf[0] == '#' || sscanf(xbuf, "%32[^:]:%128[^\n]\n", field, xvalue) == 2)) {
	  char *value = (xbuf[0] == 0 || xbuf[0] == '#') ? xbuf : strip_space(xvalue);
	  int ch = (xbuf[0] == 0 || xbuf[0] == '#') ? '#' : tolower(field[0]);
	  switch(ch) {
	  case '#':
	       break;
	  case 'a': /* access log. */
	       if (strcasecmp(field, "access-log") == 0)
		    alog_open(value, 1,1);
	       else if (strcasecmp(field, "auto-registration") == 0) 
		    config->auto_reg = (strcasecmp(value, "yes") == 0);
	       break;
	  case 'd': /* database: database name */
	       strncpy(config->dbname, value, sizeof config->dbname);
	       break;
	  case 'i':
	       if (strcasecmp(field, "ip-http-headers") == 0) {
		    char *q = NULL, *p;
		    int i = 0;
		    for (p = strtok_r(value, ",", &q); p; p= strtok_r(NULL, ",", &q))
			 strncpy(config->ip_headers[i++], strip_space(p), sizeof config->ip_headers[0]);
	       }
	       break;
	  case 'h': /* host: database host or http_port */
	       if (strcasecmp(field, "host") == 0) 
		    strncpy(config->dbhost, value, sizeof config->dbhost);
	       else if (strcasecmp(field, "http-proxy") == 0) 
		    proxy_host = octstr_create(value);
	       else if (strcasecmp(field, "http-proxy-username") == 0) 
		    proxy_user = octstr_create(value);
	       else if (strcasecmp(field, "http-proxy-password") == 0) 
		    proxy_pass = octstr_create(value);
	       else if (strcasecmp(field, "http-proxy-exceptions") == 0) {
		    Octstr *x = octstr_create(value);
		    proxy_except = octstr_split_words(x);
		    octstr_destroy(x);
	       } else if (strcasecmp(field, "http-proxy-exceptions-regex") == 0) 
		    proxy_except_regexp = octstr_create(value);
	       else if (strcasecmp(field, "http-proxy-port") == 0) 
		    proxy_port = atoi(value);
	       else if (strcasecmp(field, "http-port") == 0) 
		    config->http_port = atoi(value);
	       else if (strcasecmp(field, "http-interface") == 0)
		    strncpy(config->http_interface, value, sizeof config->http_interface);	       
	       break;
	  case 'p': /* password: database password */
	       if (strcasecmp(field, "password") == 0) 
		    strncpy(config->dbpass, value, sizeof config->dbpass);
	       else if (strcasecmp(field, "port") == 0)  
		    config->dbport = atoi(value);
	       break;
	  case 's': 
	       if (strcasecmp(field, "send-sms-url") == 0) 
		    strncpy(config->send_sms_url, value, sizeof config->send_sms_url);
	       else if (strcasecmp(field, "ssl-certkey-file") == 0) 
		    strncpy(config->ssl_certkeyfile, value,
			    sizeof config->ssl_certkeyfile);
	       else if (strcasecmp(field, "ssl-crl-file") == 0) 
		    strncpy(config->ssl_crlfile,value, sizeof config->ssl_crlfile);
	       else if (strcasecmp(field, "ssl-trusted-ca-file") == 0) 
		    strncpy(config->ssl_ca_file, value, sizeof config->ssl_ca_file);
#if 0
	       else if (strcasecmp(field, "ssp-port") == 0)
		    config->ssp_port = atoi(value);
#endif
	       else if (strcasecmp(field, "s2s-interface") == 0)
		    strncpy(config->s2s_interface, value, sizeof config->s2s_interface);
#if 0
	       else if (strcasecmp(field, "shared-content-port") == 0)
		    config->sc_port = atoi(value);
#endif
	       else 
		    fprintf(stderr, "unknown/unsupported config option %s!\n",
			    field);
	       break;
	  case 'l': /* log dir */
	       if (strcasecmp(field, "local-hostname") == 0)
		    strncpy(config->myhostname, value, sizeof config->myhostname);
	       else if (strcasecmp(field, "local-domain") == 0)
		    strncpy(config->mydomain, value, sizeof config->mydomain);
	       else if (strcasecmp(field,"log-level") == 0)
		    loglevel = atoi(value);
	       else
		    strncpy(config->logdir, value, sizeof config->logdir);
	       break;
	  case 'c':
	       if (strcasecmp(field, "cir-methods") == 0) {
		    char *q = NULL, *p;
		    int i = 0;
		    for (p = strtok_r(value, ",", &q); p; p = strtok_r(NULL, ",", &q)) {
			 char *x = strip_space(p);
			 if (strcasecmp(x, "WAPSMS") == 0)
			      config->cir_methods[i++] = CIR_WAPSMS;
			 else if (strcasecmp(x, "WAPUDP") == 0)
			      config->cir_methods[i++] = CIR_WAPUDP;			 
			 else if (strcasecmp(x, "SUDP") == 0)
			      config->cir_methods[i++] = CIR_SUDP;			 
		    }
	       } else  if (strcasecmp(field, "cir-stcp-port") == 0)
		    config->cir_stcp_port  = atoi(value);
	       else /* cir-ip  -- the external ip*/
		    strncpy(config->cir_ip, value, sizeof config->cir_ip);
	       break;
	  case 'e': /* external-http-port: external CSP HTTP port (CIR and all). */
	       config->external_http_port = atoi(value);
	       break;
	  case 'u': /* user: database user */
	       if (strcasecmp(field, "user") == 0)
		  strncpy(config->dbuser, value, sizeof config->dbuser);
	       else if (strcasecmp(field, "use-requestor-ip") == 0)
		    config->use_request_ip = 1;
#ifdef HAVE_LIBSSL
	     else if (strcasecmp(field, "use-ssl") == 0) /* ssl incoming */	     
		  config->use_ssl = (strcasecmp(value, "true") == 0 || strcasecmp(value, "yes") == 0);
#endif
	     break;
	  case 'm': /* max-simultaneous: num threads */
	       if (strcasecmp(field, "multimedia-message-text") == 0)
		    strncpy(config->mm_txt, value, sizeof config->mm_txt);
	       else if (strcasecmp(field, "msisdn-http-headers") == 0) {
		    char *q = NULL, *p;
		    int i = 0;
		    for (p = strtok_r(value, ",", &q); p; p = strtok_r(NULL, ",", &q))
			 strncpy(config->msisdn_headers[i++], 
				 strip_space(p), sizeof config->msisdn_headers[0]);
	       } else if (strcasecmp(field, "min-ttl") == 0) 
		    config->min_ttl = atoi(value);
	       else if (strcasecmp(field, "max-ttl") == 0) 
		    config->max_ttl = atoi(value);
	       else {
		    config->num_threads = atoi(value);
		    if (config->num_threads < MIN_THREADS)
			 config->num_threads = MIN_THREADS;
	       }
	       break;
	  case 'n':
	       if (strcasecmp(field, "no-c2s") == 0)
		    config->no_c2s = 1;
	       else if (strcasecmp(field, "no-s2s") == 0)
		    config->no_s2s = 1;
	     break;
	  case 'q': /* queue interval. */
	       config->qrun_interval = atof(value);
	       break;
	  case 'x': /* xmpp server ports. */
	       if (strcasecmp(field, "xmpp-server-port") == 0)
		    config->xmpp_server_port = atoi(value);
	       else if (strcasecmp(field, "xmpp-salt") == 0)
		    strncpy(config->xmpp_salt, value, sizeof config->xmpp_salt);
	       else 
		    config->xmpp_client_port = atoi(value);	       
	       break;
	  }	  
     }
     
     if (proxy_port > 0)
	  http_use_proxy(proxy_host, proxy_port, config->use_ssl,
			 proxy_except, proxy_user, 
			 proxy_pass, proxy_except_regexp);
     
     octstr_destroy(proxy_host);
     octstr_destroy(proxy_user);
     octstr_destroy(proxy_pass);
     octstr_destroy(proxy_except_regexp);
     gwlist_destroy(proxy_except, (void *)octstr_destroy);
     
#ifdef HAVE_LIBSSL
     if (config->ssl_certkeyfile[0]) {
	  Octstr *x = octstr_create(config->ssl_certkeyfile);
	  use_global_client_certkey_file(x);
	  use_global_server_certkey_file(x, x);
	  octstr_destroy(x);
     }
     if (config->ssl_ca_file[0]) {
	  Octstr *x = octstr_create(config->ssl_ca_file);
	  use_global_trusted_ca_file(x);
	  octstr_destroy(x);
     }
     
#endif    
     
     if (config->logdir[0]) {
	  char buf[512];
	  
	  sprintf(buf, "%s/barazad.log", config->logdir);
	  log_open(buf, loglevel, GW_NON_EXCL);
	  
     }
     if (config->cir_ip[0] == 0)
	  strncpy(config->cir_ip, config->myhostname, sizeof config->cir_ip);

     if (config->external_http_port<0)
	  config->external_http_port = config->http_port;
     
     return 0;
}

void *test_harness_new_request(char tlog_dir[], Octstr *ip, List *req_hdrs, Octstr *body)
{
     Octstr *xfname, *x;
     time_t t;
     struct tm *tm, _tm;
     FILE *f;

     
     t = time(NULL);
     tm = localtime_r(&t, &_tm);
     
     xfname = octstr_format("%s/%d-%S.testlog",
			    tlog_dir, mkdate(tm),  ip);

     f = fopen(octstr_get_cstr(xfname), "a");
     if (f == NULL) {
	  error(0, "Failed to open file [%s] for writing: %s", 
		octstr_get_cstr(xfname), strerror(errno));
	  goto done;
     }
     /* print the content type. */
     x = http_header_value(req_hdrs, octstr_imm("Content-Type"));
     if (x) {
	  fprintf(f, "Content-Type: %s\n",  octstr_get_cstr(x));
	  octstr_destroy(x);
     }
     
     x = octstr_format("%H", body);
     fprintf(f, "Request-Body: %s\n",  octstr_get_cstr(x));
     octstr_destroy(x);
done:
     octstr_destroy(xfname);
     return f;
}

void test_harness_log_info(void *thandle, char *fname, char *value)
{
     FILE *f = thandle;

     if (f)
	  fprintf(f, "%s: %s\n",  fname, value);

}

void test_harness_end_log(void *thandle)
{
     FILE *f = thandle;
     if (f) {
	  fprintf(f, "\n");
	  fclose(f);
     }     
}

char test_pfile[128], test_logdir[128];
int test_harness;

static struct option const long_options[] = {
    {"version", no_argument, 0, 'V'},

    {"file", 1, 0, 'f'},

    {"conf", 1, 0, 'c'},
    {"help", no_argument, 0, 'h'},
    {"test-harness", 1, 0, 't'},
    {NULL, 0, NULL, 0}
};

static void usage(int exit_status)
{
    fprintf(stdout, "%s "
#ifdef DEBUG
"[-f <file>] "
#endif
"[-c config] [-d] | -V | -h \n", PACKAGE);
    exit(exit_status);
}

static struct imps_conf_t _config;
int decode_switches(int argc, char *argv[], struct imps_conf_t **config)
{
  int c, x, config_done = 0;
    int option_index = 0;
    FILE *f;
    
    while (1) {
	 c = getopt_long(argc, argv, "hdVc:t:f:", long_options, &option_index);

        if (c == -1)
            break;
        switch (c) {
	case 'c':
	     f = fopen(optarg, "r");
	     if (f) {
		  if (parse_conf(f, &_config) == 0)
		       *config = &_config;
		  fclose(f);
		  config_done = 1;
	     } else 
		  usage(-1);
	  break;
        case 'f':
	     strncpy(test_pfile, optarg, sizeof test_pfile);
            break;
        case 'V':
            fprintf(stdout, "%s %s\n", PACKAGE, VERSION);
            exit(0);
	case 't':
	  strncpy(test_logdir, optarg, sizeof test_logdir);
	  if ((x = mkdir(test_logdir,  S_IRWXU|S_IRWXG)) != 0 && 
	      errno != EEXIST) {
	       fprintf(stderr, "Failed to create test harness director %.128s: %s!\n", 
		       test_logdir, strerror(errno));
	       exit(-1);
	  } else 
	       test_harness = 1;
	  break;
        case 'h':
        default:
            usage(EXIT_FAILURE);
            break;
        }
    }

    if (!config_done) {
	 fprintf(stderr, "No config file, falling back to: %s\n", DEFAULT_CONFIG_FILE);
	 if ((f = fopen(DEFAULT_CONFIG_FILE, "r")) == NULL)
	      fprintf(stderr, "Failed to open default configuration file: %s\n", DEFAULT_CONFIG_FILE);
	 else {
	      if (parse_conf(f, &_config) == 0)
		   *config = &_config;
	      else 
		   usage(-1);
	      fclose(f);
	 }	 
    }
    
    return 0;
}
