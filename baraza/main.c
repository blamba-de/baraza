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
/* main baraza startup engine. */
#include <signal.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <gwlib/gwlib.h>
#include "wbxml.h"
#include "conf.h"
#include "baraza.h"
#include "cspcommon.h"
#include "cspcir.h"
#include "scserver.h"
#include "ssp.h"


#define PGCONNS 5


struct imps_conf_t *config;

static int handle_parse(Octstr *s)
{
  WBXML_t w = parse_wbxml(s);
  WBXMLGen_t *z;
  void *next;
  Octstr *t;
  WV_CSP_Message_t x, y;
  Session_t u;
  Transaction_t trans;
  Login_Response_t lr;

  Octstr *os = dump_wbxml(w);

  info(0, "out: %s\n", octstr_get_cstr(os));

  octstr_destroy(os);

  parse_WV_CSP_Message(w->body, &next, 1, (void *)&x);

  z = wbxml_pack_state(w->version, w->publicid, w->charset, IMPS_1_1); 
  /*  t = pack_WV_CSP_Message(x, 1, z);  */
  
  y = csp_msg_copy(x);

   t = pack_WV_CSP_Message(x, 0, z);
   printf("%s\n", octstr_get_cstr(t));

   csp_msg_free(y);
   
   lr = csp_msg_new(Login_Response, NULL,
		    FV(user, csp_String_from_cstr_ex("wv:test", UserID)));
   trans = csp_msg_new(Transaction, NULL,
		       FV(descr, 
			  csp_msg_new(TransactionDescriptor, NULL,
				      FV(mode, csp_String_from_cstr_ex("Response", TransactionMode)),
				      FV(id, csp_String_from_cstr_ex("0001", TransactionID)))),
		       FV(content, 
			  csp_msg_new(TransactionContent,
				      octstr_imm("test"),
				      UFV(tc, Imps_Login_Response, lr))));   				     
   
   u = csp_msg_new(Session, NULL,
		   FV(descr,
		      csp_msg_new(SessionDescriptor, NULL, 
				  FV(stype, csp_String_from_cstr_ex("Outband", SessionType)))),
		   FV(tlist, gwlist_create_ex(trans)));
   
   y = csp_msg_new(WV_CSP_Message, 
		   x->attributes ? dict_get(x->attributes, octstr_imm("xmlns")) : NULL,
		   FV(sess,u));

   t = pack_WV_CSP_Message(y, 0, z);
   printf("%s\n", octstr_get_cstr(t));

   csp_msg_free(y);
   csp_msg_free(x);

  return 0;
}

static int bstop = 0;

static void quit_now(int unused)
{
     bstop = 1;
     if (config)
	  http_close_port(config->http_port); /* close the port. */     
}
static void cleanup_thread(void *unused);
int main(int argc, char *argv[])
{
     List *rh = NULL, *cgivars = NULL;
     Octstr *ip = NULL, *url = NULL, *body = NULL;
     HTTPClient *client = NULL;
     int ret;
     long  cleanup_th = -1;
     
     /* initialise stuff. */
     gwlib_init();
     res_init(); /* init resolver engine. */

     xmlLineNumbersDefault(1);

     /* handle the command line */
     decode_switches(argc, argv, &config);
     
     if (config == NULL) {
	  fprintf(stderr, "No conf file read!\n");
	  exit(1);
     }
     
     signal(SIGTERM, quit_now);
     
     if (test_pfile[0]) 
	  handle_parse(octstr_read_file(test_pfile));
     
     if (pg_cp_init(PGCONNS, config->dbhost, config->dbuser,
		    config->dbpass, config->dbname, config->dbport, 
	      config->mydomain) < 0)
	  panic(0, "failed to start DB connections!");
     

     /* initialise the request lists */
     ssp_requests = gwlist_create();
     gwlist_add_producer(ssp_requests);
     
     csp_requests = gwlist_create();
     gwlist_add_producer(csp_requests);

     sc_requests = gwlist_create();
     gwlist_add_producer(sc_requests);

     http_cir_requests = gwlist_create();
     gwlist_add_producer(http_cir_requests);
     
     start_CIR_handlers(config->num_threads, config->cir_stcp_port, config->cir_methods, 
			config->send_sms_url[0] ? config->send_sms_url : NULL); /* start CIR stuff. */
     if (!config->no_c2s)
	  start_cspd();

     if (!config->no_s2s)
	  start_sspd();
     /* start shard content server. */
     if(sc_init_server(config) < 0)
	  panic(0, "Unable to start shared content server!");

     cleanup_th = gwthread_create(cleanup_thread, NULL);

     /* Listen on the http(s) port, route requests. */
     if (config->http_interface[0]) {
	  Octstr *x = octstr_create(config->http_interface);
	  ret = http_open_port_if(config->http_port, config->use_ssl, x);
	  octstr_destroy(x);
     } else 
	  ret = http_open_port(config->http_port, config->use_ssl);

     if (ret < 0) 
	  panic(0, "failed to open port");
     
     info(0, "Starting %s [Version: %s]", SYSTEM_NAME, VERSION);
     while ((client = http_accept_request(config->http_port, &ip, &url, &rh, &body, &cgivars)) != NULL) {
	  HTTPRequest_t *r = make_http_request_info(rh, url, body, client, ip, cgivars);

	  info(1, "New request[%s], body len=%ld, uri=%s, header dump follows: ", 
	       octstr_get_cstr(r->ua), octstr_len(body), octstr_get_cstr(url));
#if 0
	  http_header_dump(rh);
#endif
	  if (octstr_len(body) > 0) { /* POST request. */
	       Octstr *ctype = NULL, *charset = NULL;
	       
#ifdef DEBUG
	       
#if 0
	       http_header_dump(rh);
	       octstr_dump(body,0);
	       DEBUG_LOG_MSG(body, ip, url, "recv");
#endif
#endif

	       /* route request. */
	       http_header_get_content_type(rh, &ctype, &charset);
	       if (ctype && octstr_case_search(ctype, octstr_imm(SSP_CONTENT_TYPE), 0) == 0) /* SSP request. */
		    gwlist_produce(ssp_requests, r);
	       else 	       
		    gwlist_produce(csp_requests, r);
	       octstr_destroy(ctype);
	       octstr_destroy(charset);
	  } else { /* CIR or content server request */
	       
	       if (url && octstr_case_search(url, octstr_imm(CIR_URI), 0) == 0)
		    gwlist_produce(http_cir_requests, r);
	       /* must be SC request. */
	       else 
		    gwlist_produce(sc_requests, r);
	  }
     }
     info(0, "Clean shutdown initiated... ");
     gwthread_wakeup(cleanup_th);

     
     /* we are done, shut down stuff. */
     gwlist_remove_producer(csp_requests);     
     gwlist_remove_producer(ssp_requests);
     gwlist_remove_producer(sc_requests);
     gwlist_remove_producer(http_cir_requests);
     
     if (!config->no_s2s) 
	  stop_sspd(); /* force it to shut down, kill listener threads */
     
     if (!config->no_c2s) 
	  stop_cspd();
     
     stop_CIR_handlers(); /* stop the TCP CIR side. and http receivers */
     sc_shutdown_server();

     gwlist_destroy(csp_requests, NULL);     
     gwlist_destroy(ssp_requests, NULL);
     gwlist_destroy(sc_requests, NULL);
     gwlist_destroy(http_cir_requests, NULL);

     gwthread_join(cleanup_th);     
     
     info(0, "Shutdown complete... ");
     return 0;
}

static void cleanup_thread(void *unused)
{


     do { /* Do cleanup. */
	  int i, n;
	  PGconn *c = pg_cp_get_conn();
	  /* auto logout all tired ones  */
	  PGresult *r = PQexec(c, "SELECT sessionid FROM sessions WHERE lastt + '15 mins' < current_timestamp AND "
		     " extract(epoch from current_timestamp-lastt) > ttl");
	  n = PQresultStatus(r) == PGRES_TUPLES_OK ? PQntuples(r) : 0;
	  for (i = 0; i<n; i++) {
	       RequestInfo_t _ri = {0}, *ri = &_ri;
	       char *sid = PQgetvalue(r, i, 0);
	       strncpy(ri->xsessid, sid ? sid : "x", sizeof ri->xsessid);
	       ri->c = c;
	       ri->is_ssp = 0;
	       ri->ver = CSP_VERSION(1,3);	       
	       if (get_session_id(c, sid, ri) >= 0) {
		    /* force a logout. */
		    void *res = handle_logout(ri, NULL);
		    info(0, "Cleanup: CSP session %s timed-out", sid);
		    csp_msg_free(res);
		    free_req_info(ri, 0);
	       }	       
	  }
	  PQclear(r);
	  /* Delete expired or sent messages. XXX Do we need to tell sender ?? */
	  r = PQexec(c, "DELETE FROM ssp_message_queue WHERE sent = true OR edate<current_timestamp");
	  PQclear(r);

	  /* Ditto for csp queue. XXX do we tell sender?? */
	  r = PQexec(c, "DELETE FROM csp_message_queue WHERE edate<current_timestamp");
	  PQclear(r);

	  /* Delete shared content */
	  r = PQexec(c, "DELETE FROM shared_content WHERE edate<current_timestamp");
	  PQclear(r);
	  
	  pg_cp_return_conn(c);
	  gwthread_sleep(config->max_ttl*2); /* sleep for twice the max ttl */
     } while (!bstop);
}
