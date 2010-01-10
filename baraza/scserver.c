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
#include "conf.h"
#include "scserver.h"


static long thid;
static char myhostname[DEFAULT_BUF_LEN], mm_txt[512];
static int sc_ssl, sc_port;
List *sc_requests;

static void handler_th(void *unused)
{
     HTTPRequest_t *hr;
     
     info(0, "Starting Shared Content HTTP server ");

     while ((hr = gwlist_consume(sc_requests)) != NULL) {
	  Octstr *id = http_cgi_variable(hr->cgivars, "i");
	  Octstr *ckey = http_cgi_variable(hr->cgivars, "d");	  
	  Octstr *keywd = http_cgi_variable(hr->cgivars, "keywd");	  
	  PGconn *c = pg_cp_get_conn();
	  const char *cmd;
	  const char *pvals[10];
	  PGresult *r;
	  int nargs;
	  
	  info(0, "Request for content ID=%s, key=%s, keyword=%s", 
	       octstr_get_cstr(id), octstr_get_cstr(ckey), 
	       octstr_get_cstr(keywd));	  
	  
	  if (ckey) {
	       pvals[0] = id ? octstr_get_cstr(id) : "-1";
	       pvals[1]  = octstr_get_cstr(ckey);
	       nargs = 2;
	       cmd = "SELECT content_type, content,content_encoding FROM shared_content WHERE "
		 "id = $1 AND content_key = $2";
	  } else {
	       pvals[0] = keywd ? octstr_get_cstr(keywd) : "x";
	       nargs = 1;
	       cmd = "SELECT content_type, content,content_encoding FROM shared_content WHERE "
		    "content_keyword = $1";	  
	  }

	  r = PQexecParams(c, cmd, nargs, NULL, pvals, NULL, NULL, 0);
	  
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) 
	       http_close_client(hr->c);
	  else {
	       List *rh = http_create_empty_headers();
	       Octstr *data = get_bytea_data(r, 0, 1);
	       char *enc = PQgetvalue(r, 0, 2);

	       if (data && enc && strcasecmp(enc, "base64") == 0)
		    octstr_base64_to_binary(data);
	       
	       http_header_add(rh, "Content-Type", PQgetvalue(r, 0, 0));
	       
	       http_send_reply(hr->c, HTTP_OK, rh, data ? data : octstr_imm(""));
	       
	       http_destroy_headers(rh);
	       octstr_destroy(data);
	  }
	  PQclear(r);
	  pg_cp_return_conn(c);
	  
	  free_http_request_info(hr);
     }

     info(0, "Stopping Shared Content HTTP server");
}

int sc_init_server(struct imps_conf_t *config)
{

     char *this_host = config->myhostname;
     
     sc_ssl = config->use_ssl;
     sc_port = config->http_port;
     strncpy(myhostname, this_host, sizeof myhostname);

     strncpy(mm_txt, config->mm_txt, sizeof mm_txt);

     thid = gwthread_create((gwthread_func_t *)handler_th, NULL);

     return 0;
}
void sc_shutdown_server(void)
{     
     gwthread_join_every((void *)handler_th);
}

Octstr *sc_add_content(PGconn *c, char *ctype, char *enc, char *data, long dsize)
{
     PGresult *r;
     Octstr *res;
     const char *pvals[10];
     int plens[10] = {0}, pfrmt[10] = {0};
     
     gw_assert(data);
     
     pvals[0] = ctype;
     pvals[1] = data;
     plens[1] = dsize;
     pfrmt[1] = 1;
     
     pvals[2] = enc ? enc : "";

     r = PQexecParams(c, 
		      "INSERT INTO shared_content (content_type, content, content_encoding, content_key) "
		      "VALUES ($1, $2, $3, md5(current_timestamp||'mykey')) "		    
			 "RETURNING id, content_key", 
		      3, NULL, pvals, plens, pfrmt, 0);
     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) 
	  res = NULL;
     else {
	  Octstr *id = octstr_create(PQgetvalue(r, 0, 0));
	  Octstr *ckey = octstr_create(PQgetvalue(r, 0, 1));

	  res = octstr_format("%s http%s://%s:%d%s?i=%E&d=%E",
			      mm_txt,
			      sc_ssl ? "s" : "",
			      myhostname, sc_port, SC_URI, id, ckey);
	  octstr_destroy(id);
	  octstr_destroy(ckey);
     }
     PQclear(r);


     return res;
}
