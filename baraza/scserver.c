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
	  char tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN];
	  char buf[512];
	  PGresult *r;

	  info(0, "Request for content ID=%s, key=%s, keyword=%s", 
	       octstr_get_cstr(id), octstr_get_cstr(ckey), 
	       octstr_get_cstr(keywd));	  
	  PQ_ESCAPE_STR(c, id ? octstr_get_cstr(id) : "-1", tmp1);
	  if (ckey) {
	       PQ_ESCAPE_STR(c,  octstr_get_cstr(ckey), tmp2);
	       sprintf(buf, "SELECT content_type, content,content_encoding FROM shared_content WHERE "
		       "id = '%.128s' AND content_key = '%.128s'", 
		       tmp1, tmp2);
	  } else {
	       PQ_ESCAPE_STR(c, keywd ? octstr_get_cstr(keywd) : "x", tmp2);
	       sprintf(buf, "SELECT content_type, content,content_encoding FROM shared_content WHERE "
		       "content_keyword = '%.128s'", 
		       tmp2);	  
	  }
	  r = PQexec(c, buf);
	  
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
     Octstr *cmd;
     void *xdata;
     size_t dlen;
     char tmp1[DEFAULT_BUF_LEN];
     char tmp2[DEFAULT_BUF_LEN];
     PGresult *r;
     Octstr *res;
     
     gw_assert(data);
     
     xdata = PQescapeBytea((void *)data, dsize, &dlen);

     PQ_ESCAPE_STR(c, ctype, tmp1);
     PQ_ESCAPE_STR(c, enc ? enc : "", tmp2);

     cmd = octstr_format("INSERT INTO shared_content (content_type, content, content_encoding, content_key) "
			 "VALUES ('%s', E'%s'::bytea, '%.128s', md5(current_timestamp||'mykey')) "
			 "RETURNING id, content_key", 
			 tmp1, xdata, tmp2);

     r = PQexec(c, octstr_get_cstr(cmd));
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

     octstr_destroy(cmd);
     PQfreemem(xdata);

     return res;
}
