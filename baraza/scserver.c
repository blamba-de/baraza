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
#include "cspim.h"

static long thid;
static char myhostname[DEFAULT_BUF_LEN], mm_txt[512];
static char webroot[256];
static int sc_ssl, sc_port;
List *sc_requests;
static Dict *mime_types; /* Indexed by file extension, value is mime type */

static const char *get_file_ctype(char *fname)
{
     char *p;
     
     gw_assert(mime_types);
     
     /* start with the longest extension and look for the type, and keep looking for smaller extensions 
      * each time. If all else fails, return default type 
      */
     for (p = strchr(fname, '.'); p != NULL; p = strchr(p + 1, '.')) {
	  Octstr *x = octstr_create(p + 1);
	  Octstr *y = dict_get(mime_types, x);
	  
	  octstr_destroy(x);

	  if (y)
	       return octstr_get_cstr(y);
     }
     return "application/octet-stream";
}


static void handler_th(void *unused)
{
     HTTPRequest_t *hr;
     
     info(0, "Starting Shared Content HTTP server ");

     while ((hr = gwlist_consume(sc_requests)) != NULL) {
	  Octstr *id = http_cgi_variable(hr->cgivars, "i");
	  Octstr *ckey = http_cgi_variable(hr->cgivars, "d");	  
	  Octstr *keywd = http_cgi_variable(hr->cgivars, "keywd");
	  Octstr *session = http_cgi_variable(hr->cgivars, "session");
	  Octstr *msgid = http_cgi_variable(hr->cgivars, "message-id");

	  PGconn *c = pg_cp_get_conn();
	  const char *cmd ;
	  const char *pvals[10];
	  PGresult *r;
	  int nargs;
	  Octstr *ctype = NULL, *content = NULL;
	  List *rh = http_create_empty_headers();
	  
	  info(0, "Request for content ID=%s, key=%s, keyword=%s", 
	       octstr_get_cstr(id), octstr_get_cstr(ckey), 
	       octstr_get_cstr(keywd));	  
	  
	  if (ckey) {
	       pvals[0] = id ? octstr_get_cstr(id) : "-1";
	       pvals[1]  = octstr_get_cstr(ckey);
	       nargs = 2;
	       cmd = "SELECT content_type, content,content_encoding FROM shared_content WHERE "
		 "id = $1 AND content_key = $2";
	  } else if (keywd) {
	       pvals[0] = keywd ? octstr_get_cstr(keywd) : "x";
	       nargs = 1;
	       cmd = "SELECT content_type, content,content_encoding FROM shared_content WHERE "
		    "content_keyword = $1";	  
	  } else if (session && msgid) {
	       RequestInfo_t _ri = {0, 
				    .is_ssp = 0,
				    .c = c
	       }, *ri = &_ri;
	       
	       if (get_session_id(c, octstr_get_cstr(session), ri) == 0) {
		    GetMessage_Request_t r = csp_msg_new(GetMessage_Request, NULL,
							  FV(msgid, 
							     csp_String_from_bstr(msgid,
										  Imps_MessageID)));
		    GetMessage_Response_t resp = r ?  handle_get_msg(ri, r) : NULL;
		    
		    
		    if (resp == NULL)
			 goto end_getmsg;
		    
		    make_msg_data(resp->minfo, &resp->data, 1);
		    
		    ctype = csp_String_to_bstr(resp->minfo->ctype);
		    content = csp_String_to_bstr(resp->data);		    		    
	       end_getmsg:
		    csp_msg_free(r);		    
		    csp_msg_free(resp);

		    free_req_info(ri, 0);
	       }
	       cmd = NULL;
	  } else { 
	       /* Use the URI */
	       Octstr *fname = octstr_format("%s/%S", webroot, hr->uri);
	       
	       content = octstr_read_file(octstr_get_cstr(fname)); /* Might fail. Then below we return 404 */
	       ctype = octstr_create(get_file_ctype(octstr_get_cstr(fname)));
	       	       
	       cmd = NULL; /* So we don't bother with DB update */
	       octstr_destroy(fname);
	  }

	  if (cmd == NULL)
	       goto loop;
	  
	  r = PQexecParams(c, cmd, nargs, NULL, pvals, NULL, NULL, 0);
	  
	  if (PQresultStatus(r) == PGRES_TUPLES_OK &&  PQntuples(r) >= 1) {
	       char *enc = PQgetvalue(r, 0, 2);
	       content = get_bytea_data(r, 0, 1);
	       
	       if (content && enc && strcasecmp(enc, "base64") == 0)
		    octstr_base64_to_binary(content);
	       
	       ctype = octstr_create(PQgetvalue(r, 0, 0));
	  }
	  
	  PQclear(r);	  

     loop:	  
	  if (content) {
	       http_header_add(rh, "Content-Type", ctype ? octstr_get_cstr(ctype) : "text/plain");	       
	       http_send_reply(hr->c, HTTP_OK, rh, content);
	  } else 
	       http_send_reply(hr->c, HTTP_NOT_FOUND, rh, NULL);
	  
	  http_destroy_headers(rh);
	  octstr_destroy(content);
	  octstr_destroy(ctype);
	  
	  pg_cp_return_conn(c);
	  
	  free_http_request_info(hr);
     }

     info(0, "Stopping Shared Content HTTP server");
}

static void init_mime_info(char *file)
{
     List *l;
     Octstr *x, *y;
     if (mime_types != NULL)
	  return;
     
     mime_types = dict_create(107, (void *)octstr_destroy);
     
     x = octstr_read_file(file);
     
     if (x == NULL)
	  return;
          
     l = octstr_split(x, octstr_imm("\n"));
     octstr_destroy(x);
     
     while ((y = gwlist_extract_first(l)) != NULL) {
	  List *r  = NULL;
	  Octstr *ctype = NULL, *ext;
	  if (octstr_get_char(y, 0) == '#') /* A comment */
	       goto loop;

	  /* Now split into words. First word is the type, all the rest are extensions */
	  
	  if ((r = octstr_split_words(y)) == NULL ||
	      gwlist_len(r) == 0)
	       goto loop;
	  
	  ctype = gwlist_extract_first(r);
	  octstr_strip_blanks(ctype);
	  if (octstr_len(ctype) == 0)
	       goto loop;
	  
	  while ((ext = gwlist_extract_first(r)) != NULL) {
	       octstr_strip_blanks(ext);
	       
	       if (octstr_len(ext) > 0)
		    dict_put(mime_types, ext, octstr_duplicate(ctype));
	       
	       octstr_destroy(ext);
	  }
	  
     loop:
	  octstr_destroy(y);
	  octstr_destroy(ctype);
	  gwlist_destroy(r, (void *)octstr_destroy);
     }

     gwlist_destroy(l, (void *)octstr_destroy);
}

static void clear_mime_info(void)
{
     dict_destroy(mime_types);
     mime_types = NULL;
}

int sc_init_server(struct imps_conf_t *config)
{

     char *this_host = config->myhostname;
     
     sc_ssl = config->use_ssl;
     sc_port = config->http_port;
     strncpy(myhostname, this_host, sizeof myhostname);

     strncpy(mm_txt, config->mm_txt, sizeof mm_txt);
     strncpy(webroot, config->webroot, sizeof webroot);
     init_mime_info(config->mime_types_file);
     
     thid = gwthread_create((gwthread_func_t *)handler_th, NULL);

     return 0;
}

void sc_shutdown_server(void)
{     
     gwthread_join_every((void *)handler_th);
     clear_mime_info();
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
