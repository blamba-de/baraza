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
#include <errno.h>
#include "utils.h"
#include "pgconnpool.h"
#include "cspcir.h"
#include "cspim.h"
#include "baraza.h"
#include <wap/wsp_headers.h>
static int cir_stop = 0;

struct CIRTarget_t {
     int64_t uid;
     char clientid[DEFAULT_BUF_LEN];
};

struct TCPCIRInfo_t {
     char sessid[DEFAULT_BUF_LEN];
     char ip[DEFAULT_BUF_LEN];
     time_t lastt;
};
static int cir_tcp_socket;
static FDSet *myfdset;
static Dict *cir_clients;
static      long cir_th;
static enum cir_methods_t *cir_methods;
static char *send_sms_url;

List *http_cir_requests = NULL;
#define TCPCIR_TIMEOUT 60
#define DEFAULT_CIR_LOGON_TIME 300 /* while we're testing. */
#define SLEEP_SECS 15
static void send_to_bot(PGconn *c, int64_t bot_uid, char url[]);

static char *get_salt(char *uri, char salt[])
{
  char *p, *lim = strrchr(uri, '/'), *q = salt;

     if (lim == NULL)
	  return "";
     /* found the end, now find the beginning. */
     p = lim - 1;
     while (p>uri && *p != '/')
	  p--;
     if (*p == '/')
	  p++;
     
     /* Now copy forward. */
     while (*p && p < lim)
	  *salt++ = *p++;
     *salt = 0;
     
     return q;
}


static void cir_http_request_handler(List *req_list)
{
     struct HTTPRequest_t *r;
     while ((r = gwlist_consume(req_list)) != NULL) {
	  char buf[128];
	  RequestInfo_t ri = {0};
	  List *rh = http_create_empty_headers();
	  char *xurl = octstr_get_cstr(r->uri);
	  char *x, *xsess = (x = strrchr(xurl, '/')) ? x+1 : "";
	  char *salt = get_salt(xurl, buf);
	  int http_res = 204;
	  PGconn *c = pg_cp_get_conn(); /* acquire a connection for our transaction. */

	  if (c != NULL) {
	       int64_t sid = strtoull(xsess, NULL, 10);
	       int res = get_session_info(c, sid, &ri);
	       int chk = (res == 0) ? check_salt(&ri, salt) : -1;
	       http_res = (res == 0 && chk == 0 && 
			   has_pending_msgs(c, ri.uid, ri.clientid, 
					    ri.conf->min_ttl,
					    ri.conf->max_ttl) == 1) ? 200 : 204;
	       
	       pg_cp_return_conn(c); /* give back the connection. */
	  } else 
	       error(0, "cspcir.http: Failed to get DB connection!");
	  
	  http_send_reply(r->c, http_res,  rh, octstr_imm(""));
	  
	  free_req_info(&ri, 0);

	  http_destroy_headers(rh);
	  free_http_request_info(r);
     }
}

void cir_newmsg(CIRTarget_t *x)
{
     /* first lets see if we can find a session for this user. */
     char xuid[64], tmp1[DEFAULT_BUF_LEN];
     int64_t uid;
     char * clientid;
     PGresult *r  = NULL;
     int i, n;
     PGconn *c = pg_cp_get_conn();
     Dict *dd = dict_create(7, NULL);
     const char *pvals[4];
     
     gw_assert(x);
     if (is_bot(c, x->uid, tmp1, NULL) && tmp1[0]) { /* handle Bot. */
	  send_to_bot(c, x->uid, tmp1);
	  goto done;
     }

     uid = x->uid;
     clientid = x->clientid;
     
     sprintf(xuid, "%lld", uid);

     pvals[0] = xuid;
     pvals[1] = clientid;
     
     if (clientid && clientid[0]) 
	  r = PQexecParams(c, "SELECT sessionid,cookie, csp_version,msisdn,request_ip,cir_mask,sudp_port "
			   " FROM sessions WHERE userid = $1 "
			   "AND "
			   " (clientid = $2 OR clientid = '')",
			   2, NULL, pvals, NULL, NULL, 0);
     else 
	  r = PQexecParams(c, "SELECT sessionid,cookie, csp_version,msisdn,request_ip,cir_mask,sudp_port "
			   " FROM sessions WHERE userid = $1 ",
			   1, NULL, pvals, NULL, NULL, 0);
	       
     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) 
	  goto done;
     
     n = PQntuples(r);
     for (i = 0; i<n; i++) { /* inform all that are waiting, but only first one gets it. */
	  char *zz;
	  char *s = PQgetvalue(r, i, 0);
	  char *cookie = PQgetvalue(r, i, 1);
	  char *v = PQgetvalue(r, i, 2);
	  char *msisdn = PQgetvalue(r, i, 3);
	  char *req_ip = PQgetvalue(r, i, 4);
	  int cir_mask = (zz = PQgetvalue(r, i, 5)) ? atoi(zz) : 0;
	  int sudp_port = (zz = PQgetvalue(r, i, 6)) ? atoi(zz) : 0; 
	  Octstr *xmsisdn = msisdn ? octstr_create(msisdn) : NULL;
	  Octstr *xreq_ip = req_ip ? octstr_create(req_ip) : NULL;
	  int major = 0, minor = 0;
	  Octstr *xkey = octstr_create(s ? s : "");
	  Connection *cinfo; /* STCP CIR connection. */
	  Octstr *cir_msg;

	  sscanf(v, "%d.%d", &major, &minor);
	  cir_msg = octstr_format("WVCI %d.%d %s", 
				  major, 
				  minor, 
				  cookie ? cookie : "");
	  if (cir_clients && (cinfo = dict_get(cir_clients, xkey)) != NULL) {/* first try STCP */	       
	       info(0, "STCP CIR sending out: %s", octstr_get_cstr(cir_msg));
	       conn_write(cinfo, cir_msg); /* XXX what happens if  it has been destroyed in the meantime? */
	       conn_write(cinfo, octstr_imm("\r\n"));
	  } else {
	       /* Try WAPUDP and WAPSMS in the order requested. */
	       static unsigned char ct; /* trans counter. */
	       Octstr *wap_msg = octstr_create("");
	       Octstr *wap_msg_hdr = octstr_create("");
	       int i;
	       
	       octstr_append_char(wap_msg, ++ct); /* Push ID */
	       octstr_append_char(wap_msg, 0x06); /* PUSH message. */
#if 0
	       octstr_append_char(wap_msg, 1+strlen(CIR_CONTENT_TYPE)); /* header length. */
	       octstr_append_cstr(wap_msg, CIR_CONTENT_TYPE);
	       octstr_append_char(wap_msg, 0x00);
#else 
	       wsp_pack_integer_value(wap_msg_hdr, WAP_CIR_CONTENT_TYPE); /* content type ID for cir. */

	      //  octstr_append_char(wap_msg_hdr, 0xC6); 

	       octstr_append_char(wap_msg_hdr, 0xAF); /* X-Wap-Application-ID: 56731 */
	       wsp_pack_integer_value(wap_msg_hdr, CIR_APP_ID);

	       octstr_append_char(wap_msg, octstr_len(wap_msg_hdr)); /* length of headers. */
	       octstr_append(wap_msg, wap_msg_hdr); /* followed by headers. */
	       
	       octstr_destroy(wap_msg_hdr);
#endif
	       octstr_append(wap_msg, cir_msg);
	       
	       for (i = 0; i<MAXLIST && cir_methods[i] != CIR_NONE; i++) {
		    int sent = 0;

		    if (cir_methods[i] == CIR_WAPSMS && send_sms_url && octstr_len(xmsisdn) > 0 && 
			(cir_mask & HAS_WAPSMS) && 
			dict_get(dd, xmsisdn) == NULL) { /* don't send twice to same number. */
			 Octstr *udh;
			 Octstr *url;
			 List * rh = http_create_empty_headers();
			 int res;
			 udh = octstr_create("060504" WAP_PUSH_PORT "23F0");
			 octstr_hex_to_binary(udh);
			 url = octstr_format("%s&text=%E&udh=%E&to=%E", 
					     send_sms_url, wap_msg, udh, xmsisdn);
			 res = fetch_url(url, HTTP_METHOD_GET, NULL, rh, NULL, NULL);

			 info(0, "WAPSMS CIR sending out[%s -> %d]: %s ", msisdn, res, octstr_get_cstr(cir_msg));
			 octstr_destroy(udh);
			 http_destroy_headers(rh);
			 sent = (http_status_class(res) == HTTP_OK);

			 dict_put(dd, xmsisdn, (void *)1); /* mark as handled. */
		    } else if (cir_methods[i] == CIR_WAPUDP && octstr_len(xreq_ip) > 0  && (cir_mask & HAS_WAPUDP)) {
			 Octstr *addr = udp_create_address(xreq_ip, WAP_PUSH_PORT_DEC);
			 int sock = udp_client_socket();
			 if (sock >= 0) {
			      udp_sendto(sock, wap_msg, addr);
			      sent = 1;
			      close(sock);
			      
			      info(0, "WAPUDP CIR sending out: %s", octstr_get_cstr(cir_msg));
			 }
			 octstr_destroy(addr);
		    } else if (cir_methods[i] == CIR_SUDP && octstr_len(xreq_ip) > 0  && (cir_mask & HAS_WAPUDP)) {
			 Octstr *addr = udp_create_address(xreq_ip, sudp_port);
			 int sock = udp_client_socket();
			 if (sock >= 0) {
			      udp_sendto(sock, cir_msg, addr);
			      sent = 1;
			      close(sock);
			      
			      info(0, "SUDP CIR sending out: %s", octstr_get_cstr(cir_msg));
			 }
			 octstr_destroy(addr);
		    }
		    if (sent) break;
	       }
	       octstr_destroy(wap_msg);
	  }
	  octstr_destroy(xkey);

	  octstr_destroy(cir_msg);
	  octstr_destroy(xmsisdn);
	  octstr_destroy(xreq_ip);
     }
     
done:
     if (r) 
	  PQclear(r);
     dict_destroy(dd);
     pg_cp_return_conn(c);
     gw_free(x);
}

#if 0
static void cir_notifier(Dict *sessions)
{
     do {
	  List *l = dict_keys(sessions);
	  Octstr *xkey;
	  
	  while ((xkey = gwlist_extract_first(l)) != NULL) {
	       Connection *cinfo = dict_get(sessions, xkey);
	       
	       if (cinfo) {
		    RequestInfo_t ri = {0};
		    PGconn *c = pg_cp_get_conn(); /* acquire a connection for our transaction. */
		    int res = get_session_id_ex(c, octstr_get_cstr(xkey), &ri, 1);
		    int msgs = (res == 0) && (has_pending_msgs(c, ri.uid, ri.clientid) == 1);
		    
		    
		    pg_cp_return_conn(c); /* give back the connection. */		    
		    if (msgs) {
			 Octstr *x = octstr_format("WVCI %d.%d %S\r\n", 
						   CSP_MAJOR_VERSION(ri.ver), 
						   CSP_MINOR_VERSION(ri.ver), 
						   ri.cookie);
			 
			 conn_write(cinfo, x); /* XXX what happens if  it has been destroyed in the meantime? */
			 octstr_destroy(x);
		    }
		    free_req_info(&ri, 0);
	       }
	       octstr_destroy(xkey);
	  }
	  gwthread_sleep(SLEEP_SECS);
     } while (!cir_stop);
}

#endif 

/* free: only called by Connection module. */
static void free_cir_info(struct TCPCIRInfo_t *cinfo)
{
     if (cinfo == NULL)
	  return;
     
     info(0, "Entered cir_free [%s]", cinfo->sessid);
     if (cinfo->sessid[0]) {
	  Octstr *xkey = octstr_create(cinfo->sessid);

	  dict_remove(cir_clients, xkey);
	  octstr_destroy(xkey);
     }
     gw_free(cinfo);
}

static void cir_processor(Connection *conn, struct TCPCIRInfo_t *data)
{
     Octstr *line = conn_read_line(conn);
     Octstr *cir_req = NULL;
     
     if (cir_stop || conn_eof(conn) || /* die on EOF , or if no logon within time limit. */
	 (!data->sessid[0] && time(NULL) - data->lastt > DEFAULT_CIR_LOGON_TIME)) {
	  info(0, "CIR: session being destroyed [ip=%s, sessid=%s]", 
	       data ? data->ip : "(none)",
	       data ? data->sessid : "(none)");
	  conn_unregister(conn);
	  conn_destroy(conn); /* destroy it and go. */
	  goto done;
     } else if (line == NULL) 
	  goto done;
     
     /* we have a single CIR request: check for HELO, use it to mark this thingie. */
     octstr_strip_blanks(line);
     info(0, "Received STCP CIR requested [from: %s]: %s", data->ip,  octstr_get_cstr(line));
     if (octstr_case_search(line, octstr_imm("HELO "), 0) == 0 && data->sessid[0] == 0) { /* only if not yet logged on.*/
	  RequestInfo_t ri = {0};
	  PGconn *c = pg_cp_get_conn(); /* acquire a connection for our transaction. */
	  char *xsess = octstr_get_cstr(line) + 5;
	  int res = get_session_id(c, xsess, &ri);
	  
	  if (res < 0)  /* no session: spec says, close connection, and quietly delete data object. */
	       warning(0, "CIR TCP request with sessid = %s: unknown session", xsess);
	  else {
	       Octstr *xkey = octstr_create(xsess);
	       int msgs = has_pending_msgs(c, ri.uid, ri.clientid, ri.conf->min_ttl, ri.conf->max_ttl);
	       
	       set_has_cir(c, ri.sessid, 1); /* mark as having CIR so we reduce on keep-alive requests. */

	       strncpy(data->sessid, xsess, sizeof data->sessid);
	       
	       /* put in our dict, indexed by session ID. */
	       if (dict_put_once(cir_clients, xkey, conn) == 0)  /* duplicate connection, kill it */
		    data->sessid[0] = 0;
	       
	       octstr_destroy(xkey);

	       if (msgs)
		    cir_req = octstr_format("WVCI %d.%d %S\r\n", 
					    CSP_MAJOR_VERSION(ri.ver), 
					    CSP_MINOR_VERSION(ri.ver), 
					    ri.cookie);
	  }
	  pg_cp_return_conn(c);
	  free_req_info(&ri, 0);	  
     } /* else  an ordinary ping */
     

     if (data->sessid[0]) {
	  conn_write(conn, octstr_imm("OK\r\n")); /* always reply with OK. */
	  if (cir_req)
	       conn_write(conn, cir_req);
     } else {
	  conn_unregister(conn);
	  conn_destroy(conn);	  /* no connection, or error: close it. */
     }
done:
     octstr_destroy(line);     
     octstr_destroy(cir_req);
}

static void cir_tcp_handler(void *unused)
{
     
     do {
	  struct sockaddr_in addr;
	  socklen_t alen = 0;

	  memset(&addr, 0, sizeof addr);
	  int fd = accept(cir_tcp_socket, (struct sockaddr *)&addr, &alen);
	  Octstr *ip = (fd >= 0) ? host_ip(addr) : NULL;	  
	  Connection *conn;
	  struct TCPCIRInfo_t *cinfo;
	  if (fd < 0) {
	       if (errno == EINTR)
		    goto loop;
	       else 
		    break;
	  }
	  info(0, "CIR TCP connect from: %s", octstr_get_cstr(ip));
	  conn = conn_wrap_fd(fd, 0);
	  
	  cinfo = gw_malloc(sizeof *cinfo);
	  cinfo->sessid[0] = 0;
	  cinfo->lastt = time(NULL);
	  strncpy(cinfo->ip, octstr_get_cstr(ip), sizeof cinfo->ip);

	  conn_register_real(conn, myfdset, (conn_callback_t *)cir_processor, cinfo, 
			     (conn_callback_data_destroyer_t *)free_cir_info);
     loop:
	  octstr_destroy(ip);
     } while (!cir_stop);
     
}

void start_CIR_handlers(int num_threads, int cir_stcp_port, enum cir_methods_t xcir_methods[],
     char *xsend_sms_url)
{
     int i;
          
     cir_methods = xcir_methods;
     send_sms_url = xsend_sms_url;
     
     if ((cir_tcp_socket = make_server_socket(cir_stcp_port, NULL)) < 0)
	  panic(0, "failed to open CIR tcp port: %d: %s", cir_stcp_port, strerror(errno));
     
     
     for (i = 0; i<num_threads; i++) /* start the http cir handlers. */
	  gwthread_create((gwthread_func_t *)cir_http_request_handler, http_cir_requests);
     
     myfdset = fdset_create_real(TCPCIR_TIMEOUT); /* time out is set to 60 seconds. */
     cir_clients = dict_create(10001, NULL);
     
     cir_th = gwthread_create((gwthread_func_t *)cir_tcp_handler, NULL);   /* start tcp CIR handler. */
     
}

void stop_CIR_handlers(void)
{
     
     gwthread_join_every((void *)cir_http_request_handler);
     
     close(cir_tcp_socket); /* close the server socket. */

     cir_stop = 1; /* Kill all of them . */
     
     gwthread_join(cir_th); /* after this, all pending connections should exit. Right? */

     dict_destroy(cir_clients);
     fdset_destroy(myfdset);
}

CIRTarget_t *make_cir_target(int64_t uid, char clientid[])
{
     CIRTarget_t *x = gw_malloc(sizeof x[0]);

     x->uid = uid;
     strncpy(x->clientid, clientid, sizeof x->clientid);
     
     return x;
}

static void add_multipart_element(MIMEEntity *plist, Octstr *data, char *fname, Octstr *ctype)
{
     MIMEEntity *p = mime_entity_create();
     Octstr *cd = octstr_format("form-data; name=\"%s\"", fname);
     List *xh = http_create_empty_headers();

     http_header_add(xh, "Content-Disposition", octstr_get_cstr(cd));	  
     if (ctype) /* This header must come after the above it seems. */
	  http_header_add(xh, "Content-Type", octstr_get_cstr(ctype));
     
     mime_replace_headers(p, xh);
     http_destroy_headers(xh);
     
     mime_entity_set_body(p, data);

     mime_entity_add_part(plist, p); /* add it to list so far. */
     mime_entity_destroy(p);

     octstr_destroy(cd);
}

/* Send messages for this Bot. */
static void send_to_bot(PGconn *c, int64_t bot_uid, char url[])
{
     void *msg;
     RequestInfo_t _ri = {
	  .binary = 1,
	  .ver = CSP_VERSION(1,3),
	  .sinfo = {
	       .push_len = INT_MAX, 
	       .pull_len = INT_MAX, 
	       .deliver_method = Push_DMethod
	  },
	  .conf = config,
     }, *ri = &_ri;

     
     if (url == NULL || url[0] == 0)
	  return;
     
     ri->c = c;
     ri->uid = bot_uid;
     sprintf(ri->_uid, "%lld", ri->uid);

     while ((msg = get_pending_msg(ri)) != NULL) {
	  int typ = CSP_MSG_TYPE(msg);
	  Octstr *data = NULL, *sender = NULL, *ctype = NULL;
	  Octstr *body = NULL, *rb = NULL, *u = NULL;
	  List *rh = http_create_empty_headers(), *xh = NULL;
	  NewMessage_t m;
	  MIMEEntity *x;
	  int ret;
	  
	  /* for now we only handle NewMsg */
	  if (typ != Imps_NewMessage)
	       goto loop;
	  
	  /* Get the content type and the sender, and the content data. */
	  m = msg;
	  if (m->data == NULL || m->minfo == NULL) 
	       goto loop;
	  
	  data = csp_String_to_bstr(m->data);
	  ctype = m->minfo->ctype ? csp_String_to_bstr(m->minfo->ctype) : octstr_imm("text/plain");
	  if (m->minfo->enc && 
	      strcasecmp(csp_String_to_cstr(m->minfo->enc), "base64") == 0)
	       octstr_base64_to_binary(data); /* remove encoding. */
	  sender = make_sender_str(m->minfo->sender);
	  
	  x = mime_entity_create();
	  /* make and send the request. */
	  http_header_add(rh, "User-Agent", PACKAGE "/" VERSION);	       	  	  
	  http_header_add(rh, "Content-Type", "multipart/form-data");	  	  
	  mime_replace_headers(x, rh);
	  http_destroy_headers(rh);
	  
	  /* add sender and IM. */
	  add_multipart_element(x, data, "im", ctype);
	  add_multipart_element(x, sender, "sender", NULL);
	  
	  rh = mime_entity_headers(x);
	  body = mime_entity_body(x);
	  mime_entity_destroy(x);

	  /* Make the request. */
	  u = octstr_create(url);
	  ret = url_fetch_content(HTTP_METHOD_POST, 
				  u, rh, body, &xh, &rb);
	  if (ret == HTTP_OK) { /* send back a Ack, also queue a response if any. */	       
	       if (m->minfo->msgid) { /* send the ack. */
		    MessageDelivered_t md = csp_msg_new(MessageDelivered, NULL,
							FV(msgid, csp_msg_copy(m->minfo->msgid)));
		    void *msg = handle_msg_delivered(ri, md);

		    csp_msg_free(msg);
		    csp_msg_free(md);
	       }
	       

	       if (octstr_len(rb) > 0) { /* send a response. */
		    void *z;
		    Octstr *ctype = NULL;
		    Octstr *params = NULL;
		    Octstr *enc = http_header_value(xh, octstr_imm("Content-Transfer-Encoding"));
		    SendMessage_Request_t sm;
		    MessageInfo_t minfo;
		    Recipient_t r = csp_msg_new(Recipient, NULL, NULL);
		    Sender_t o_sender = m->minfo->sender;
		    void *rto = csp_msg_copy(o_sender->u.val);
		    Sender_t n_sender = make_sender_struct(c, bot_uid, NULL, NULL, NULL);
		    List *el = NULL;
		    
		    get_content_type(xh, &ctype, &params);
		    
		    /* make recipient structure. */
		    if (o_sender->u.typ == Imps_User)
			 CSP_MSG_SET_FIELD(r, ulist,
					   gwlist_create_ex(rto));
		    else if (o_sender->u.typ == Imps_Group)
			 CSP_MSG_SET_FIELD(r, glist,
					   gwlist_create_ex(rto));
		    else 
			 csp_msg_free(rto);
		    
		    minfo = csp_msg_new(MessageInfo, NULL,
					FV(ctype, csp_String_from_bstr(ctype ? ctype : 
								       octstr_imm("text/plain"),
								       Imps_ContentType)),
					FV(enc, csp_String_from_bstr(enc ? enc : 
								     octstr_imm("NONE"), 
								     Imps_ContentEncoding)),
					FV(tdate, time(NULL)),
					FV(rcpt, r),
					FV(sender, n_sender));
		    
		    sm = csp_msg_new(SendMessage_Request, NULL,
				     FV(msginfo, minfo),
				     FV(data, csp_String_from_bstr(rb, Imps_ContentData)));
		    
		    /* XXX  There is a potential loop here, if we allow agents to push
		     * to other agents through the system: 
		     * each one keeps sending and notifying (CIR) the other, which then sends again.
		     */
		    z = handle_send_im(ri, sm);
		    		    
		    octstr_destroy(ctype);
		    octstr_destroy(params);
		    csp_msg_free(z);
		    octstr_destroy(enc);
		    gwlist_destroy(el, (void *)octstr_destroy); /* ignore errors. */
		    csp_msg_free(sm);
	       }
	  } else  {
	       char xuid[64];
	       sprintf(xuid, "%lld", bot_uid);
	       error(0, "Failed to fetch Bot URL [%s] for userid %s. HTTP code=%d", url, xuid, ret);
	  }
     loop:
	  csp_msg_free(msg);
	  octstr_destroy(data);
	  octstr_destroy(sender);
	  octstr_destroy(ctype);
	  octstr_destroy(body);
	  octstr_destroy(rb);
	  http_destroy_headers(xh);
	  http_destroy_headers(rh);
	  octstr_destroy(u);
     }
}
