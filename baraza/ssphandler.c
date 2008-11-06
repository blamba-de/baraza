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
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <gwlib/gwlib.h>

#include "cspmessages.h"
#include "dns.h"
#include "utils.h"
#include "pgconnpool.h"
#include "mqueue.h"

#include "conf.h"
#include "sspmessages.h"
#include "ssphandler.h"

/* *** SSP Daemon. *** */

enum {Request_MODE, Response_MODE};

/* XXX will be in conf -- soon! */
char myhostname[DEFAULT_BUF_LEN] = "mirza.ds.co.ug", mydomain[DEFAULT_BUF_LEN] = "ds.co.ug"; 

static Octstr *certfile;

static int send_secret_token(Octstr *url, char *domain, char *transid, Octstr *a_secret, char *mode);
static int ssp_get_session(PGconn *c, char *domain, Octstr *our_domain, Octstr **sessid, Octstr **url);
static int ssp_send(Octstr *url, Octstr *xml, char *transid, char *sessid);

static Octstr *do_setup_trans(PGconn *c, xmlNodePtr node, int mode, char *trans, Octstr **b_url,
			      int *our_mode, Octstr **our_transid, HTTPClient *hc, int *reply_sent);
static List *do_trans(PGconn *c, xmlNodePtr transnode, int mode, char *trans, char *sessid,
		      Octstr *b_domain, Octstr *ip);

static Octstr *get_ssp_session_info(PGconn *c, char *sessid, Octstr **b_url, Octstr **b_domain)
{
     char buf[512], tmp[DEFAULT_BUF_LEN], *p;
     Octstr *a_sid;
     PGresult *r;
     
     PQ_ESCAPE_STR(c, sessid, tmp);
     if ((p = strchr(tmp, '@')) != NULL)
	  p++;
     else 
	  p = "";
     sprintf(buf, "UPDATE ssp_sessions SET ldate = current_timestamp WHERE b_sessionid = '%.128s' AND "
	     " ssp_domain = '%.128s' RETURNING ssp_domain_url, a_sessionid, ssp_domain", tmp, p);
     r = PQexec(c, buf);
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  char *x = PQgetvalue(r, 0, 0);
	  *b_url = octstr_create(x);
	  x = PQgetvalue(r, 0, 1);
	  a_sid = octstr_create(x);

	  x = PQgetvalue(r, 0, 2);
	  *b_domain = octstr_create(x);
     } else 
	  a_sid = NULL;
     PQclear(r);

     return a_sid;
}


/* does the processing:  */
static void ssp_process(List *reqs)
{
     HTTPRequest_t *r;
     
     while ((r = gwlist_consume(reqs)) != NULL) {
	  PGconn *c = pg_cp_get_conn();
	  xmlDocPtr xml;
	  xmlNodePtr node, child;
	  int res = -1, reply_sent = 0;
	  Octstr *b_url = NULL, *out_xml = octstr_create("");
	  char *sessid = NULL;
	  
#if 1	  
	  info(0, "Received SSP Request: %s", octstr_get_cstr(r->body)); 
#endif
	  /* first we parse the body, pull out SSP top-level node. */
	  xml = xmlParseMemory(octstr_get_cstr(r->body), octstr_len(r->body));
	  node  = xml ? find_node(xml->xmlChildrenNode, "WV-SSP-Message", 3) : NULL;
	  if (node == NULL) {
	       res =  HTTP_BAD_REQUEST;
	       goto done;
	  }
	  /* get the top node and first inner one. */
	  if ((node = find_nodebytype(node->children, XML_ELEMENT_NODE, 1)) == NULL ||
	      (child = find_nodebytype(node->children, XML_ELEMENT_NODE, 1)) == NULL) {
	       res = HTTP_BAD_REQUEST;
	       goto done;
	  }
	  
	  
	  if (xmlStrcasecmp(node->name, (void *)"SetupTransaction") == 0) {
	       char *x, *trans =  NATTR(node, "transactionID");
	       int mode, our_mode = Request_MODE;
	       Octstr *s, *our_tid = NULL;

	       if ((x =  NATTR(node, "mode")) != NULL && 
		   strcasecmp(x, "Request") == 0)
		    mode = Request_MODE;
	       else 
		    mode = Response_MODE;
	       
	       if ((s =  do_setup_trans(c, child, mode, trans, &b_url, &our_mode, &our_tid, r->c, &reply_sent)) == NULL)
		    res = -1;
	       else if (s) {		 
		    if (octstr_len(s) > 0) { /* we need to send back some response. */
			 gw_assert(our_tid); /* in order to send back we must have a trans id */
			 octstr_format_append(out_xml, "<SetupTransaction transactionID=\"%S\" mode=\"%s\">\n"
					      "%S\n</SetupTransaction>\n",
					      our_tid, (our_mode == Request_MODE) ? "Request" : "Response", s);
		    }
		    res = 200;
	       }
	       if (trans) 
		    xmlFree(trans);
	       if (x) 
		    xmlFree(x);	  
	       octstr_destroy(s);
	       octstr_destroy(our_tid);
	  } else if  (xmlStrcasecmp(node->name,  (void *)"Session") == 0) {
	       Octstr *b_domain = NULL;
	       Octstr *a_sid;

	       sessid =  NATTR(node, "sessionID");	       
	       a_sid = sessid ? get_ssp_session_info(c, sessid, &b_url, &b_domain) : NULL;
	       if (a_sid) {
		    Octstr *xout = octstr_create("");
		    for (child = node->children; child; child = child->next)
			 if (child->type == XML_ELEMENT_NODE &&
			     xmlStrcasecmp(child->name,  (void *)"Transaction") == 0) { /* transaction node. */	       
			      char *x, *trans =  NATTR(child, "transactionID");
			      int mode;
			      Octstr *s = NULL;
			      List *sl = NULL;
			      int j, m;

			      if ((x =  NATTR(child, "mode")) != NULL && 
				  strcasecmp(x, "Request") == 0)
				   mode = Request_MODE;
			      else 
				   mode = Response_MODE;

			      if (trans == NULL) {
				   error(0, "Missing transactionID in trans Node [sessid: %s]", sessid);
				   goto loop; /* no transaction ID in transaction */
			      }
			      
			      node = find_nodebytype(child->children, XML_ELEMENT_NODE, 1);
			      			      
			      if (node == NULL) {
				   error(0, "Missing transaction content node [sessid: %s]", sessid);
				   goto loop; /* no child in transaction */
			      }
			      sl = do_trans(c, node, mode, trans, sessid, b_domain, r->ip);

                              /* only request ever sends back.*/
			      if (mode == Request_MODE && gwlist_len(sl) > 0) 
				   for (j = 0, m = gwlist_len(sl); j<m; j++) 
					if ((s = gwlist_get(sl, j)) != NULL && 
					    octstr_len(s) > 0)
					     octstr_format_append(xout, 
								  "<Transaction mode=\"Response\" "
								  "transactionID=\"%s\">\n%S\n"
								  "</Transaction>\n",
								  trans, s);
			      loop:
			      if (sl) 
				   gwlist_destroy(sl, (void *)octstr_destroy);
			      if (trans)  xmlFree(trans);
			      if (x)   xmlFree(x);			 
			 }
		    if (octstr_len(xout) > 0) 
			 octstr_format_append(out_xml, 
					      "<Session sessionID=\"%S\">\n%S\n</Session>", a_sid, xout);
		    octstr_destroy(xout);
		    res = 200;  /* behave like we've handled it all, because we will respond via return. */
	       } else 
		    res = -1;  /* no session. */
	       
	       octstr_destroy(a_sid);
	       octstr_destroy(b_domain);
	  } else 
	       res = HTTP_BAD_REQUEST;     
     done:
	  pg_cp_return_conn(c);
	  
	  if (!reply_sent) {
	       if (res > 0)
		    send_http_ack(r->c, res);
	       else 
		    http_close_client(r->c);
	  }
	  
	  if (octstr_len(out_xml) > 0 && b_url != NULL)  { /* handle outgoing transaction. */
	       Octstr *s;
	       List *rh = http_create_empty_headers();
	       int http_code;
	       if (sessid)
		    http_header_add(rh, "x-wv-sessionid", sessid);
	       
	       s = octstr_format("<?xml version='1.0'?>\n"				 
				 "<WV-SSP-Message xmlns=\"http://www.openmobilealliance.org/DTD/WV-SSP1.3\">\n"
				 "%S\n</WV-SSP-Message>\n",
				 out_xml);
	       http_code = fetch_url(b_url, HTTP_METHOD_POST, s, rh, SSP_CONTENT_TYPE, certfile);

#if 1	  
	       info(0, "SSP Reply transaction [http result: %d]: %s", http_code, octstr_get_cstr(s)); 
#endif

	       http_destroy_headers(rh);
	       octstr_destroy(s);
	  }
	  if (sessid) 
	       xmlFree(sessid);
	  if (xml)
	       xmlFreeDoc(xml);
	  octstr_destroy(out_xml);
	  octstr_destroy(b_url);
	  free_http_request_info(r);
     }
}

List *ssp_requests;

/* Outgoing message handler. Returns SSP_XXX  */ 
static int ssp_msg_send(PGconn *c, EmptyObject_t msg, List *rcptlist,  Sender_t sender, 
		 char *domain, int64_t tid)
{
     Octstr *sessid = NULL, *url = NULL;
     List *l;
     int res;
     Octstr *from_domain = sender ?  get_sender_domain(sender) : octstr_create(mydomain);

     if (msg == NULL) {
	  error(0, "NULL msg in SSP handler for domain [%s]!", domain);
	  octstr_destroy(from_domain);
	  return SSP_ERROR_FATAL;
     } else  if ((res = ssp_get_session(c, domain, from_domain, &sessid, &url)) != SSP_OK) {
	  octstr_destroy(from_domain);
	  return res; 
     }
     octstr_destroy(from_domain);

     /* We got a session id. Now convert the message and send out. */
     if ((l = csp2ssp_msg(msg, NULL, sender, rcptlist)) == NULL) {
	  error(0, "Unsupported msg [type %s:%d] in SSP handler for domain [%s]!", 
		csp_obj_name(CSP_MSG_TYPE(msg)),
		CSP_MSG_TYPE(msg),
		domain);
	  return SSP_ERROR_FATAL;
     } else { /* we converted, so send to host. */
	  char xtid[256];
	  int i, n, m;
	  SSPRecipient_t *r;
	  
	  res = SSP_OK;
	  for (i = 0, m = gwlist_len(rcptlist), n = gwlist_len(l); i<n; i++) {
	       Octstr *s = gwlist_get(l, i);
	       Octstr *ssp_xml;
	       
	       r = (i<m) ? gwlist_get(rcptlist, i) : NULL;
	       
	       sprintf(xtid, "%010lld-%lld", tid, (r) ? r->id : 0);
	       ssp_xml = octstr_format("<?xml version='1.0'?>\n"
				       "<WV-SSP-Message xmlns=\"http://www.openmobilealliance.org/DTD/WV-SSP1.3\">\n" 
				       "<Session sessionID=\"%S\">\n"
				       "<Transaction mode=\"Request\" transactionID=\"%s\">\n"
				       "%S\n</Transaction>\n</Session>\n</WV-SSP-Message>\n", sessid, xtid,s);
	       
	       if (ssp_send(url, ssp_xml, xtid, octstr_get_cstr(sessid)) != SSP_OK) {
		    octstr_destroy(ssp_xml);
		    res = SSP_ERROR_TRANSIENT;
		    break;
	       } else if (r) 
		    r->sent = 1;
	       octstr_destroy(ssp_xml);
	  }
	  
	  /* mark the rest as sent, if sent. */
	  for ( ; i<m; i++)
	    if ((r = gwlist_get(rcptlist, i)) != NULL) 
	      r->sent = (res == SSP_OK);	  
     }
     
     gwlist_destroy(l, (void *)octstr_destroy);
     octstr_destroy(sessid);
     octstr_destroy(url);
     return res;
}

static Octstr *make_secret(char *to_domain, char *from_domain)
{
     unsigned long i = 0;
     Octstr *x = octstr_format("%s %ld %ld %s", to_domain, gw_rand(), ++i, from_domain);
     Octstr *y = md5digest(x);
     
     octstr_destroy(x);
     
     return y;
}
/* Tries the relays one by one until a good one is found. Returns -1 on error. */
static int try_send_secret(PGconn *c, SrvRecord_t recs, int scount, char *sessionid, 
			   char *mydomain, Octstr *secret, char *mode)
{
     int i, res;
     Octstr *xurl = NULL;
     char buf[256];
     PGresult *r;

     for (i = 0; i<scount; i++) {
	  Octstr *url;
	  
	  /* first try HTTPS, then HTTP: If we are able to send the token, then we 
	     assume all else will be well. 
	  */
	  url = octstr_format("https://%.128s:%d/", recs[i].host, recs[i].port);
	  if (send_secret_token(url, mydomain, sessionid, secret, mode) == SSP_OK) {  /* success. */
	       xurl = url;
	       break;
	  } 
	  octstr_destroy(url);
	  url = octstr_format("http://%.128s:%d/", recs[i].host, recs[i].port);
	  if (send_secret_token(url, mydomain, sessionid, secret, mode) == SSP_OK) {  /* success. */
	       xurl = url;
	       break;
	  } 
	  octstr_destroy(url);	  
     }
     
     if (xurl) {
	  sprintf(buf, "UPDATE ssp_sessions SET ssp_domain_url = '%.128s' WHERE id = %s", 
		  octstr_get_cstr(xurl), sessionid);
	  info(0, "SSPsendtoken: Sent initial greeting to %s for domain %s", octstr_get_cstr(xurl), mydomain);
	  res = 0;
     } else { /* Delete it. */
	  sprintf(buf, "DELETE FROM ssp_sessions WHERE id = %s", sessionid);
	  info(0, "SSPsendtoken: No hosts accepted initial greeting for domain %s.", mydomain);
	  res = -1;     
     }

     r = PQexec(c, buf);
     PQclear(r);
     
     octstr_destroy(xurl);
     return res;
}

/* find a session we can use. If none exists, start a new session. */
static int ssp_get_session(PGconn *c, char *domain, Octstr *our_domain, Octstr **sessid, Octstr **url)
{     
     int i, n,  res;
     int scount = 0;
     char buf[512], tmp1[DEFAULT_BUF_LEN];
     PGresult *r;
     SrvRecord_t recs;
     Octstr *a_secret;

     *sessid = NULL;
     *url = NULL;

     PQ_ESCAPE_STR(c, octstr_get_cstr(our_domain), tmp1);
     sprintf(buf, "SELECT ssp_domain_url, a_sessionid, to_char(ldate,'YYYYMMDD') FROM ssp_sessions WHERE "
	     "ssp_domain = '%.128s' AND mydomain='%.128s'", domain, tmp1);
     r = PQexec(c, buf);

     if (PQresultStatus(r) == PGRES_TUPLES_OK && (n = PQntuples(r)) > 0) { /* we got something. */
	  for (i = 0; i<n; i++) {
	       char *u = PQgetvalue(r, i, 0);
	       char *s = PQgetvalue(r, i, 1);

	       if (!PQgetisnull(r, i, 2)) { /* we have a session! */		    
		    *sessid = octstr_create(s);
		    *url = octstr_create(u);
		    PQclear(r);
		    return SSP_OK;		   		    
	       } 
	  }
	  
	  /* we have one but it's still connecting. So return Transient. */
	  PQclear(r);
	  return SSP_ERROR_TRANSIENT;
     }
     
     PQclear(r);

     /* no connections,  Time to make one. Do a DNS lookup. If that fails, return ERROR_FATAL,
      * if it succeeds, try to connect to the hosts in order of pref. if one succeeds, then we are good. 
      *
      * 
      */
     
     if ((recs = dns_find_srv(domain, "_imps-server._tcp", &scount)) == NULL || scount == 0) {
	  if (recs)
	       gw_free(recs);	  
	  info(0, "S2S Imps: Domain [%s] does not do ssp", domain);
	  return SSP_ERROR_FATAL;
     }
     
     res = SSP_ERROR_TRANSIENT;
     
     a_secret = make_secret(domain, octstr_get_cstr(our_domain));
     /* we first create the entry so we have a transaction ID. */
     PQ_ESCAPE_STR(c, octstr_get_cstr(our_domain), tmp1);
     sprintf(buf, "INSERT INTO ssp_sessions (ssp_domain, outgoing, a_secret, mydomain) "
	     " VALUES ('%.128s', true, '%.128s', '%.128s') RETURNING id",
	     domain, octstr_get_cstr(a_secret), tmp1);

     
     r = PQexec(c, buf);
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) 	  
	  try_send_secret(c, recs, scount, 
			  PQgetvalue(r, 0, 0), 
			  octstr_get_cstr(our_domain), a_secret, "Request"); /* will delete session on fail.*/
     
     PQclear(r);
     octstr_destroy(a_secret);
     gw_free(recs);

     return res;
}

static int ssp_send(Octstr *url, Octstr *xml, char *transid, char *sessid)
{
     List *rh = http_create_empty_headers();
     int status, res;
     
     if (transid)
	  http_header_add(rh, "x-wv-transactionid", transid);
     if (sessid)
	  http_header_add(rh, "x-wv-sessionid", sessid);
     status = fetch_url(url, HTTP_METHOD_POST, xml, rh, "application/vnd.wv.ssp+xml", certfile);
#if 1
     info(0, "SSP sending transaction data [http result: %d]: %s", status, octstr_get_cstr(xml)); 
#endif
     res  = (http_status_class(status) == HTTP_STATUS_SUCCESSFUL) ? SSP_OK : SSP_ERROR_TRANSIENT;
	  
     http_destroy_headers(rh);
     return res;
}

static int send_secret_token(Octstr *url, char *domain, char *transid, Octstr *a_secret, char *mode)
{
     Octstr *xml;
     int res;

     xml = octstr_format("<?xml version='1.0'?>\n"
			 "<WV-SSP-Message xmlns=\"http://www.openmobilealliance.org/DTD/WV-SSP1.3\">\n" 
			 " <SetupTransaction mode=\"%s\" transactionID=\"%.128s\">\n" 
			 " <SendSecretToken serviceID=\"wv:@%s\" protocol=\"WV-SSP\"\n" 
			 "procotolVersion=\"1.3\">\n" 
			 "<SecretToken>\n"  /* We don't base64 encode our secrets */
			 "%S\n" 
			 "</SecretToken> \n"
			 "</SendSecretToken> \n"
			 "</SetupTransaction> \n"
			 "</WV-SSP-Message> \n", 
			 mode,
			 transid, domain, a_secret);
     
     res = ssp_send(url, xml, transid, NULL);
     octstr_destroy(xml);
     return res;
}


/* Do what the transaction asks of us. Gets node inside the transaction node. */
static List *do_trans(PGconn *c, xmlNodePtr transchild, int mode, char *trans, char *sessid, 
		      Octstr *b_domain, Octstr *ip)
{
     int64_t our_tid, our_rid, orig_sender_uid;
     User_t sender = NULL;
     List *rcptlist = NULL;
     EmptyObject_t msg;
     int mtype;
     List *res = NULL;
     Octstr *orig_sender_clientid = NULL;
     int code, csp_ver = CSP_VERSION(1,2);
     void *orig_msg = NULL;
     
     if (mode == Response_MODE) {  /* extract our transaction ID. */
	  char *p = strchr(trans, '-');
	  our_tid = strtoull(trans, NULL, 10);	  
	  our_rid = (p) ? strtoull(p+1, NULL, 10) : -1;
	  /* get the user (if any) who sent us the information */
	  queue_get_ssp_sender_info(c, our_tid, &orig_sender_uid, &orig_sender_clientid, 
			       &csp_ver, &orig_msg);
     } else 
	  our_tid = our_rid = orig_sender_uid = -1;
     
     /* find first child and see if we can convert message from SSP  */
     if ((msg = ssp2csp_msg(transchild, &rcptlist, &sender, csp_ver, orig_msg)) == NULL) 
	  res = gwlist_create_ex(octstr_imm("<Status code=\"405\"/>"));
     else if (sender && (code = verify_ssp_sender(sender, b_domain)) != 200)
	  res = gwlist_create_ex(octstr_format("<Status code=\"%d\"/>", code));
     else {
	  Octstr *xuserid = NULL, *xclientid = NULL;	  
	  Recipient_t rto = NULL, *rto_ptr = NULL;
	  List *el = NULL;
          Sender_t xsender = NULL;
	  Octstr *xres = NULL;
	  int dont_send = 0;
	  
	  if (sender) {
	       ApplicationID_t appid;
	       ClientID_t clnt;		    

	       appid = (sender->u.typ == Imps_ApplicationID) ? sender->u.val : NULL;
	       clnt = (sender->u.typ == Imps_ApplicationID) ? NULL : sender->u.val;

	       xclientid = make_clientid(clnt, appid);
	       xuserid = csp_String_to_bstr(sender->user);
	       xsender = csp_msg_new(Sender, NULL,
				     UFV(u, Imps_User, csp_msg_copy(sender)));
	  } 

	  switch (mtype = CSP_MSG_TYPE(msg)) {
	  case Imps_InviteUser_Response: /* handle the ones that must be handled here. */
	       rto_ptr = &((InviteUser_Response_t)msg)->rcpt;
	       goto process;
	  case Imps_DeliveryReport_Request:
	       if (((DeliveryReport_Request_t)msg)->minfo)
		    rto_ptr = &((DeliveryReport_Request_t)msg)->minfo->rcpt;
	       goto process;
	  case Imps_SendMessage_Response:
	    {
		 SendMessage_Response_t sm = (void *)msg;
		 if (sm->res && sm->res->code == 200)
		      dont_send = 1; /* optimize: don't report success. It was reported before (right??) */
	    }
	    goto process;
	  case Imps_Result: 

	       if (((Result_t)msg)->code == 200) /* ignore success :-) */
		    dont_send = 1;
	       else { 	       /* change to status. */
		    msg = (void *)csp_msg_new(Status, NULL, FV(res, msg));
		    mtype = Imps_Status;
	       }
	       goto process;
	  case Imps_PresenceNotification_Request:
	  case Imps_GetPresence_Response:
	  case Imps_JoinGroup_Response:
	  case Imps_LeaveGroup_Response:
	  case Imps_GetGroupMembers_Response:
	  case Imps_GetJoinedUsers_Response:
	  case Imps_GetGroupProps_Response:
	  case Imps_RejectList_Response:
	  case Imps_GroupChangeNotice:
	  case Imps_SubscribeGroupNotice_Response: /* although not clear if client can tell why it's receiving this.*/
	    
	  process:
	       if (rcptlist == NULL) /* then we use the original sender. */
		    rto = make_local_rcpt_struct(c, orig_sender_uid, orig_sender_clientid);
	       else 
		    rto = csp_msg_new(Recipient, NULL, FV(ulist, rcptlist));	       

	       /* queue it and send no reply. */
	       if (!dont_send)
		    xres = queue_msg(c, xsender, -1, xuserid,
				     xclientid ? octstr_get_cstr(xclientid) : NULL,
				     rto, msg, mtype, rto_ptr, 0, 0, NULL, 
				     time(NULL) + DEFAULT_EXPIRY, 1, csp_ver, &el);
	       break;
	  default: /* the rest we use csp processor. */
	  {	       
	       RequestInfo_t r = {0};
	       
	       
	       r.c = c;
	       r.req_ip = ip;
	       r.xsessid = sessid;
	       r.is_ssp = 1;
	       r.uid = r.sessid = -1;
	       r.ver = CSP_VERSION(1,3); /* we lie! */

	       r.userid = xuserid;
	       r.clientid = xclientid;
	       
	       if (req_funcs[mtype] == NULL) {
		    error(0, "unsupported request type %d [%s] on SSP interface, rejected", 
			  mtype, csp_obj_name(mtype));
		    res = gwlist_create_ex(octstr_imm("<Status code=\"501\"/>"));
	       } else {
		    EmptyObject_t xres = req_funcs[mtype](&r, msg);
		    
		    if (xres) {			 
			 res = csp2ssp_msg(xres, msg, NULL, NULL);
			 
			 csp_msg_free(xres);
		    } else 
			 res = gwlist_create_ex(octstr_imm(""));
	       }       
	  }
	  break;
	  }
	  octstr_destroy(xclientid);
	  octstr_destroy(xuserid);
	  octstr_destroy(xres);
	  gwlist_destroy(el, (void *)_csp_msg_free);
     }
     
     csp_msg_free(msg);
     gwlist_destroy(rcptlist, (void *)_csp_msg_free);
     octstr_destroy(orig_sender_clientid);
     csp_msg_free(sender);
     csp_msg_free(orig_msg);
     return res;
}

/* handles the setup transaction business. */
static Octstr *do_setup_trans(PGconn *c, xmlNodePtr node, int mode, char *trans, Octstr **b_url,
			      int *our_mode, Octstr **our_transid, HTTPClient *hc, int *reply_sent)
{
     char buf[512], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN], tmp3[DEFAULT_BUF_LEN];
     char *fld,  value[DEFAULT_BUF_LEN], *xtid;
     	  char mytid[100];
     Octstr *res = NULL;

     xtid = NULL;     
     if (xmlStrcasecmp(node->name,  (void *)"SendSecretToken") == 0) { /* sending a secret. */	       
	  char *sid = NATTR(node, "serviceID"), *x;
	  char *domain = sid ? strchr(sid, '@') : NULL;
	  xmlNodePtr snode = find_node(node->xmlChildrenNode, "SecretToken",  3);	  
	  Octstr *b_secret;
	  PGresult *r;
  
	  if (sid == NULL || snode == NULL || domain == NULL) {
	       if (sid) xmlFree(sid);
	       return NULL;
	  } else 	       
	       domain++;
	  
	  /* extract the secret token. */
	  if ((b_secret  = _xmlNodeContent(snode)) == NULL) 
	       b_secret = octstr_create("");

	  if ((x = NATTR(snode, "encoding")) != NULL) {
	       octstr_base64_to_binary(b_secret);
	       xmlFree(x);
	  }
	  PQ_ESCAPE_STR(c, domain, tmp1);	       	  
	  PQ_ESCAPE_STR(c, octstr_get_cstr(b_secret), tmp2);
	  if (mode == Response_MODE) { /* domain is responding, so we'll send a login-request */	       
	       
	       PQ_ESCAPE_STR(c, trans ? trans : "", tmp3);	  
	       
	       /* Sec 9.2.1 says that the response we send has our own transaction ID. Why should it?? */
	       sprintf(buf, "UPDATE ssp_sessions SET b_secret = '%.128s',b_transid = '%.128s'  WHERE "
		       " ssp_domain='%.128s' AND b_secret IS NULL AND outgoing = true RETURNING id,ssp_domain_url,mydomain", 
		       tmp2, tmp3, tmp1); 
	       r = PQexec(c, buf);

	       if (PQresultStatus(r) == PGRES_TUPLES_OK &&
		   PQntuples(r) > 0) { /* We found one, so lets send loginrequest. */
		    Octstr *pdigest;
		    char *mydomain;
		    
		    strncpy(mytid, PQgetvalue(r, 0, 0), sizeof mytid);

		    *b_url = octstr_create(PQgetvalue(r, 0, 1));		    
		    mydomain = PQgetvalue(r, 0, 2);

		    pdigest = md5(b_secret);
		    octstr_binary_to_base64(pdigest);
		    
		    res = octstr_format("<LoginRequest serviceID=\"wv:@%s\" timeToLive=\"%d\">\n" 
					"<PasswordDigest encoding=\"base64\">\n%S\n" 
					"</PasswordDigest>\n</LoginRequest>\n",
					mydomain, DEFAULT_EXPIRY, pdigest);
		    *our_mode = Request_MODE;
		    xtid = mytid;
		    
		    octstr_destroy(pdigest);
		    
	       } else 
		    res = NULL;
	       PQclear(r);	       
	  } else { /* Request: A first sendsecret token. */
	       Octstr *a_secret = make_secret(domain, mydomain), *xurl = NULL;
	       SrvRecord_t recs = NULL;
	       int scount;
	       PGresult *r;

	       res = NULL; /* assume error. */
	       
	       PQ_ESCAPE_STR(c, trans ? trans : "", tmp3);	  
	       sprintf(buf, "INSERT INTO ssp_sessions (ssp_domain, outgoing, a_secret, b_secret, mydomain, b_transid) "
		       " VALUES ('%.128s', false, '%.128s', '%.128s', '%.128s', '%.128s') RETURNING id",
		       tmp1, octstr_get_cstr(a_secret), tmp2, mydomain, tmp3);     

	       r = PQexec(c, buf);
	       if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0)
		    goto done1;	       

		    
	       /* Do a DNS lookup for the other guy, try to send until success. Then update DB or fail. */
	       
	       if ((recs = dns_find_srv(domain, "_imps-server._tcp", &scount)) == NULL || scount == 0) {
		    warning(0, "handle_setup_trans: Received secrettoken request but domain %s does not do ssp", domain);
		    goto done1;
	       }
	       
	       /* we got some records. So: Send an ack to the caller, then find which of these servers works best */  	       
	       send_http_ack(hc, HTTP_OK);
	       *reply_sent = 1;
	       	       
	       try_send_secret(c, recs, scount, PQgetvalue(r, 0,0), mydomain, a_secret, "Response"); 
	  done1:
	       PQclear(r);
	       octstr_destroy(a_secret);
	       if (recs)
		    gw_free(recs);
	       octstr_destroy(xurl);
	  }
     }  else  if (xmlStrcasecmp(node->name,  (void *)"LoginRequest") == 0) { /* sending a logon request. */	       
	  Octstr *pwdigest = NULL, *a_secret = NULL, *y = NULL;
	  xmlNodePtr snode = find_node(node->xmlChildrenNode, "PasswordDigest",  3);	  
	  char *sid = NATTR(node, "serviceID"), *x;
	  char *domain = sid ? strchr(sid, '@') : NULL, *xmydomain;
	  int pw_ok;
	  PGresult *r;
	  
	  /* Two possibilities:
	   * If this is a request, then we simply verify and flag this transaction as OK. And send back our own LoginRequest.
	   * If this is a response, then must have sent a login request before, so we verify and send back a loginresponse.
	   */

	  PQ_ESCAPE_STR(c, domain ? domain + 1 : "", tmp1);	       	  
	  if (snode == NULL || sid == NULL) {
	       if (sid) 
		    xmlFree(sid);
	       return NULL; /* close connection on bad input. */
	  }
	  if ((pwdigest  = _xmlNodeContent(snode)) == NULL) 
	       pwdigest = octstr_create("");
	  if ((x = NATTR(snode, "encoding")) != NULL) {
	       octstr_base64_to_binary(pwdigest);
	       xmlFree(x);
	  }

	  /* Get our secret. */
	  if (mode == Request_MODE)  {
	       fld = "b_transid";
	       PQ_ESCAPE_STR(c, trans, value);
	  } else {
	       int64_t tid = -1;
	       fld = "id";
	       sscanf(trans, "%lld", &tid); /* just to be sure... */
	       sprintf(value, "%lld", tid);
	  }
	  
	  sprintf(buf, "SELECT a_secret,id,b_secret,mydomain,ssp_domain_url FROM ssp_sessions "
		  "WHERE %s = '%.128s' AND ssp_domain = '%.128s'",
		  fld, value, tmp1);	  
	  r = PQexec(c, buf);
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) {
	       buf[0] = 0; /* prevent execution of SQL below. */
	       goto done2;
	  }
	  
	  a_secret = octstr_create(PQgetvalue(r, 0,0));
	  strncpy(mytid, PQgetvalue(r, 0, 1), sizeof mytid);	  
	  xmydomain = PQgetvalue(r, 0, 3);
	  *b_url = octstr_create(PQgetvalue(r, 0, 4));		    

	  /* we use MD5 for now XXXX */
	  y = md5(a_secret);
	  pw_ok = octstr_compare(y, pwdigest);
	  octstr_destroy(y);
	  
	  if (pw_ok != 0) { /* close connection! */
	       res = NULL;
	       sprintf(buf, "DELETE FROM ssp_sessions WHERE id = %s", mytid);
	       goto done2;
	  }
	  
	  if (mode == Request_MODE) {
	       Octstr *b_secret = octstr_create(PQgetvalue(r, 0, 2));
	       Octstr *bdigest;
	       
	       bdigest = md5(b_secret);
	       octstr_binary_to_base64(bdigest);	       
	       res = octstr_format("<LoginRequest serviceID=\"wv:@%s\" timeToLive=\"%d\">\n" 
				   "<PasswordDigest encoding=\"base64\">\n%S\n" 
				   "</PasswordDigest>\n</LoginRequest>\n",
				    xmydomain, DEFAULT_EXPIRY, bdigest);
	       *our_mode = Response_MODE;	       

	       xtid = trans; /* set transaction to the one of sender. */
	       octstr_destroy(bdigest);
	       octstr_destroy(b_secret);
	  } else {
	       res = octstr_format("<LoginResponse sessionID=\"%s@%s\" timeToLive=\"%d\">\n" 
				   "<Status code=\"200\"/>\n </LoginResponse>\n",
				   mytid, xmydomain, DEFAULT_EXPIRY);
	       xtid = mytid;
	       *our_mode = Request_MODE;	       
	  }
	  sprintf(buf, "UPDATE ssp_sessions SET pw_check_ok = true WHERE id = %s", mytid);     
     done2:
	  if (buf[0]) {
	       PGresult *r = PQexec(c, buf);
	       PQclear(r);
	  }
	  octstr_destroy(pwdigest);
	  octstr_destroy(a_secret);
	  PQclear(r);
     } else  if (xmlStrcasecmp(node->name,  (void *)"LoginResponse") == 0) { /* sending a logon request. */	       
	  xmlNodePtr snode = find_node(node->xmlChildrenNode, "Status", 3);	  
	  char *x, *xmydomain;
	  char *sid = NATTR(node, "sessionID");
	  int code;
	  PGresult *r;
	       
	  /* XXX note: We do not support redirect lists. */
	  if ((x = NATTR(snode, "code")) != NULL) {
	       code = atoi(x);
	       xmlFree(x);
	  } else 
	       code = -1;
	  
	  if (mode == Request_MODE)  {
	       fld = "b_transid";
	       PQ_ESCAPE_STR(c, trans, value);
	  } else {
	       int64_t tid = -1;
	       fld = "id";
	       sscanf(trans, "%lld", &tid); /* just to be sure... */
	       sprintf(value, "%lld", tid);
	  }
	  
	  sprintf(buf, "SELECT id, pw_check_ok,mydomain,ssp_domain_url FROM ssp_sessions WHERE %s = '%.128s'", fld, value);
	  r = PQexec(c, buf);

	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) {
	       buf[0] = 0; /* prevent execution of SQL below. */
	       goto done3;
	  }
	  
	  strncpy(mytid, PQgetvalue(r, 0, 0), sizeof mytid);	  
	  *b_url = octstr_create(PQgetvalue(r, 0, 3));		    
	  
	  if (http_status_class(code) != HTTP_STATUS_SUCCESSFUL) {
	       sprintf(buf, "DELETE FROM ssp_sessions WHERE id = %s", mytid);
	       info(0, "ssp-start trans: Logon failed, mode=%s, code=%d, trans=%s", mode==Request_MODE ? "Request" : "Response", 
		    code, trans);
	       goto done3;
	  }

	  xmydomain = PQgetvalue(r, 0, 2);
	  if ((x = PQgetvalue(r, 0, 1)) == NULL ||
	      tolower(x[0]) != 't') { /* we can't receive a login response without a verified passwd.*/
	       res = NULL;
	       sprintf(buf, "DELETE FROM ssp_sessions WHERE id = %s", mytid); /* logon failed, close connection. */
	       goto done3;
	  } 

	  if (mode == Request_MODE) {	       
	       res = octstr_format("<LoginResponse sessionID=\"%s@%s\" timeToLive=\"%d\">\n" 
				   "<Status code=\"200\"/>\n </LoginResponse>\n",
				   mytid, xmydomain, DEFAULT_EXPIRY);	       
	       xtid = trans;
	       *our_mode = Response_MODE;
	  } else 
	       res = octstr_imm(""); /* no response. We are done. */
	  PQ_ESCAPE_STR(c, xmydomain, tmp1);
	  PQ_ESCAPE_STR(c, sid, tmp2);
	  sprintf(buf, "UPDATE ssp_sessions SET ldate = current_timestamp, a_sessionid='%s@%.128s', "
		  "b_sessionid = '%.128s' WHERE  id = %s", mytid, tmp1, tmp2, mytid);	  
     done3:
	  if (buf[0]) {
	       PGresult *r = PQexec(c, buf);
	       PQclear(r);
	  }
	  PQclear(r);
	  if (sid)
	       xmlFree(sid);
     } else {
	  error(0, "ssp-start-transaction: unexpected XML node: %s", node->name);
	  res = NULL; 
     }
     
     if (xtid && xtid[0])
	  *our_transid = octstr_create(xtid);
     
     return res;
}

static int init_ssp(struct imps_conf_t *conf)
{
     int i;
     strncpy(myhostname, conf->myhostname, sizeof myhostname);
     strncpy(mydomain, conf->mydomain, sizeof mydomain);
     /* start main handler threads. */
     for (i = 0; i<conf->num_threads; i++)
	  gwthread_create((gwthread_func_t *)ssp_process, ssp_requests);
     
     return 0;
}

static void close_ssp(void)
{
     gwthread_join_every((void *)ssp_process);
}

static s2sHandler_t _ssp_handler = {
     "Imps SSP",
     init_ssp, 
     ssp_msg_send,
     close_ssp,
};

s2sHandler_t *imps_ssp_handler = &_ssp_handler; /* the handler functions. */
