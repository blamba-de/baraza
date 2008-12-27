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
#include <gwlib/gwlib.h>

#include "cspmessages.h"
#include "wbxml.h"
#include "utils.h"
#include "pgconnpool.h"
#include "cspcir.h"
#include "conf.h"
#include "json.h"
#include "baraza.h"

#define DEBUG 1

static void request_handler(List *req_list);


List *csp_requests;

void start_cspd(void)
{ 
     int i;              
     for (i = 0; i<config->num_threads; i++)
	  gwthread_create((gwthread_func_t *)request_handler, csp_requests);     
}

void stop_cspd(void)
{
     gwthread_join_every((gwthread_func_t *)request_handler);       
}

EmptyObject_t csp_handle_request(void *req_obj, int typ, RequestInfo_t *ri);
static void request_handler(List *req_list)
{
     HTTPRequest_t *r;

     while ((r = gwlist_consume(req_list)) != NULL) {
	  WV_CSP_Message_t req = NULL, resp = NULL;

	  WBXML_t wbxml = NULL;
	  xmlDocPtr xml = NULL;
	  xmlDtdPtr dtd = NULL;
	  Octstr *rbody = NULL;
	  void *start = NULL, *end;
	  int status = HTTP_OK, bin = -1;
	  Octstr *tsid; 
	  Octstr *ctype, *xmlns;
	  int n, cspver, json = 0;
	  
	  void *thandle = test_harness ? test_harness_new_request(test_logdir, r->ip, r->rh, r->body) : NULL;
	  
	  http_header_dump(r->rh);
	  if ((ctype = http_header_value(r->rh, octstr_imm("Content-Type"))) == NULL) {
	       error(0, "Missing content type in request from: %s", octstr_get_cstr(r->ip));
	       goto loop;
	  } else if (octstr_case_search(ctype, octstr_imm("wbxml"), 0) > 0) { /* order of comparions matters of course. */
	       bin = 1;
	       wbxml = parse_wbxml(r->body); /* assume highest version. */
	       start = wbxml ? wbxml->body : NULL;
	  } else if (octstr_case_search(ctype, octstr_imm("xml"), 0) > 0) { 
	       bin = 0;
	       xml = xmlParseMemory(octstr_get_cstr(r->body), octstr_len(r->body));
	       start = xml ? find_node(xml->xmlChildrenNode, "WV-CSP-Message", 3) : NULL;
	       if (xml)
		    dtd = find_dtd_node(xml->xmlChildrenNode, 3); /* find DTD node. */
	  } else if (octstr_case_search(ctype, octstr_imm("json"), 0) > 0) { 

	       debug("cspd.json", 0, "JSON request: %s",octstr_get_cstr(r->body));
	       
	       if ((req = parse_json_packet(r->body)) == NULL) {
		    error(0, "Failed to parse JSON message body, content type: %s ",
			  octstr_get_cstr(ctype));

		    goto loop;
	       }
	       bin = -1;
	       json = 1;
	  }

	  if (bin>=0) { /* only for plain-old CSP protocols. */
	       info(0, "Request from %s, blen=%ld, ctype=%s", 
		    octstr_get_cstr(r->ip), octstr_len(r->body),
		    bin ? "wbxml" : "xml");
	       
	       if (start == NULL ||
		   parse_WV_CSP_Message(start, &end, bin, (void *)&req) != 0) {
		    error(0, "Failed to parse %s message body, content type: %s dump follows: ", 
			  bin ? "wbxml" : "xml",
			  octstr_get_cstr(ctype));
		    octstr_dump(r->body,0);
		    
		    http_header_dump(r->rh);
		    goto loop;
	       }
	       
#ifdef DEBUG
	       do {
		    Octstr *t = pack_WV_CSP_Message(req, 0, NULL),
			 *t2 = xml_make_preamble(NULL, NULL, NULL);
		    Octstr *os = dump_wbxml(wbxml);
#if 0
		    info(0, "We received:\n%s%s\n", 
			 octstr_get_cstr(t2), octstr_get_cstr(t));	       
#endif
		    octstr_destroy(t);
		    octstr_destroy(t2);
		    
#if 1   
		    info(0, "Wbxml received was: %s\n", octstr_get_cstr(os)); 
#endif
		    octstr_destroy(os);
	       } while(0);
#endif
	       
	  /* Get version. */
	       xmlns = req->attributes ? dict_get(req->attributes, octstr_imm("xmlns")) : NULL;
	       cspver = csp_version(octstr_get_cstr(xmlns));	       
	  } else 
	       cspver = CSP_VERSION(1,3); /* JSON. */

	  /* this below is used for debugging purposes. */

	  if ((tsid = http_header_value(r->rh, octstr_imm("X-Baraza-Session-ID"))) != NULL ) 
	       if (req->sess && req->sess->descr && req->sess->descr) { /* change the session ID within. */
		    CSP_MSG_CLEAR_SFIELD(req->sess->descr, sessid);
		    CSP_MSG_SET_FIELD(req->sess->descr, sessid, 
				      csp_String_from_bstr(tsid, Imps_SessionID));
	       }
	  octstr_destroy(tsid);

	  /* pass through transaction content, calling relevant functions, 
	   * getting data back, building reply transaction. 
	   */

	  if (req && req->sess) {
	       RequestInfo_t _ri = {0}, *ri = &_ri;
	       Session_t sess;
	       SessionDescriptor_t sessid;
	       TransactionDescriptor_t tdescr = NULL;
	       char *sid = (req->sess->descr && req->sess->descr->sessid) ? 
		    (void *)req->sess->descr->sessid->str : NULL;
	       List *tresp = gwlist_create();
	       PGconn *c = pg_cp_get_conn(); /* acquire a connection for our transaction. */
	       int i;
	       
	       ri->ver = cspver; 
	       ri->req_ip = r->ip;
	       strncpy(ri->xsessid,  sid ? sid : "", sizeof ri->xsessid);

	       ri->c = c;
	       ri->conf = config; /* record conf data. */
	       ri->is_ssp = 0;
	       ri->binary = (json) ? 1 : bin;

	       /* Get the request IP  */
	       for (i = 0; i<NELEMS(config->ip_headers) && 
			 config->ip_headers[i][0]; i++) {
		    Octstr *x, *y = octstr_create(config->ip_headers[i]);
		    if ((x = http_header_value(r->rh, y)) != NULL) {
			 ri->client_ip = x;
			 octstr_destroy(y);
			 break;
		    } else 
			 octstr_destroy(y);
	       }

	       if (ri->client_ip == NULL && 
		   config->use_request_ip)
		    ri->client_ip = octstr_duplicate(r->ip);
	       
	       /* Get MSISDN */
	       for (i = 0; i<NELEMS(config->msisdn_headers) && 
			 config->msisdn_headers[i][0]; i++) {
		    Octstr *x, *y = octstr_create(config->msisdn_headers[i]);
		    if ((x = http_header_value(r->rh, y)) != NULL) {
			 ri->msisdn = x;
			 octstr_destroy(y);
			 break;
		    } else 
			 octstr_destroy(y);
	       }

	       
	       test_harness_log_sessid(thandle, sid);


	       /* Query the DB for the struct. */
	       if (sid == NULL || get_session_id(c, sid, ri) < 0)
		    ri->sessid = -1;

	       if (req->sess->tlist) 
		    for (i = 0, n = gwlist_len(req->sess->tlist); i < n; i++) {
			 Transaction_t t = gwlist_get(req->sess->tlist, i);
			 TransactionContent_t tc = t ? t->content : NULL;
			 char *tid = (t && t->descr && t->descr->id) ? (char *)t->descr->id->str : NULL;
			 Octstr *t_xmlns = (tc && tc->attributes) ? dict_get(tc->attributes, octstr_imm("xmlns")) : NULL;
			 EmptyObject_t tc_resp = NULL;

			 info(0, "transaction [%s], session [%s]", tid ? tid : "(EMPTY)", 
			      sid ? sid : "(EMPTY)");
			 if (tc == NULL) {
			      warning(0, "Empty TransactionContent[t=%s,s=%s] encountered, skipped!",
				      tid, sid);
			      continue;
			 }
			 
			 ri->transid = (tid && tid[0]) ? octstr_create((void *)tid) : NULL;

			 test_harness_log_req_type(thandle, tc->tc.typ);

			 if ((tc_resp = csp_handle_request(tc->tc.val, tc->tc.typ, ri)) != NULL)  {		      
			      Transaction_t rt;
			      int tc_type = tc_resp->typ;
			      char *mode = (tid && tid[0]) ? "Response" : "Request";
			      
			      tdescr =  csp_msg_new(TransactionDescriptor, NULL,
						    FV(mode, csp_String_from_cstr_ex(mode, TransactionMode)),
						    FV(id, csp_String_from_bstr(ri->transid ? ri->transid : 
										octstr_imm(""), 
										Imps_TransactionID)));
			      rt = csp_msg_new(Transaction, NULL,
					       FV(descr, tdescr),
					       FV(content, csp_msg_new(TransactionContent,
								       t_xmlns,
								       UFV(tc, tc_type, tc_resp))));		      
			      gwlist_append(tresp, rt);
			 } else 
			      info(0, "empty response from csp_handle for [%s]", csp_obj_name(tc->tc.typ));		    
			 octstr_destroy(ri->transid);
			 ri->transid = NULL; /* clear it. */
		    }
	       if (gwlist_len(tresp) > 0) { /* only return something for something. */		    
		    sessid = csp_msg_copy(req->sess->descr); /* copy session descriptor. */
		    sess = csp_msg_new(Session, NULL,
				       FV(descr, sessid),
				       FV(tlist, tresp)); 
		    /* Add Poll flag */
		    if (ri->sessid >= 0) { /* means we're logged on. */
			 int x = has_pending_msgs_ex(ri->c, ri->uid, ri->clientid, 
						     ri->conf->min_ttl, 
						     ri->conf->max_ttl, 
						     ri->sessid, ri->cir);
			 if (ri->ver > CSP_VERSION(1,1))
			      CSP_MSG_SET_FIELD(sess, poll, x);
			 else if (tdescr) /* should have been set above. */
			      CSP_MSG_SET_FIELD(tdescr, poll, x);			 
		    }
		    
		    resp = csp_msg_new(WV_CSP_Message, 
				       req->attributes ? dict_get(req->attributes, octstr_imm("xmlns")) : NULL,
				       FV(sess,sess));
	       } else {
		    gwlist_destroy(tresp, NULL);
		    resp = NULL;
	       }

	       pg_cp_return_conn(c); /* return connection. */
	       free_req_info(ri, 0);
	  }

	  if (resp) {
	       if (bin >= 0) {
		    WBXMLGen_t *z = NULL;
		    Octstr *out;	       

		    z  = (bin) ? wbxml_pack_state(wbxml->version, wbxml->publicid, wbxml->charset, cspver) : 
			 NULL; 		    
		    out = pack_WV_CSP_Message(resp, bin, z); /* make the body... */

	       /* ... then make the pre-amble. */
		    rbody = (bin) ? wbxml_make_preamble(z) : 
			 xml_make_preamble(dtd ? (char *)dtd->name : NULL, 
					   dtd ? (char *)dtd->ExternalID :NULL,
					   dtd ? (char *)dtd->SystemID : NULL);
		    if (out) 
			 octstr_append(rbody, out);
		    octstr_destroy(out);
		    wbxml_pack_state_free(z);
	       }  else 
		    rbody = make_json_packet(resp);	       
	  } else 
	       rbody = octstr_create(""); /* empty response as per CSP_Trans */
     loop:
	  info(0, "Reply being sent with %ld bytes, dump follows: ", octstr_len(rbody));
	  if (rbody) {
	       List *rh = http_create_empty_headers();


	       test_harness_log_response_packet(thandle, rbody);

	       http_header_add(rh, "Content-Type", octstr_get_cstr(ctype));
	       octstr_dump(rbody, 0);
	       http_send_reply(r->c, status, rh, rbody);
	       http_destroy_headers(rh);

#ifdef DEBUG
	       DEBUG_LOG_MSG(rbody, r->ip, NULL, "send");
	       if (bin>0) 
		    do {
			 WBXML_t x = parse_wbxml(rbody);			
			 void *y = NULL, *_r = NULL;
			 if (x) {
			      Octstr *os = dump_wbxml(x);
			      parse_WV_CSP_Message(x->body, &y, 1, &_r); 
			      Octstr *t = pack_WV_CSP_Message(_r, 0, NULL),
				   *t2 = xml_make_preamble(NULL, NULL, NULL);
#if 0
			      info(0, "We re-parsed and sent out:\n%s%s\n",
				      octstr_get_cstr(t2), octstr_get_cstr(t));	       
#endif
			      octstr_destroy(t);
			      octstr_destroy(t2);
#if 1
			      if (os)
				   info(0, "Wbxml going out:\n%s\n", octstr_get_cstr(os));	       
#endif
			      octstr_destroy(os);
			      free_wbxml(x);			      
			 }
			 csp_msg_free(_r);
		    } while (0);
#endif
	  } else 
	       http_close_client(r->c);

	  if (test_harness) 
	       test_harness_end_log(thandle);
	  octstr_destroy(rbody);
	  octstr_destroy(ctype);
	  if (xml)
	       xmlFreeDoc(xml);

	  free_wbxml(wbxml);

	  csp_msg_free(req);
	  csp_msg_free(resp);

	  /* free the struct returned. */
	  free_http_request_info(r);
     }

     info(0, "Request thread exists");
}


EmptyObject_t csp_handle_request(void *req_obj, int typ, RequestInfo_t *ri)
{
     void *res = NULL;
     Result_t rs;

     if ((ri == NULL || ri->sessid < 0) && 
	 (typ != Imps_Login_Request &&  /* these two do not require a session. */
	  typ != Imps_GetSPInfo_Request)) {
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,604), 
			   FV(descr, csp_String_from_cstr("Not logged on", 
							  Imps_Description)));
	  res = csp_msg_new(Status,NULL,
			    FV(res,rs));
     } else if (req_funcs[typ] == NULL) {
	  error(0, "unknown/unsupported request type: %d [%s] in session %s", 
		typ,  csp_obj_name(typ), ri->xsessid);
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,506), 
			   FV(descr, csp_String_from_cstr("Service not agreed", 
							  Imps_Description)));
	  res = csp_msg_new(Status,NULL,
			    FV(res,rs));
     } else 
	  res = req_funcs[typ](ri, req_obj);

     return res;
}


