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
#include <libpq-fe.h>
#include "cspim.h"
#include "cspcommon.h"
#include "pgconnpool.h"
#include "utils.h"
#include "mqueue.h"


SendMessage_Response_t handle_send_im(RequestInfo_t *ri, SendMessage_Request_t req)
{
     PGconn *c = ri->c;
     SendMessage_Response_t resp;
     MessageInfo_t info;

     int64_t uid = ri->uid, gid = -1;
     Dict *d = NULL;
     List *el = NULL, *l = NULL;
     struct QLocalUser_t *localids = NULL;
     int lcount = 0, code;     
     long validity, rcount = 0;
     time_t expiryt;
     Recipient_t tmpr;
     Result_t rs;
     struct QSender_t qs;
     Octstr *msgid = NULL, *x;
     Octstr *clientid = ri->clientid;
     char *descr, *err = NULL;
     
     if (req == NULL || 
	 req->msginfo == NULL) {
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,400), 
				 FV(descr, csp_String_from_cstr("Invalid format", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  
	  goto done;	  
     }
     
     info = req->msginfo;

     if (info && info->sender == NULL) 
	  info->sender = make_sender_struct2(ri->userid, clientid, NULL, NULL);
     else if (info && (code = verify_sender(c, &info->sender, uid, ri->userid, ri->clientid, 
					    &gid, &err)) != 200) {
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,code), 
				 FV(descr, csp_String_from_cstr(err, Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  
	  goto done;	  
     } 

     /* fix date/time */
     if (!csp_msg_field_isset(info, tdate))
	  CSP_MSG_SET_FIELD(info, tdate, time(NULL));

     /* Get the list of recipients. */
     FILL_QSENDER(qs, ri->is_ssp, uid, ri->userid, clientid);
     d = queue_split_rcpt(c, qs, info->rcpt, 0, &localids, &lcount, &el, &info->sender, ri->is_ssp);
     
     if (csp_msg_field_isset(req->msginfo, valid))
	  validity = req->msginfo->valid;
     else 
	  validity = DEFAULT_EXPIRY;
     expiryt = time(NULL) + validity;
    
     if (!ri->is_ssp || info->msgid == NULL) { /* for SSP, do not change the message ID. */
	  msgid = make_msg_id(c);
	  if (csp_msg_field_isset(info, msgid))
	       CSP_MSG_CLEAR_SFIELD(info, msgid);
	  CSP_MSG_SET_FIELD(info, msgid, csp_String_from_bstr(msgid, Imps_MessageID)); /* set the message ID. */
     } else 
	  msgid = csp_String_to_bstr(info->msgid);

     /* Send to the foreign recipients. */
     tmpr = info->rcpt;
     if (d && (l = dict_keys(d)) != NULL)
	  while ((x = gwlist_extract_first(l)) != NULL) {
	       Recipient_t r = dict_get(d, x);
	       
	       info->rcpt = r;
	       
	       /* ignore error for now?? */
	       queue_foreign_msg_add(c, req,  info->sender, 
				     uid, clientid ? octstr_get_cstr(clientid) : "", msgid, 
				     octstr_get_cstr(x), NULL, ri->ver, expiryt);
	       octstr_destroy(x);

	       rcount++; /* count number of recipients. */
	  }
     gwlist_destroy(l, NULL);
     info->rcpt = tmpr;
     
     /* send to local ones: Don't bother with rcpt  field. It will be fixed at final delivery. */
     lcount = remove_disallowed_local_recipients(c, info->sender, uid, localids, lcount, el);
     if (localids && lcount > 0) {
	  /* we queue it as a new msg structure. */
	  NewMessage_t nm = csp_msg_new(NewMessage, NULL,
					FV(minfo, csp_msg_copy(info)), 
					FV(data, csp_msg_copy(req->data)));

	  rcount += lcount;
	  queue_local_msg_add(c, nm,  info->sender, localids, lcount, 
			      req->dreport, msgid, 
			      "minfo,rcpt",
			      expiryt);
	  csp_msg_free(nm);
     }
     
     /* report errors here. */
     if (el && gwlist_len(el) > 0) {
	  code = (rcount > 0) ? 201 : 900;
	  descr = (code == 201) ? "Partial Success" : "Errors";
     }  else {
	  code = 200;
	  descr = "Success";
     }
     
     rs = csp_msg_new(Result, NULL, 
		      FV(code,code), 
		      FV(descr, csp_String_from_cstr(descr,
						     Imps_Description)),
		      FV(drlist, el));
     
     el = NULL; /* used! */

     resp = csp_msg_new(SendMessage_Response,NULL,  
			FV(res,rs),
			FV(msgid,  (code == 900) ? NULL : csp_String_from_bstr(msgid, Imps_MessageID)));	  
     
 done:

     if (localids)
	  gw_free(localids);
     gwlist_destroy(el, _csp_msg_free);
     dict_destroy(d);
     octstr_destroy(msgid);
     
     return resp;
}

Status_t handle_setd_method(RequestInfo_t *ri, SetDeliveryMethod_Request_t req)
{
     
     char cmd[512];
     PGconn *c = ri->c;
     Result_t rs;
     PGresult *r;
     char dmethod[32];
     const char *pvals[5];
     
     int64_t sid = ri->sessid;

     
     if (req->dmethod) 
	  sprintf(dmethod, ",deliver_method='%.1s' ", req->dmethod->str);
     else 
	  dmethod[0] = 0;

     pvals[0] = ri->_sessid;
     if (csp_msg_field_isset(req, gid)) { /* refers to a group. */

	  /* XXX We ignore group check since it makes no difference. Right?? */
	  
	  pvals[1] = req->gid ? (char *)req->gid->str : "";
	  r = PQexecParams(c, "DELETE FROM group_session_limits WHERE sessid = $1 AND groupid = $2", 
			   2, NULL, pvals, NULL, NULL, 0);
	  PQclear(r);
	
	  r = PQexecParams(c, "INSERT into group_session_limits (sessid, groupid) VALUES ($1, $2) RETURNING id", 
			   2, NULL, pvals, NULL, NULL, 0);			   
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1)
	       warning(0, "error setting group delivery method: %s", PQerrorMessage(c));
	  else {
	       int64_t id = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
	       char val1[100], val2[100];

	       if (csp_msg_field_isset(req, acceptlim))
		    sprintf(val1, ", push_len=%d", (int)req->acceptlim);
	       else 
		    val1[0] = 0;
	       
	       if (csp_msg_field_isset(req, gclimit))
		    sprintf(val2, ", pull_len=%d", (int)req->gclimit);
	       else 
		    val2[0] = 0;
	       
	       if (val1[0] || val2[0] || dmethod[0]) {
		    PGresult *r;
		    sprintf(cmd, "UPDATE group_session_limits SET groupid = groupid %s %s %s WHERE id = %lld", 
			    val1, val2, dmethod, id);
		    r = PQexec(c, cmd);
		    PQclear(r);		    
	       }	       
	  }
	  PQclear(r);
     } else { /* ignore whether client negotiated it. spec is full of sh*t since it should not matter. */
	  sprintf(cmd, "UPDATE sessions SET push_len = %d, caps = true %s WHERE id = %lld", (int)req->acceptlim, 
		  dmethod,
		  sid);
	  r = PQexec(c, cmd);
	  PQclear(r);
     }
     rs =  csp_msg_new(Result, NULL, 
		       FV(code,200), 
		       FV(descr, csp_String_from_cstr("Complete", Imps_Description)));	  

     return csp_msg_new(Status,NULL,  FV(res,rs));	  
}

GetMessageList_Response_t handle_get_message_list(RequestInfo_t *ri, GetMessageList_Request_t req)
{
     char cmd[512];
     PGconn *c = ri->c;
     Result_t rs;
     PGresult *r;
     int i, n, lim, has_lim;
     int64_t uid = ri->uid;
     MessageInfoList_t mlist = NULL;
     Recipient_t ru = NULL;
     GetMessageList_Response_t resp;

     if (csp_msg_field_isset(req, gid)) {       /* XXX missing support for group history. */
	  void *rs = csp_msg_new(Result, NULL, 
			   FV(code,821), 
			   FV(descr, csp_String_from_cstr("History not supported", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  
	  goto done;         
     }
     
     sprintf(cmd, "SELECT msg_data FROM csp_message_queue q WHERE msg_type = 'NewMessage' AND "
	     "EXISTS (SELECT id FROM csp_message_recipients WHERE messageid = q.id AND userid = %lld)",
	     uid);

     r = PQexec(c, cmd); 

     if (PQresultStatus(r) != PGRES_TUPLES_OK) {
	  warning(0, "getmessagelist failed: %s", PQerrorMessage(c));
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,500), 
			   FV(descr, csp_String_from_cstr("Server error", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  
	  PQclear(r);
	  goto done;
     }

     has_lim = csp_msg_field_isset(req, count);
     n = PQntuples(r);
     if (has_lim) 
	  lim = req->count;
     else 
	  lim = n;
     mlist = csp_msg_new(MessageInfoList, NULL, FV(mlist, gwlist_create()));
     
     /* make recipient structure for use in notifiction. */
     ru = make_local_rcpt_struct(c, uid, ri->clientid);
     for (i = 0; i < n && i < lim; i++) {
	  Octstr *in = get_bytea_data(r, i, 0);
	  NewMessage_t nm = NULL;
	  MessageInfo_t mi;
	  

	  if ((nm = csp_msg_from_str(in, Imps_NewMessage)) == NULL) {
	       error(0, "failed to convert newmessage struct at %s:%d", __FILE__, __LINE__);
	       goto loop;
	  }

	  /* we need to massage the recipient structure a little. */
	  mi = nm->minfo;
	  nm->minfo = NULL; /* so that it is not freed below. */
	  if (csp_msg_field_isset(mi,rcpt)) {
	       csp_msg_free(mi->rcpt);
	       mi->rcpt = csp_msg_copy(ru);
	  }
	  gwlist_append(mlist->mlist, mi);
	  
     loop:
	  octstr_destroy(in);	  
	  csp_msg_free(nm);
     }
     PQclear(r);
     
     resp = csp_msg_new(GetMessageList_Response, NULL, 
			FV(milist, mlist));
     
     if (has_lim && ri->ver>=CSP_VERSION(1,3)) 
	  CSP_MSG_SET_FIELD(resp, count, n);
     
     mlist = NULL; /* so it does not get freed */

 done:

     csp_msg_free(ru);
     csp_msg_free(mlist);

     return resp;
}


/* Send a delivery report for a message. */
static int send_dlr_for_msg(PGconn *c, int64_t msgid, int64_t orig_to, int code, char *descr)
{
     char cmd[512];
     PGresult *r;

     sprintf(cmd, "SELECT delivery_report, msg_data, msg_type,full_userid,screen_name,sender,clientid,userid "
	     " FROM csp_message_recipients_view WHERE id = %lld AND userid = %lld", 
	     msgid, orig_to);

     r = PQexec(c, cmd);
     if (PQresultStatus(r) != PGRES_TUPLES_OK) 
	  error(0, "error deleting message: %s", PQerrorMessage(c));
     else if (PQntuples(r) > 0) {	  
	  char *x = PQgetvalue(r, 0, 0);
	  Octstr *in = get_bytea_data(r, 0, 1);
	  char *t = PQgetvalue(r, 0, 2);
	  char *u = PQgetvalue(r, 0, 3);
	  char *sname = PQgetvalue(r, 0, 4);
	  char *sender = PQgetvalue(r, 0, 5);
	  char *clid = PQgetvalue(r, 0, 6);
	  int64_t xuid = strtoull(PQgetvalue(r, 0, 7), NULL, 10);
	  int type = csp_name_to_type(t); 
	  int send_dlr = _str2bool(x);
	  Octstr *y = NULL;
	  NewMessage_t msg = NULL;
	  DeliveryReport_Request_t dlr =  NULL;
	  Sender_t new_sender = NULL, orig_sender = NULL;
	  Recipient_t r  = NULL;
	  Result_t res = NULL;
	  MessageInfo_t minfo = NULL;
	  void *val = NULL;
	  List *el = NULL;
	  
	  if (type != Imps_NewMessage || 
	      !send_dlr)
	       goto done2; /* nothing to do. */
	  else if ((msg = csp_msg_from_str(in, type)) == NULL) {
	       error(0, "failed to convert newmessage struct at %s:%d", __FILE__, __LINE__);
	       goto done2;
	  }
	  
	  /* Make the new recipient. */
	  val = make_user_struct(sname, u, clid);
	  new_sender = csp_msg_new(Sender, NULL, 
				UFV(u, CSP_MSG_TYPE(val), val));
	  
	  /* Now make the recipient from original sender. */
	  orig_sender = parse_sender_str(sender);
	  r = csp_msg_new(Recipient, NULL, 
			  FV(ulist,gwlist_create()),
			  FV(glist, gwlist_create()));
	  if (orig_sender) {
	       void *val = csp_msg_copy(orig_sender->u.val);
	       List *l;
	       
	       l = (orig_sender->u.typ == Imps_User) ? r->ulist : r->glist;
	       gwlist_append(l, val);
	  } else 
	       warning(0, "failed to parse sender string from DB: %.128s", sender);
	  
	  /* Massage the msginfo structure. */
	  minfo = msg->minfo;
	  msg->minfo = NULL; /* steal it. */
	  
	  CSP_MSG_CLEAR_SFIELD(minfo, sender);
	  CSP_MSG_SET_FIELD(minfo, sender, csp_msg_copy(new_sender));
	  
	  CSP_MSG_CLEAR_SFIELD(minfo, rcpt);
	  CSP_MSG_SET_FIELD(minfo, rcpt, csp_msg_copy(r));
	  
	  res = csp_msg_new(Result,NULL, 
			    FV(code, code),
			    FV(descr, csp_String_from_cstr(descr, Imps_Description)));
	  /* Now make the delivery report. */
	  dlr = csp_msg_new(DeliveryReport_Request, NULL, 
			    FV(minfo, minfo),
			    FV(dtime, time(NULL)),
			    FV(res, res));

	  /* now send it. */
	  el = gwlist_create();
	  y = queue_msg(c, new_sender, xuid, NULL, clid, r, dlr, 			 
			&dlr->minfo->rcpt, 0, 0, NULL, time(NULL) + DEFAULT_EXPIRY, 
			0, CSP_VERSION(1,2), &el); /* don't send Rcpt struct path: we don't need it in this context. */
	  octstr_destroy(y);
	  /* we ignore errors. */
     done2:

	  octstr_destroy(in);	  
	  csp_msg_free(msg);
	  csp_msg_free(dlr);
	  csp_msg_free(r);
	  gwlist_destroy(el, _csp_msg_free);
	  csp_msg_free(orig_sender);
	  csp_msg_free(new_sender);
     }



     PQclear(r);
     return 0;
}

/* deletes a message, sends any DLR requested, returns error code. 
 * reason/reason_code are for the DLR
 */
static int delete_pending_msg(PGconn *c, int64_t rcpt_to, char *msgid, int reason_code, char *reason)
{
     char  tmp[64];
     PGresult *r;
     int code;
     char *mstatus;
     const char *pvals[5];
     
     if (reason_code == 200)
	  mstatus = "F";
     else if (reason_code == 538)
	  mstatus = "R";
     else 
	  mstatus = "S"; /* forwarded. */
     
     pvals[0] = msgid; 
     pvals[1] = mstatus;
     pvals[2] = tmp;
     
     sprintf(tmp, "%lld", rcpt_to);
     
     r  = PQexecParams(c, "UPDATE csp_message_recipients SET msg_status = $2  WHERE userid=$3 AND "
		       "messageid = (SELECT id FROM csp_message_queue WHERE msgid = $1 LIMIT 1) RETURNING "
		       " messageid, id",
		       3, NULL, pvals, NULL, NULL, 0); /* first mark it. */
     if (PQresultStatus(r) != PGRES_TUPLES_OK) {
	  error(0, "error deleting message: %s", PQerrorMessage(c));
	  code = 500;
     } else if (PQntuples(r) < 1) 
	  code = 426;
     else {
	  PGresult *r2;
	  char *xms, *xrid;
	  int64_t xmsgid;
	  int64_t rid;
	  
	  xms = PQgetvalue(r, 0, 0);
	  xrid = PQgetvalue(r, 0, 1);
	  
	  xmsgid = strtoull(xms, NULL, 10);
	  rid  = strtoull(xrid, NULL, 10);

	  send_dlr_for_msg(c, xmsgid, rcpt_to, reason_code, reason); 
	  
	  code = 200;
	  /* finally delete it */
	  pvals[0] = xrid;
	  
	  r2 = PQexecParams(c, "DELETE from csp_message_recipients WHERE id = $1" ,
			    1, NULL, pvals, NULL, NULL, 0);
	  PQclear(r2);
	  
	  /* XXX try to delete ones that are already sent... */
	  pvals[0] = xms;
	  r2 = PQexecParams(c, "DELETE FROM csp_message_queue WHERE id = $1 AND NOT "
			    " EXISTS (SELECT id FROM csp_message_recipients WHERE messageid=$1)",
			    1, NULL, pvals, NULL, NULL, 0);
	  PQclear(r2);
     }
     
     PQclear(r);

     return code;
}

Status_t handle_reject_msg(RequestInfo_t *ri, RejectMessage_Request_t req)
{
     PGconn *c = ri->c;
     MessageID_t msgid;
     int64_t uid = ri->uid;     
     int i, n;
     Result_t rs;
     List *drlist;
     int code;
     
     drlist = gwlist_create();
     for (i = 0, n = gwlist_len(req->mlist); i<n; i++) 
	  if ((msgid = gwlist_get(req->mlist, i)) != NULL) {
	       int code = delete_pending_msg(c, uid, (char *)msgid->str, 538, "Rejected");
	       
	       if (code != 200) {
		    Octstr *x = octstr_format("message: %s", (char *)msgid->str);
		    DetailedResult_t d = csp_msg_new(DetailedResult, NULL, 
						     FV(code, code),
						     FV(descr, csp_String_from_bstr(x, Imps_Description)));
		    gwlist_append(drlist, d);
		    octstr_destroy(x);		    		    
	       }	       
	  }
     code = gwlist_len(drlist) > 0 ? 201 : 200;
     rs = csp_msg_new(Result, NULL,
		      FV(code, code),
		      FV(descr, csp_String_from_cstr("Complete", Imps_Description)),
		      FV(drlist, drlist));

     return csp_msg_new(Status, NULL, FV(res, rs));
}

void fixup_rcpt_field(Recipient_t rcpt, char *sname, char *uname, char *clientid)
{
     
     void *ux = make_user_struct(sname, uname, clientid);
     char *fname = (CSP_MSG_TYPE(ux) == Imps_Group) ? "glist" : "ulist";
     int fnum = csp_get_field_num(rcpt, fname);
     
     /* clear all recipient lists. */
     gwlist_destroy(rcpt->glist, _csp_msg_free);
     gwlist_destroy(rcpt->ulist, _csp_msg_free);
     gwlist_destroy(rcpt->clist, _csp_msg_free);
	       
#if 0 /* not needed really, given the flags clearing below. */
     rcpt->glist = NULL;
     rcpt->ulist = NULL;
     rcpt->clist = NULL;
#endif
     csp_msg_unset_fieldset(rcpt, "glist", "ulist", "clist"); /* clear the flags for all. */
     
     csp_msg_set_field_value(rcpt, fnum, gwlist_create_ex(ux)); /* only set one of them. */
     
     
}
GetMessage_Response_t handle_get_msg(RequestInfo_t *ri, GetMessage_Request_t req)
{
     PGconn *c = ri->c;
     PGresult *r;
     
     GetMessage_Response_t resp;
     int type;
     char *msgid, *u, *clid, *sname;
     Octstr *data = NULL;
     NewMessage_t msg = NULL;
     const char *pvals[5];
     
     pvals[0] = msgid = req->msgid ? (char *)req->msgid->str : "";
     pvals[1] = ri->_uid;
          
     r = PQexecParams(c, "SELECT msg_data, msg_type,full_userid,screen_name,clientid "
		      " FROM csp_message_recipients_view WHERE msgid = $1 AND userid = $2", 
		      2, NULL, pvals, NULL, NULL, 0);     
     if (PQresultStatus(r) != PGRES_TUPLES_OK) {	  
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,500), 
				 FV(descr, csp_String_from_cstr("Server error", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status, NULL, FV(res, rs));
	  
	  error(0, "error fetching message: %s", PQerrorMessage(c));

	  goto done;	  	  
     } else if (PQntuples(r) < 1) {
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,426), 
				 FV(descr, csp_String_from_cstr("Not found", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status, NULL, FV(res, rs));

	  goto done;
     }

     data = get_bytea_data(r, 0, 0);
     type = csp_name_to_type(PQgetvalue(r, 0, 1));
     u = PQgetvalue(r, 0, 2);
     sname = PQgetvalue(r, 0, 3);
     clid = PQgetvalue(r, 0, 4);

     if (type != Imps_NewMessage || 
	 (msg = csp_msg_from_str(data, Imps_NewMessage)) == NULL) {
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,500), 
				 FV(descr, csp_String_from_cstr("Not found", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status, NULL, FV(res, rs));	  
	  
	  error(0, "request for queue entry  in GetMessage that is not a message: msgid: %s, message parse %s",
		msgid, msg ? "passed" : "failed");

	  goto done;
     }
     
     make_msg_data(msg->minfo, &msg->data, ri->binary);
     resp = csp_msg_new(GetMessage_Response, NULL, 
			FV(data, msg->data), 
			FV(minfo, msg->minfo)); /* steal the fields. */
     msg->data = NULL; 
     msg->minfo = NULL;

     
     /* now fix up the message info structure: change the recipient to ourselves. */
     if (resp->minfo && resp->minfo->rcpt) 
	  fixup_rcpt_field(resp->minfo->rcpt, sname, u, clid);
     
 done:
     PQclear(r);  
     csp_msg_free(msg);
     octstr_destroy(data);
     
     return resp;
}

Status_t handle_msg_delivered(RequestInfo_t *ri, MessageDelivered_t req)
{
     PGconn *c = ri->c;
     PGresult *r;
     int64_t uid = ri->uid;     
     
     Result_t rs;
     char *msgid;
     const char *pvals[5];
     
     
     pvals[0] = msgid = req->msgid ? (char *)req->msgid->str : "";
     pvals[1] = ri->_uid;
     r = PQexecParams(c, "SELECT id "
		      " FROM csp_message_recipients_view WHERE msgid = $1 AND userid = $2", 
		      2, NULL, pvals, NULL, NULL, 0);
     
     if (PQresultStatus(r) != PGRES_TUPLES_OK) {	  
	  rs = csp_msg_new(Result, NULL, 
				 FV(code,500), 
				 FV(descr, csp_String_from_cstr("Server error", Imps_Description)));	  
	  
	  error(0, "error fetching message: %s", PQerrorMessage(c));
	  PQclear(r);
	  goto done;	  	  
     } else if (PQntuples(r) < 1) {
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,426), 
			   FV(descr, csp_String_from_cstr("Not found", Imps_Description)));	  
	  PQclear(r);
	  goto done;
     }
     PQclear(r);
     
     delete_pending_msg(c, uid, msgid, 200, "Fetched"); 
     
     rs = csp_msg_new(Result, NULL,
		      FV(code, 200),
		      FV(descr, csp_String_from_cstr("Complete", Imps_Description)));

 done:

     return csp_msg_new(Status, NULL, FV(res, rs));
}

Status_t handle_fwd_msg(RequestInfo_t *ri, ForwardMessage_Request_t req)
{

     PGconn *c = ri->c;
     PGresult *r;
     int64_t uid = ri->uid;     
     Status_t resp;
     int type, code;
     char *msgid;
     Octstr *data = NULL;
     NewMessage_t msg = NULL;
     SendMessage_Request_t sm = NULL;
     SendMessage_Response_t smr = NULL;
     const char *pvals[4];
     
     pvals[0] = msgid = req->msgid ? (char *)req->msgid->str : "";
     pvals[1] = ri->_uid;
          
     r = PQexecParams(c, "SELECT msg_data, msg_type "
		      " FROM csp_message_recipients_view WHERE msgid = $1 AND userid = $2", 
		      2, NULL, pvals, NULL, NULL, 0);
     
     if (PQresultStatus(r) != PGRES_TUPLES_OK) {	  
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,500), 
				 FV(descr, csp_String_from_cstr("Server error", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status, NULL, FV(res, rs));
	  
	  error(0, "error fetching message: %s", PQerrorMessage(c));
	  PQclear(r);
	  goto done;	  	  
     } else if (PQntuples(r) < 1) {
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,426), 
				 FV(descr, csp_String_from_cstr("Not found", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status, NULL, FV(res, rs));
	  PQclear(r);
	  goto done;
     }

     data = get_bytea_data(r, 0, 0);
     type = csp_name_to_type(PQgetvalue(r, 0, 1));

     PQclear(r);
     
     if (type != Imps_NewMessage || 
	 (msg = csp_msg_from_str(data, Imps_NewMessage)) == NULL) {
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,500), 
				 FV(descr, csp_String_from_cstr("Not found", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status, NULL, FV(res, rs));	  
	  
	  error(0, "request for queue entry  in GetMessage that is not a message: msgid: %s, message parse %s",
		msgid, msg ? "passed" : "failed");
	  goto done;
     }

     /* how does user request a DLR for a forwarded message ?? */
     sm = csp_msg_new(SendMessage_Request, NULL, 
		      FV(data, msg->data), /* steal the fields. */
		      FV(msginfo, msg->minfo)); 
     msg->data = NULL; 
     msg->minfo = NULL;
     
     /* now fix up the message info structure: change the recipient to ourselves. */
     if (sm->msginfo) {
	  MessageInfo_t minfo = sm->msginfo;
	  Recipient_t r = csp_msg_copy(req->rcpt);

	  csp_msg_free(minfo->sender);
	  if (req->sender)  /* change sender if set, else remove it. */
	       CSP_MSG_SET_FIELD(minfo, sender, csp_msg_copy(req->sender)); 
	  else 
	       CSP_MSG_SET_FIELD(minfo, sender, make_sender_struct(c, uid, NULL, NULL, NULL));
	  
	  if (csp_msg_field_isset(sm->msginfo, rcpt))
	       CSP_MSG_CLEAR_SFIELD(sm->msginfo, rcpt); /* clear this one. */
	  CSP_MSG_SET_FIELD(sm->msginfo, rcpt, r); 	  
     }     
     smr = handle_send_im(ri, sm);
     
     if (CSP_MSG_TYPE(smr) == Imps_SendMessage_Response) {
	  if (smr->res)
	       code = smr->res->code;
	  else 
	       code = 500;
	  if (ri->ver>=CSP_VERSION(1,3) && csp_msg_field_isset(smr,msgid)) 
	       resp = (void *)csp_msg_new(ForwardMessage_Response, NULL,
					  FV(msgid, csp_msg_copy(smr->msgid)));
	  else 
	       resp = csp_msg_new(Status, NULL,
				  FV(res, csp_msg_copy(smr->res)));	  
     } else {
	  Status_t xsmr = (void *)smr;
	  resp = csp_msg_copy(xsmr); /* status message. */
	  code = (xsmr->res) ? xsmr->res->code : 500;
     }
     
     if (CSP_SUCCESS(code))
	  delete_pending_msg(c, uid, msgid, 541, "Forwarded"); 
 done:

     csp_msg_free(msg);
     csp_msg_free(sm);
     csp_msg_free(smr);
     octstr_destroy(data);
     
     return resp;

}


/* Block list handling: if add = 1 means add, else delete from list 
 * allow = 1 means grant, else block
 */
static void modify_access_list(PGconn *c, int64_t uid, const char *field1, char *value1, 
			       const char *field2, char *value2, 
			       int allow,
			       int add)
{
     char cmd[512];
     PGresult *r;
     const char *pvals[10];

     pvals[0] = value1;
     pvals[2] = value2;
          
     if (add) {
	  sprintf(cmd, "DELETE FROM access_lists WHERE owner=%lld AND %s=$1 AND %s=$2 and allow=%s; ",
		  uid, field1, field2, allow ? "true" : "false");
	  r = PQexecParams(c, cmd, 2, NULL, pvals, NULL, NULL, 0);
	  PQclear(r);
	  
	  sprintf(cmd, "INSERT INTO access_lists (owner, allow, %s, %s) VALUES "
		  "(%lld, %s, $1, $2) ",
		  field1, field2, uid, allow ? "true" : "false");
     } else 
	  sprintf(cmd, "DELETE FROM access_lists WHERE owner=%lld AND %s = $1 AND "
		  " %s = $2 AND "
		  "allow = %s",
		  uid, field1,  field2,
		  allow ? "true" : "false");

     r = PQexecParams(c, cmd, 2, NULL, pvals, NULL, NULL, 0);
     
     PQclear(r);          
}

/* handle screen names. */
static void modify_screen_name_acls(PGconn *c, int64_t uid, List *snames, int allow, int add, List *el)
{
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     ScreenName_t s;
     int i;

     for (i = 0; i<gwlist_len(snames); i++) 
	  if ((s = gwlist_get(snames, i)) != NULL) {
	       char *sname = s->sname ? (char *)s->sname->str : "";
	       char *gid  = s->gid ? (char *)s->gid->str : "";
	       int64_t xgid;
	       int islocal;
	       
	       extract_id_and_domain(gid, xid, xdomain);	       

	       xgid = get_groupid(c, xid, xdomain, &islocal);
	       if (xgid < 0 && islocal) {
		    Octstr *err = octstr_format("invalid group: %.128s", gid);
		    DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
						      FV(code,800),
						      FV(descr, 
							 csp_String_from_bstr(err, 
									      Imps_Description)));
		    gwlist_append(el, dr);
		    continue;
	       }
	       
	       modify_access_list(c, uid, "screen_name", sname, "group_id", gid, 
				  allow, add);
	  }          

}


static void modify_group_acls(PGconn *c, int64_t uid, List *grps, int allow, int add, List *el)
{
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     GroupID_t gid;
     int i;
     
     for (i = 0; i<gwlist_len(grps); i++) 
	  if ((gid = gwlist_get(grps, i)) != NULL) {
	       int64_t xgid;
	       int islocal;
	       
	       extract_id_and_domain((char *)gid->str, xid, xdomain);	       
	       xgid = get_groupid(c, xid, xdomain, &islocal);
	       if (xgid < 0 && islocal) {
		    Octstr *err = octstr_format("invalid group: %.128s", (char *)gid->str);
		    DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
						      FV(code,800),
						      FV(descr, 
							 csp_String_from_bstr(err, 
									      Imps_Description)));
		    gwlist_append(el, dr);
		    continue;
	       }
	       modify_access_list(c, uid, "group_id", (char *)gid->str, 
				  "foreign_userid", "", 
				  allow, add);      
	  }
}

static void modify_userid_acls(PGconn *c, int64_t uid, List *userids, int allow, int add, List *el)
{
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN], buf[64];
     UserID_t u;
     int i;
     char *field;
     char *val;
     
     for (i = 0; i<gwlist_len(userids); i++) 
	  if ((u = gwlist_get(userids, i)) != NULL) {
	       /* check if user is local. */
	       char *user = (char *)u->str;
	       int islocal;
	       int64_t xuid;
	       
	       extract_id_and_domain(user, xid, xdomain);

	       xuid = get_userid(c, xid, xdomain, &islocal);	       
	       if (xuid < 0 && islocal) {
		    Octstr *err = octstr_format("invalid userid: %.128s", user);
		    DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
						      FV(code,531),
						      FV(descr, 
							 csp_String_from_bstr(err, 
									      Imps_Description)));
		    gwlist_append(el, dr);
		    continue;
	       } else if (!islocal) { /* foreign user */
		    field = "foreign_userid";
		    val = user;
	       } else {
		    field = "local_userid";
		    sprintf(buf, "%lld", xuid);
		    val = buf;
	       }
	       modify_access_list(c, uid, field, val, "application_id", "", 
				  allow, add);          
	  }
}

static void modify_appid_acls(PGconn *c, int64_t uid, List *apps, int allow, int add, List *el)
{
     ApplicationID_t app;
     int i;
     
     for (i = 0; i<gwlist_len(apps); i++) 
	  if ((app = gwlist_get(apps, i)) != NULL)
	       modify_access_list(c, uid, "application_id", (char *)app->str, "screen_name", "", 
				  allow, add);     
}


/* for a single contact list. */
static void modify_single_clist_acls(PGconn *c, int64_t uid, char *clist, int allow, int add, List *el)
{
     
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN], buf[512];
     int64_t cid;
     int islocal, i, n;
     PGresult *r;

     extract_id_and_domain(clist, xid, xdomain);
          
     /* not too efficient */
     sprintf(buf, "userid=%lld", uid);
     cid = get_contactlist(c, xid, xdomain, buf, &islocal);

     if (cid < 0) {
	  Octstr *err = octstr_format("invalid contactlist: %.128s", clist);
	  DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
					    FV(code,700),
					    FV(descr, 
					       csp_String_from_bstr(err, 
								    Imps_Description)));
	  gwlist_append(el, dr);
	  
	  return;
     }

     /* Get the members. */
     sprintf(buf, "SELECT local_userid, foreign_userid FROM contactlist_members WHERE cid = %lld", 
	     cid);

     r = PQexec(c, buf);
     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
     for (i = 0; i<n; i++) {
	  char *lu = PQgetvalue(r, i, 0);
	  char *fu = PQgetvalue(r, i, 1);
	  char *field, *value;
	  
	  if (PQgetisnull(r, i, 0) == 0) { /* local user. */
	       field = "local_userid";
	       value = lu;	       
	  } else {
	       field = "foreign_userid";
	       value = fu;
	  }
	  modify_access_list(c, uid, field, value, "application_id", "", 
			     allow, add);          
     }
     PQclear(r);
}

static void modify_clist_acls(PGconn *c, int64_t uid, List *clist, int allow, int add, List *el)
{
     ContactList_t cl;
     int i;
     for (i = 0; i<gwlist_len(clist); i++) 
	  if ((cl = gwlist_get(clist, i)) != NULL) 
	       modify_single_clist_acls(c, uid, (char *)cl->str, allow, add, el);
     
}

static void process_acl_entity(PGconn *c, int64_t uid, EntityList_t e,  int allow, 
			       List *el)
{
     if (e == NULL)
	  return;
     
     modify_screen_name_acls(c, uid, e->snames, allow, 1, el);
     modify_group_acls(c, uid, e->gids, allow, 1, el);
     modify_userid_acls(c, uid, e->users, allow, 1, el);
     modify_appid_acls(c, uid, e->appids, allow, 1, el);
     modify_clist_acls(c, uid, e->clist, allow, 1, el);
     
}

static void process_acl_add_remove(PGconn *c, int64_t uid, AList_Union_t al, int allow, 
				   List *el)
{
     if (al == NULL)
	  return;
     
     if (al->alist) {
	  AddList_t e = al->alist;
	  modify_screen_name_acls(c, uid, e->snames, allow, 1, el);
	  modify_group_acls(c, uid, e->gids, allow, 1, el);
	  modify_userid_acls(c, uid, e->users, allow, 1, el);
	  modify_appid_acls(c, uid, e->appids, allow, 1, el);
	  modify_clist_acls(c, uid, e->clist, allow, 1, el);
     }
     if (al->rlist) {
	  RemoveList_t e = al->rlist;
	  modify_screen_name_acls(c, uid, e->snames, allow, 0, el);
	  modify_group_acls(c, uid, e->gids, allow, 0, el);
	  modify_userid_acls(c, uid, e->users, allow, 0, el);
	  modify_appid_acls(c, uid, e->appids, allow, 0, el);
	  modify_clist_acls(c, uid, e->clist, allow, 0, el);
     }

}

Status_t handle_block_entity_req(RequestInfo_t *ri, BlockEntity_Request_t req)
{
     PGconn *c = ri->c;     
     int code;
     int64_t uid = ri->uid;
     Result_t rs;
     List *drlist = gwlist_create();
     int has_grant_inuse = 0, has_block_inuse = 0;
     

     has_block_inuse = csp_msg_field_isset(req,blist_inuse) || 
	  (req->blist && csp_msg_field_isset(req->blist, inuse));
     has_grant_inuse = csp_msg_field_isset(req, glist_inuse) || 
	  (req->glist && csp_msg_field_isset(req->glist, inuse));
     
     if (req->blist) {
	  if (req->blist->blist.typ == Imps_EntityList)
	       process_acl_entity(c, uid, req->blist->blist.val,  0, drlist);
	  else 
	       process_acl_add_remove(c, uid, req->blist->blist.val,  0, drlist);	      
     }
     
     if (req->glist) {
	  if (req->glist->glist.typ == Imps_EntityList)
	       process_acl_entity(c, uid, req->glist->glist.val,  1, drlist);
	  else 
	       process_acl_add_remove(c, uid, req->glist->glist.val,  1, drlist);	      
     }

     if (has_grant_inuse || has_block_inuse) {
	  char cond1[100], cond2[100];
	  char cmd[512];
	  PGresult *r;
	  
	  int g = req->glist_inuse || 
	       (req->glist && req->glist->inuse);
	  int b = req->blist_inuse || 
	       (req->blist && req->blist->inuse);
	  
	  if (has_grant_inuse)
	       sprintf(cond1, ", grant_list_in_use = %s",
		       g ? "true" : "false");
	  else 
	       cond1[0] = 0;
	  if (has_block_inuse)
	       sprintf(cond2, ", block_list_in_use = %s",
		       b ? "true" : "false");
	  else 
	       cond2[0] = 0;
	  sprintf(cmd, "UPDATE users SET lastt=current_timestamp %s %s WHERE id = %lld", 
		  cond1, cond2, uid);
	  r = PQexec(c, cmd);
	  PQclear(r);		       
     }
          /* report errors here. */
     if (gwlist_len(drlist) > 0) 
	  code = 201;
     else 
	  code = 200;
     
     rs = csp_msg_new(Result, NULL, 
		      FV(code,code), 
		      FV(descr, csp_String_from_cstr(code == 200 ? "Success" : "Partial Success",
						     Imps_Description)),
		      FV(drlist, drlist));
     drlist = NULL;
     
     gwlist_destroy(drlist, _csp_msg_free);

     return csp_msg_new(Status, NULL, FV(res, rs));
}


static EntityList_t get_acls_list(PGconn *c, int64_t uid, int allow)
{
     int i, n;
     char cmd[512];
     PGresult *r;
     EntityList_t e = NULL;
     sprintf(cmd , "SELECT full_userid, screen_name,group_id, application_id "
	     " FROM access_lists_view WHERE owner = %lld AND allow = %s",
	     uid, allow ? "true" : "false");
     r = PQexec(c, cmd);

     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;

     if (n > 0) {
	  e = csp_msg_new(EntityList, NULL,
			  FV(users, gwlist_create()),
			  FV(snames, gwlist_create()),
			  FV(gids, gwlist_create()),
			  FV(clist, gwlist_create()),
		     FV(appids, gwlist_create()));
	  
	  for (i = 0; i<n; i++) {
	       char *fu = PQgetvalue(r, i, 0);
	       char *su = PQgetvalue(r, i, 1);
	       char *gu = PQgetvalue(r, i, 2);
	       char *au = PQgetvalue(r, i, 3);
	       
	       if (fu && fu[0]) {	       
		    UserID_t x = csp_String_from_cstr(fu, Imps_UserID);
		    gwlist_append(e->users, x);
	       } else if (su && su[0]) {
		    Octstr *x = format_screen_name_ex(gu, su);
		    ScreenName_t s = parse_screen_name(octstr_get_cstr(x));
		    
		    gwlist_append(e->snames, s);
		    octstr_destroy(x);
	       } else if (gu && gu[0]) {
		    GroupID_t x = csp_String_from_cstr(gu, Imps_GroupID);
		    gwlist_append(e->gids, x);
	       } else if (au && au[0]) {
		    ApplicationID_t x = csp_String_from_cstr(au, Imps_ApplicationID);
		    gwlist_append(e->appids, x);
	       }	  
	  }
     }
     PQclear(r);
     
     return e;
}

GetBlockedList_Response_t handle_get_block_list(RequestInfo_t *ri, void *unused)
{
     PGconn *c = ri->c;     
     int64_t uid = ri->uid;
     int has_grant_inuse = 0, has_block_inuse = 0;
     GetBlockedList_Response_t resp;

     BlockList_t b;     
     GrantList_t g;
     
     check_csp_grant_block_in_use(c, uid, &has_grant_inuse, &has_block_inuse);
     
     resp = csp_msg_new(GetBlockedList_Response,NULL, NULL);
     /* start with the block list */
     b = csp_msg_new(BlockList, NULL,
		     UFV(blist, Imps_EntityList, get_acls_list(c, uid, 0)));
     if (ri->ver<CSP_VERSION(1,3))
	  CSP_MSG_SET_FIELD(b,inuse,has_block_inuse);
     else 
	  CSP_MSG_SET_FIELD(resp, blist_inuse,has_block_inuse);
     CSP_MSG_SET_FIELD(resp, blist, b);

     /* ... then accept. */
     g = csp_msg_new(GrantList, NULL,
		     UFV(glist, Imps_EntityList, get_acls_list(c, uid, 1)));
     if (ri->ver<CSP_VERSION(1,3))
	  CSP_MSG_SET_FIELD(g,inuse,has_grant_inuse);
     else 
	  CSP_MSG_SET_FIELD(resp, glist_inuse,has_grant_inuse);
     CSP_MSG_SET_FIELD(resp, glist, g);
     
     return resp;
}
