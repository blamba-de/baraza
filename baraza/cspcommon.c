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
#include <string.h>
#include <gwlib/gwlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libpq-fe.h>
#include "cspcommon.h"
#include "csppresence.h"
#include "cspgroup.h"
#include "cspim.h"
#include "pgconnpool.h"
#include "utils.h"
#include "mqueue.h"
#include "conf.h"

#define KeepAliveTime DEFAULT_POLL_MIN


static Functions_t handle_funcs_request(Functions_t req, int ver, int *dflt_notify);

static void *handle_capabilitylist(PGconn *c, CapabilityList_t cl, RequestInfo_t *ri, int *utype); 



/* makes a new session, or re-establishes existing session. */
static Octstr *make_sess(PGconn *c, char *oldsess, char *user, char *domain, 
			 ClientID_t clnt, ApplicationID_t appid, 
			 char *cookie,
			 char **err, int *code, int64_t *xuid, int64_t *xsid, char *orig_msisdn,
			 int csp_version)
{
     PGresult *r;
     u_int64_t uid = 0;
     char cmd[512], tmp1[128], tmp2[128], msisdn[64], tmp3[128];
     Octstr *clid = NULL, *sess = NULL;
     /* Get the uid. */

     sprintf(cmd, "SELECT id,phone FROM users WHERE userid='%.128s' AND domain = '%.128s'", user, domain);
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
	  error(0, "user [%s at %s] disappeared ??", user, domain);
	  msisdn[0] = 0;
     } else {
	  uid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
	  strncpy(msisdn, PQgetvalue(r, 0, 1), sizeof msisdn);
     }
     PQclear(r);

     *xuid = uid;
     *xsid = -1;
     /* First make a clientID of sorts. */
     clid = make_clientid(clnt, appid);

     PQ_ESCAPE_STR(c, octstr_get_cstr(clid), tmp1);
     if (oldsess) { /* then check that it exists and that client id matches. */
	  PQ_ESCAPE_STR(c, oldsess,tmp2);
	  sprintf(cmd, "SELECT id FROM sessions WHERE sessionid = '%.128s' AND userid = %lld AND clientid = '%.128s';",
		  tmp2, uid, tmp1);
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || 
	      PQntuples(r) < 1) {
	       *err = "SessionID ClientID mismatch";
	       *code = 422;
	  } else 
	       sess = octstr_create(oldsess);
	  PQclear(r);
     } else {
	  PQ_ESCAPE_STR(c, cookie, tmp2);
	  PQ_ESCAPE_STR(c, orig_msisdn ? orig_msisdn : msisdn, tmp3);
	  sprintf(cmd, "INSERT INTO sessions (userid, clientid, cookie,msisdn,csp_version) VALUES "
		  " (%lld, '%.128s', '%.128s', '%.128s', '%d.%d') RETURNING id", uid,tmp1, tmp2,
		  msisdn[0] ? tmp3 : "",
		  CSP_MAJOR_VERSION(csp_version), CSP_MINOR_VERSION(csp_version));
	  r = PQexec(c, cmd);

	  if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	       u_int64_t sid = strtoull(PQgetvalue(r, 0,0), NULL, 10);
	       
	       *xsid = sid;
	       PQclear(r);
	       sprintf(cmd, "UPDATE sessions SET sessionid =  upper(md5(current_timestamp::text)) || '%lldG' "
		       "WHERE id = %lld RETURNING sessionid",
		       sid, sid);
	       r = PQexec(c, cmd);
	       if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
		    char *s = PQgetvalue(r, 0, 0);
		    sess = octstr_create(s);
	       }
	  }

	  PQclear(r);
     }
     octstr_destroy(clid);
     return sess;
}

static Octstr *make_nonce(char salt[], char cookie[], char user[])
{
     Octstr *s = octstr_format("%s %s %s", salt, cookie, user);
     Octstr *x = md5digest(s);

     octstr_destroy(s);
     return x;
}

static int check_user(char user[], int lim)
{
     char *p = user;
     int ch;
     while (p - user < lim && 
	    (ch = *p++) != '\0')
	  if (ch == '/' ||
	      ch == '~' || /* and others... */
	      ch == '<' ||
	      ch == '>' ||
	      ch == '@'
	       ) return 0;
     return 1;
}
Login_Response_t handle_login(RequestInfo_t *ri, Login_Request_t req)
{
     char *user = req->user ? csp_String_to_cstr(req->user) : NULL;
     char xuser[DEFAULT_BUF_LEN] = {0}, xdomain[DEFAULT_BUF_LEN] = {0};
     char *pass = req->pwd ? (char *)req->pwd->str : NULL;
     char *digest = req->digest ? (char *)req->digest->str : NULL;
     char tmp1[128], tmp2[256],cmd[512];
     List *schemas = req->dschema;
     DigestSchema_t rschema = NULL;
     Functions_t fns = NULL;
     Nonce_t nonce = NULL;
     Result_t rs;
     Login_Response_t res = NULL;
     int code = 200;
     char *err = "";
     PGconn *c = ri->c;
     PGresult *r;
     int log_success = 0, cap_req = 0;
     SessionID_t *newsess = NULL;
     AgreedCapabilityList_t caplist = NULL;
     int has_user, auto_regd = 0;
     
     if (user == NULL) {
	  error(0, "missing userid n login request");
	  code = 531;
	  err = "missing user";
	  goto done;
     } 
     
     extract_id_and_domain(user, xuser, xdomain);
     if (xdomain[0] == 0) /* default to current domain. */
	  strncpy(xdomain, ri->conf->mydomain, sizeof xdomain);
     
     PQ_ESCAPE_STR_LOWER(c, xuser, tmp1);
     PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
     
     if (pass || digest) { /* we have a password or digest proceed. */
	  int islocal = 0; 
	  char xpass[128] = {0};
	  char *type = pass ? "plain" : "md5";
	  
	  if (pass) 
	       PQ_ESCAPE_STR(c, pass, xpass);
	  else { /* digest more complicated. */
	       Octstr *s = octstr_create(digest);
	       octstr_base64_to_binary(s);
	       octstr_binary_to_hex(s, 0);
	       /* Hex does not need to be escaped. */
	       strncpy(xpass, octstr_get_cstr(s), sizeof xpass);
	       octstr_destroy(s);
	  }
	  code = 531; /* defaults to go-away! */
	  err = "no such user";
	  if (get_userid(c, tmp1, tmp2, &islocal) < 0 && islocal && 
	      ri->conf->auto_reg && check_user(xuser, sizeof xuser)) { /* handle autoregistration. */	       
	       if (pass)
		    sprintf(cmd, "SELECT new_user('%s', '%s', '%.128s',true)", 
			    tmp1, xpass,  tmp2);
	       else {
		    Octstr *xnonce = make_nonce(ri->conf->nonce_salt,
						req->cookie ? csp_String_to_cstr(req->cookie) : "x", user);	       
		    
		    sprintf(cmd, "SELECT new_user_md5('%s', '%s', '%.128s', '%.128s',true)", 
			    tmp1, tmp2, octstr_get_cstr(xnonce), xpass);			 
		    octstr_destroy(xnonce);
	       }
	       r = PQexec(c, cmd);
	       code = (PQresultStatus(r) == PGRES_TUPLES_OK) ? 200 : 500; 
	       err = (code == 200) ? "Success" : "Auto-registration failed!";
	       PQclear(r);	  
	       auto_regd = (code == 200); /* flag that we've auto registered */
	  }  else if (islocal) { /* the user is local, and is trying to authenticate. */
	       sprintf(cmd, "SELECT verify_%s_pass('%s', '%s', '%.128s')", type, tmp1, tmp2, xpass);
	       r = PQexec(c, cmd);	 
	       
	       if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r)  > 0) { /* we got a result. */
		    char *s = PQgetvalue(r, 0, 0);
		    code = _str2bool(s) ? 200 : 409;
		    err  = (code == 200) ? "Success" : "Invalid password";
	       }  
	       PQclear(r);
	  }  else if (!islocal)
	       err = "Domain not supported here";
	  log_success =  (code == 200);	  
     } else if (schemas) { /* we won't even look at them. If passed, we only support MD5. */
	  
	  sprintf(cmd, "SELECT nonce FROM users where userid = '%.128s' AND domain  = '%.128s'",
		  tmp1, tmp2);
	  r = PQexec(c, cmd);
	  has_user = (PQresultStatus(r) == PGRES_TUPLES_OK) &&  (PQntuples(r) >= 1);
	  if (has_user || ri->conf->auto_reg) { /* auto-reg is allowed. */
	       Octstr *xnonce = has_user ? NULL : make_nonce(ri->conf->nonce_salt,
							     req->cookie ? csp_String_to_cstr(req->cookie) : "x", user);
	       char *s = has_user ? PQgetvalue(r, 0, 0) : octstr_get_cstr(xnonce);
	       code = 200;
	       err = "Send Digest Please";
	       rschema = (void *)csp_String_from_cstr("MD5", Imps_DigestSchema);
	       nonce = (void *)csp_String_from_cstr(s, Imps_Nonce);
	       
	       octstr_destroy(xnonce);
	  } else {
	       code = 531;
	       err = "no such user";
	  }
	  PQclear(r);	  
     }
     
     /* XXX at this point, for registration we'll give you a system message list. */

     if (log_success) { /* make a new session, or re-establish one that is existent. */
	  int64_t uid = -1, xsid = -1;
	  char *cookie = req->cookie ? (void *)req->cookie->str : "";
	  char *oldsess = req->sessid ? (void *)req->sessid->str : NULL;
	  char *xmsisdn = req->client && req->client->msisdn ?
	    csp_String_to_cstr(req->client->msisdn) : NULL;
	  Octstr *s = make_sess(c, oldsess, tmp1, tmp2, req->client, req->appid, cookie,
				&err, &code, &uid, &xsid, xmsisdn, ri->ver);
	  Octstr *clid = make_clientid(req->client, req->appid);
	  
	  ri->uid = uid; /* set new UID and session id */
	  ri->sessid = xsid;
	  strncpy(ri->xsessid, s ? octstr_get_cstr(s) : "", sizeof ri->xsessid);
	  if (ri->clientid) 
	       octstr_destroy(ri->clientid);
	  ri->clientid = octstr_duplicate(clid);
	  if (s) {
	       int utype, dflt_notify;	       
	       newsess = (void *)csp_String_from_bstr(s, Imps_SessionID);
	       if (req->fns) 
		    fns = handle_funcs_request(req->fns, ri->ver, &dflt_notify);
	       if (req->caps && ri->ver >= CSP_VERSION(1,3)) /* only allowed for v1.3 and above. */
		    caplist = handle_capabilitylist(ri->c, req->caps, ri, &utype);
	       
	       update_session_notify(c,ri->sessid,dflt_notify);
	       octstr_destroy(s);
	  } 
	  
	  cap_req = (code == 200) && (caplist == NULL); /* capability request only if not yet done. */
	  log_success = (code == 200); /* reset log_success. */
	  	  
	  octstr_destroy(clid);

	  if (log_success) { /* update presence */
	       ClientID_t clnt = NULL;
	       ApplicationID_t appid = NULL;
	       OnlineStatus_t os;
	       PresenceSubList_t p;
	       ClientInfo_t cinfo = csp_msg_new(ClientInfo, NULL,
						FV(qual, 1),
						FV(ctype, csp_String_from_cstr("MOBILE_PHONE", Imps_ClientType)));	       
	       Status_t xcstatus = csp_msg_new(Status, NULL, FV(_content, octstr_imm("OPEN")));
	       CommC_t cc = csp_msg_new(CommC, NULL,
					FV(cap, csp_String_from_cstr("IM", Imps_Cap)),
					FV(status, xcstatus),
					FV(contact, csp_String_from_cstr(user, Imps_Contact)),
					FV(note, csp_String_from_cstr("IM online", Imps_Note)));
	       CommCap_t ccp;

	       parse_clientid(ri->clientid, &clnt, &appid);

	       ccp = csp_msg_new(CommCap, NULL, /* version 1 seems to want comcap. */
				 FV(commc, gwlist_create_ex(cc)),
				 FV(qual, 1),
				 FV(client, clnt ? csp_msg_copy(clnt) : NULL));
	       os = csp_msg_new(OnlineStatus, NULL,
				FV(qual, 1),
				FV(pvalue, csp_String_from_cstr("T", 
								Imps_PresenceValue)),
				FV(client, clnt));
	       
	       p = csp_msg_new(PresenceSubList, NULL, 
			       FV(ostatus, gwlist_create_ex(os)),
			       FV(cinfo, gwlist_create_ex(cinfo)),
			       FV(commcap, gwlist_create_ex(ccp)));
	       update_pres_info(ri->c, p, xsid, uid, PRES_FROM_SERVER);
	       
	       csp_msg_free(p);
	       csp_msg_free(appid);
	  }
     } else 
	  ri->sessid = -1; /* not yet logged on, kill sessid if any. */     
     
 done:
     
     rs = csp_msg_new(Result, NULL, 
		     FV(code,code), 
		     FV(descr, csp_String_from_cstr(err, Imps_Description)));
     
     res = csp_msg_new(Login_Response, NULL,
		       FV(client, csp_msg_copy(req->client)),		       
		       FV(res,rs),
		       FV(nonce,nonce), /* may or may not be set. */
		       FV(dschema, rschema),
		       FV(sessid, newsess),
		       FV(alivet, ri->conf->min_ttl),
		       FV(capreq, cap_req),
		       FV(fns, fns),
		       FV(caplist, caplist));

     /* we need to clear some flags. */
     if (!log_success) {
	  csp_msg_unset_fieldset(res, "alivet");
	  csp_msg_unset_fieldset(res, "capreq");
     }
#if 0 /* ..null structures and will be skipped anyway. */
     if (newsess == NULL)
	  csp_msg_unset_fieldset(res, "sessid");
     if (nonce == NULL)
	  csp_msg_unset_fieldset(res, "nonce");
#endif

     return res;
}

void *handle_noop(RequestInfo_t *ri, void *unsed)
{

  return NULL;
}

KeepAlive_Response_t handle_keepalive(RequestInfo_t *ri, KeepAlive_Request_t req)
{
     int setit = 0;
     char cmd[512];
     KeepAlive_Response_t resp;
     PGresult *r;
     long ttl;

     if (!csp_msg_field_isset(req, ttl))
	  ttl = ri->conf->min_ttl;
     else 
	  ttl = req->ttl;

     if (ttl > ri->conf->max_ttl) {
	  ttl =  ri->conf->max_ttl;
	  setit = 1;
     } else if (ttl < ri->ttl) {
	  ttl = ri->ttl;
	  setit = 1;
     }
     
     
     if (ri->cir) { /* CIR clients need not send keep alive often. */
	  ttl = ri->conf->max_ttl;
	  setit = 1;
     }

     sprintf(cmd, "UPDATE sessions SET ttl = %ld WHERE id = %lld", ttl, ri->sessid);
     
     r =  PQexec(ri->c, cmd);
     PQclear(r);
     
     resp = csp_msg_new(KeepAlive_Response, NULL, 
			FV(res, csp_msg_new(Result, NULL, 
					    FV(code, 200))));     
     if (setit)
	  CSP_MSG_SET_FIELD(resp, ttl, ttl);
     return resp;
}

void *handle_logout(RequestInfo_t *ri, void *unused)
{

     PGconn *c = ri->c;
     PGresult *r;
     char cmd[512];
     Result_t rs;
     
     ClientID_t clnt = NULL;
     ApplicationID_t appid = NULL;
     OnlineStatus_t os;
     PresenceSubList_t p;


/* Delete the session. */     
     sprintf(cmd, "DELETE FROM sessions WHERE id  = %lld "
#ifdef DEBUG
	     " AND id <> 1 " /* special one we do not touch */
#endif
	     "RETURNING id", ri->sessid);

     r = PQexec(c, cmd);

     if (PQresultStatus(r) == PGRES_TUPLES_OK && 
	 PQntuples(r) > 0) {
	  
	  /* Leave any groups joined. */
	  leave_all_groups(c, ri->uid, ri->clientid, ri->ver, 824, 0);	  	  
     }
     PQclear(r); 
     
     /* Then the world we've logging out. */

     parse_clientid(ri->clientid, &clnt, &appid);
     os = csp_msg_new(OnlineStatus, NULL,
		      FV(qual, 1),
		      FV(pvalue, csp_String_from_cstr("F", 
						      Imps_PresenceValue)),
		      FV(client, clnt));

     p = csp_msg_new(PresenceSubList, NULL, 
		     FV(ostatus, gwlist_create_ex(os)));
     update_pres_info(ri->c, p, ri->sessid, ri->uid, PRES_FROM_SERVER);

     csp_msg_free(p);
     csp_msg_free(appid);
     
     rs  = csp_msg_new(Result, NULL, 
		       FV(code,200), 
		       FV(descr, csp_String_from_cstr("Ok", Imps_Description)));	  
	 
     return (ri->ver > CSP_VERSION(1,1)) ? 
	  (void *)csp_msg_new(Status, NULL, FV(res,rs)) :
	  csp_msg_new(Disconnect, NULL, FV(res, rs));     
}

/* First we need some helper functions for service handling. */

/* if a feature was requested (either parent was requested or it was requested) but is not supported, set that field
 * to true in the inverted tree. 
 */

#define ClearField(_obj,_fld) CSP_MSG_CLEAR_FIELD(_obj, _fld)
#define ClearSField(_obj,_fld) CSP_MSG_CLEAR_SFIELD(_obj, _fld)


#define FeatSupported(preq,_obj,_feat) if (preq || (_obj)->_feat) do {csp_msg_unset_fieldset(_obj, #_feat); } while (0)
#define FeatNotSupported(preq, _obj,_feat) if (preq || (_obj)->_feat) do {(_obj)->_feat = 1; csp_msg_set_fieldset(_obj, #_feat); } while (0)

// for testing, we use the one below!
// #define FeatNotSupported(p,o,f) FeatSupported(p,o,f)

#define CullSubTree(_obj, _field) do {csp_msg_free((_obj)->_field); (_obj)->_field = NULL; csp_msg_unset_fieldset(_obj, #_field); } while (0)
/* the following functions take a sub-tree of requested functions, 
 * and return a sub-tree of only those functions or features that will be supported
 */
static FundamentalFeat_t  fill_fundamental_feat(FundamentalFeat_t f, int ver)
{
     int sup_count = 0;
     /* counters for version-specific missing fields. */
     int sfunc_ct = 0, srchfunc_ct = 0;
     if (f == NULL) return f;
     
     if (csp_empty_struct(f)) { /* populate it. means entire thingie was asked for. */
	  ServiceFunc_t svf  = csp_msg_new(ServiceFunc, NULL,
					   FV(spi, 1),
					   FV(map,1),
					   FV(seg,1));
	  SearchFunc_t scf = csp_msg_new(SearchFunc, NULL,
					   FV(srch, 1),
					   FV(advsrch,1),
					   FV(stsrc,1));
	  InviteFunc_t ivf = csp_msg_new(InviteFunc, NULL,
					   FV(inv, 1),
					   FV(cainv,1));
	  VerifyIDFunc_t vif = csp_msg_new(VerifyIDFunc, NULL,
					   FV(verify, 1));
	  
	  CSP_MSG_SET_FIELD(f,feat, csp_msg_new(FundamentalFeat_Union, NULL,
						FV(sfunc, svf),
						FV(srchfunc, scf),
						FV(ifunc, ivf),
						FV(vidfunc, vif)));
	  
	  if (ver <= CSP_VERSION(1,1))  /* doesn't exist in 1.1 */
	       ClearSField(f->feat, vidfunc);
	  if (ver <= CSP_VERSION(1,2)) { /* clear some fields that are only in higher versions. */
	       ClearField(svf, seg);	       
	       ClearField(svf,map);
	       ClearField(scf,advsrch);	       	       
	  }
     }

     if (ver <= CSP_VERSION(1,2)) { 
	  sfunc_ct = 2;
	  srchfunc_ct = 1;
     } 
	  
     /* now go through the tree. For each request feature which we don't support, 
	Set to 0/NULL 
     */

     
     
     if (f->mf) { /* request was made for mandatory features, means no other request was made. Clear it. */
	  csp_msg_unset_fieldset(f, "mf");	       	       	  
	  sup_count = 4;
     } else { /* one sub-tree at a time:
	       * mark those that are supported. 
	       * after that, check each sub-tree. If fully supported (all fields unmarked), delete/clear children, 
	       * and leave parent only. 
	       * if fully unsupported (all fields marked), then leave parent only in place. 
	       */
	  FundamentalFeat_Union_t ff = f->feat;
	  unsigned long fcount, scount, delcount = 0;	  
	  if (ff->sfunc) {
	       int preq = csp_empty_struct(ff->sfunc);

	       FeatSupported(preq,ff->sfunc, spi);  /* XXX edit these to control what is supported. */
	       if (ver > CSP_VERSION(1,2)) {
		    FeatNotSupported(preq,ff->sfunc,  map);
		    FeatNotSupported(preq,ff->sfunc,  seg);
	       }

	       if (csp_empty_struct(ff->sfunc)) {
		    CullSubTree(ff, sfunc);
		    sup_count++;
	       } else if (csp_struct_count_fields(ff->sfunc, &fcount, &scount) == 0 &&
			scount == (fcount-sfunc_ct)) {/* All are set, clear the object. */
		    csp_struct_clear_fields(ff->sfunc,~0);
		    delcount++;
	       }
	       
	  } else 
	       sup_count++;

	  if (ff->srchfunc) {
	       int preq = csp_empty_struct(ff->srchfunc);

	       FeatSupported(preq,ff->srchfunc, srch);  /* XXX edit these to control what is supported. */
	       if (ver > CSP_VERSION(1,2)) 
		    FeatNotSupported(preq,ff->srchfunc,  advsrch);
	       FeatSupported(preq,ff->srchfunc,  stsrc);

	       if (csp_empty_struct(ff->srchfunc)) {
		    CullSubTree(ff, srchfunc);
		    sup_count++;
	       } else if (csp_struct_count_fields(ff->srchfunc, &fcount, &scount) == 0 &&
			scount == (fcount-srchfunc_ct)) { /* All are set, clear the object. */
		    csp_struct_clear_fields(ff->srchfunc,~0);
		    delcount++;
	       }
	       
	  } else 
	       sup_count++;

	  if (ff->ifunc) {
	       int preq = csp_empty_struct(ff->ifunc);
	       
	       FeatSupported(preq,ff->ifunc, inv);  /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->ifunc,  cainv);


	       if (csp_empty_struct(ff->ifunc)) {
		    CullSubTree(ff, ifunc);
		    sup_count++;
	       }  else if (csp_struct_count_fields(ff->ifunc, &fcount, &scount) == 0 &&
			scount == fcount) {/* All are set, clear the object. */
		    csp_struct_clear_fields(ff->ifunc,~0);	       
		    delcount++;
	       }
	  } else 
	       sup_count++;

	  if (ff->vidfunc) {
	       int preq = csp_empty_struct(ff->vidfunc);
	       FeatSupported(preq,ff->vidfunc, verify);  /* XXX edit these to control what is supported. */
	       
	       if (csp_empty_struct(ff->vidfunc)) {
		    CullSubTree(ff, vidfunc);
		    sup_count++;
	       }  else if (csp_struct_count_fields(ff->vidfunc, &fcount, &scount) == 0 &&
			scount == fcount) { /* All are set, clear the object. */
		    csp_struct_clear_fields(ff->vidfunc,~0);	       
		    delcount++;
	       }
	  } else 
	       sup_count++;
	  
	  
	  /* Finally if all the children of FundamentalFeat are marked as unsupported, then clear them all, leaving itself. */
	  if (delcount == 4) 
	       csp_struct_clear_fields(f,~0);  /* clear fields of top-level itself. */
	  	  
     }
     
     
     if (sup_count == 4) { /* this means that inverted tree is empty (we support all that was asked for
				 * under fundamentalFeat, so return it as empty. 
				 */
	  csp_msg_free(f);
	  f = NULL;
     }
     
     return f;
}

static PresenceFeat_t  fill_presence_feat(PresenceFeat_t f, int ver)
{
     int sup_count = 0;
     
     int pafunc_ct = 0;

     if (f == NULL) 
	  return f;
     
     if (csp_empty_struct(f)) { /* populate it. means entire thingie was asked for. */
       ContListFunc_t cl = csp_msg_new(ContListFunc, NULL,
					FV(gcli, 1),
					FV(ccli,1),
					FV(mcls,1),	
					FV(dcli,1));
       PresenceAuthFunc_t pa = csp_msg_new(PresenceAuthFunc, NULL,
					   FV(getwl, 1),
					   FV(c, 1),
					   FV(g, 1),
					   FV(r,1));
       PresenceDeliverFunc_t pd = csp_msg_new(PresenceDeliverFunc, NULL,
					      FV(getpr, 1),
					      FV(updpr,1));
       AttListFunc_t al = csp_msg_new(AttListFunc, NULL,
				      FV(cali, 1),
				      FV(dali, 1),
				      FV(gals, 1));
	  
       CSP_MSG_SET_FIELD(f, feat, csp_msg_new(PresenceFeat_Union, NULL,
					      FV(clfunc, cl),
					      FV(pafunc, pa),
					      FV(pdfunc, pd),
					      FV(alfunc, al)));
	  
	  if (ver <= CSP_VERSION(1,1))  /* doesn't exist in 1.1 */	    
	       ClearField(pa,g);	  
	  else if (ver >= CSP_VERSION(1,3)) { /* clear some fields that are NOT in higher versions. */
	       ClearField(pa,r);
	       ClearField(pa,c);
	       ClearField(pa,g);
	       	       
	       ClearSField(f->feat, alfunc);	       	       
	  }
     }

     if (ver <= CSP_VERSION(1,1))  
	  pafunc_ct = 1;     
     else if (ver >= CSP_VERSION(1,3)) 
	  pafunc_ct = 3;
     
     /* now go through the tree. For each request feature which we don't support, 
	Set to 0/NULL 
     */

     
     
     if (f->mp)  {/* request was made for mandatory features, means no other request was made. Clear it. */
	  csp_msg_unset_fieldset(f, "mp");	       	       	  
	  sup_count = 4;
     }   else { /* one sub-tree at a time:
	       * mark those that are supported. 
	       * after that, check each sub-tree. If fully supported (all fields unmarked), delete/clear children, 
	       * and leave parent only. 
	       * if fully unsupported (all fields marked), then leave parent only in place. 
	       */
	  PresenceFeat_Union_t ff = f->feat;
	  unsigned long fcount, scount, delcount = 0;	  
	  if (ff->clfunc) {
	       int preq = csp_empty_struct(ff->clfunc);
	       FeatSupported(preq,ff->clfunc, gcli);  /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->clfunc,  ccli);
	       FeatSupported(preq,ff->clfunc,  dcli);
	       FeatSupported(preq,ff->clfunc,  mcls);
	       
	       if (csp_empty_struct(ff->clfunc)) {
		    CullSubTree(ff, clfunc);
		    sup_count++;
	       } else if (csp_struct_count_fields(ff->clfunc, &fcount, &scount) == 0 &&
			scount == fcount) {/* All are set, clear the object. */
		    csp_struct_clear_fields(ff->clfunc,~0);
		    delcount++;
	       }
	       
	  } else 
	       sup_count++;

	  if (ff->pafunc) {
	       int preq = csp_empty_struct(ff->pafunc);
	       FeatSupported(preq,ff->pafunc, getwl);  /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->pafunc,  r);

	       if (ver<CSP_VERSION(1,3)) {
		    FeatNotSupported(preq,ff->pafunc,  c);
		    if (ver>CSP_VERSION(1,1)) 
			 FeatNotSupported(preq,ff->pafunc,  g);
	       } 

	       if (csp_empty_struct(ff->pafunc)) {
		    CullSubTree(ff, pafunc);
		    sup_count++;
	       } else if (csp_struct_count_fields(ff->pafunc, &fcount, &scount) == 0 &&
			scount == (fcount-pafunc_ct)) { /* All are set, clear the object. */
		    csp_struct_clear_fields(ff->pafunc,~0);
		    delcount++;
	       }
	       
	  } else 
	       sup_count++;


	  if (ff->pdfunc) {
	       int preq = csp_empty_struct(ff->pdfunc);
	       FeatSupported(preq,ff->pdfunc, getpr);  /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->pdfunc,  updpr);


	       if (csp_empty_struct(ff->pdfunc)) {
		    CullSubTree(ff, pdfunc);
		    sup_count++;
	       } else if (csp_struct_count_fields(ff->pdfunc, &fcount, &scount) == 0 &&
			scount == fcount) { /* All are set, clear the object. */
		    csp_struct_clear_fields(ff->pdfunc,~0);	       
		    delcount++;
	       }
	  } else 
	       sup_count++;


	  if (ff->alfunc) {
	       int preq = csp_empty_struct(ff->alfunc);
	       FeatSupported(preq,ff->alfunc, cali);  /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->alfunc, dali);
	       FeatSupported(preq,ff->alfunc, gals);
		       
	       if (csp_empty_struct(ff->alfunc)) {
		    CullSubTree(ff, alfunc);
		    sup_count++;
	       } else if (csp_struct_count_fields(ff->alfunc, &fcount, &scount) == 0 &&
			scount == fcount) {/* All are set, clear the object. */
		    csp_struct_clear_fields(ff->alfunc,~0);	       
		    delcount++;
	       }
	  } else 
	       sup_count++;

	  
	  
	  /* Finally if all the children of PresenceFeat are marked as unsupported, then clear them all, leaving itself. */
	  if (delcount == 4) 
	       csp_struct_clear_fields(f,~0);  /* clear fields of top-level itself. */
	  	  
     }
     
     
     if (sup_count == 4) { /* this means that inverted tree is empty (we support all that was asked for
				 * under presenceFeat, so return it as empty. 
				 */
	  csp_msg_free(f);
	  f = NULL;
     }
     
     return f;
}


static IMFeat_t  fill_im_feat(IMFeat_t f, int ver)
{
     int sup_count = 0;
     int imrfunc_ct = 0;
     if (f == NULL) 
	  return f;
     
     if (csp_empty_struct(f)) { /* populate it. means entire thingie was asked for. */
	  IMSendFunc_t sf  = csp_msg_new(IMSendFunc, NULL,
					 FV(mdeliv, 1),
					 FV(fwmsg,1));
	  IMReceiveFunc_t rf = csp_msg_new(IMReceiveFunc, NULL,
					   FV(setd, 1),
					   FV(getlm, 1),
					   FV(getm, 1),
					   FV(notif, 1),
					   FV(offnotif, 1),
					   FV(rejcm,1));
	  IMAuthFunc_t af = csp_msg_new(IMAuthFunc, NULL,
					FV(glblu, 1),
					FV(blent,1));
	  
	  CSP_MSG_SET_FIELD(f, feat, csp_msg_new(IMFeat_Union, NULL,
						 FV(imfunc, sf),
						 FV(imrfunc, rf),
						 FV(imafunc, af)));
	  
	  if (ver < CSP_VERSION(1,3))  /* doesn't exist until 1.3 */	       
	       ClearField(rf,offnotif);
	  
     }

     if (ver < CSP_VERSION(1,3)) 
	  imrfunc_ct = 1;

     /* now go through the tree. For each request feature which we don't support, 
	Set to 0/NULL 
     */

     
     
     if (f->mm)  {/* request was made for mandatory features, means no other request was made. Clear it. */
	  csp_msg_unset_fieldset(f, "mm");	       	       	  
	  sup_count = 3;
     } else { /* one sub-tree at a time:
	       * mark those that are supported. 
	       * after that, check each sub-tree. If fully supported (all fields unmarked), delete/clear children, 
	       * and leave parent only. 
	       * if fully unsupported (all fields marked), then leave parent only in place. 
	       */
	  IMFeat_Union_t ff = f->feat;
	  unsigned long fcount, scount, delcount = 0;	  
	  if (ff->imfunc) {
	       int preq = csp_empty_struct(ff->imfunc);
	       FeatSupported(preq,ff->imfunc, mdeliv);  /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->imfunc,  fwmsg);
	       
	       if (csp_empty_struct(ff->imfunc)) {
		    CullSubTree(ff, imfunc);
		    sup_count++;
	       } else if (csp_struct_count_fields(ff->imfunc, &fcount, &scount) == 0 &&
			scount == fcount) { /* All are set, clear the object. */
		    csp_struct_clear_fields(ff->imfunc,~0);
		    delcount++;
	       }
	       
	  } else 
	       sup_count++;

	  
	  if (ff->imrfunc) {
	       int preq = csp_empty_struct(ff->imrfunc);
	       FeatSupported(preq,ff->imrfunc, setd);  /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->imrfunc,  getlm);
	       FeatSupported(preq,ff->imrfunc,  rejcm);
	       FeatSupported(preq,ff->imrfunc,  notif);
	       FeatSupported(preq,ff->imrfunc,  newm);
	       
	       if (ver >= CSP_VERSION(1,3))
		    FeatNotSupported(preq,ff->imrfunc,  offnotif);
	       
	       if (csp_empty_struct(ff->imrfunc)) {
		    CullSubTree(ff, imrfunc);
		    sup_count++;
	       } else if (csp_struct_count_fields(ff->imrfunc, &fcount, &scount) == 0 &&
			scount == (fcount-imrfunc_ct)) { /* All are set, clear the object. */
		    csp_struct_clear_fields(ff->imrfunc,~0);
		    delcount++;
	       }
	       
	  } else 
	       sup_count++;

	  
	  if (ff->imafunc) {
	       int preq = csp_empty_struct(ff->imafunc);
	       FeatSupported(preq,ff->imafunc, glblu);  /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->imafunc,  blent);
	       
	       
	       if (csp_empty_struct(ff->imafunc)) {
		    CullSubTree(ff, imafunc);
		    sup_count++;
	       }  else if (csp_struct_count_fields(ff->imafunc, &fcount, &scount) == 0 &&
			scount == fcount) { /* All are set, clear the object. */
		    csp_struct_clear_fields(ff->imafunc,~0);	       
		    delcount++;
	       }
	  } else 
	       sup_count++;
	 	  
	  /* Finally if all the children of IMFeat are marked as unsupported, then clear them all, leaving itself. */
	  if (delcount == 3) 
	       csp_struct_clear_fields(f,~0);  /* clear fields of top-level itself. */
	  
     }
     
     
     if (sup_count == 3) {      /* this means that inverted tree is empty (we support all that was asked for
				 * under presenceFeat, so return it as empty. 
				 */
	  csp_msg_free(f);
	  f = NULL;
     }
     
     return f;
}


static GroupFeat_t  fill_group_feat(GroupFeat_t f, int ver)
{
     int supcount = 0;
     int gufunc_ct = 0;

     if (f == NULL) 
	  return f;
     
     if (csp_empty_struct(f)) { /* populate it. means entire thingie was asked for. */
	  GroupMgmtFunc_t gm  = csp_msg_new(GroupMgmtFunc, NULL,
					    FV(creag, 1),
					    FV(delgr,1),
					    FV(getgp, 1),
					    FV(setgp, 1));
	  GroupUseFunc_t gu = csp_msg_new(GroupUseFunc, NULL,
					  FV(subgcn, 1),
					  FV(grchn, 1),
					  FV(excon, 1));
	  GroupAuthFunc_t ga = csp_msg_new(GroupAuthFunc, NULL,
					   FV(getgm, 1),
					   FV(addgrm,1),
					   FV(rmvgm,1),
					   FV(mbrac,1),
					   FV(rejec,1),
					   FV(getju,1));
	  
	  CSP_MSG_SET_FIELD(f,feat, csp_msg_new(GroupFeat_Union, NULL,
						FV(gmfunc, gm),
						FV(gufunc, gu),
						FV(gafunc, ga)));
	  
	  if (ver < CSP_VERSION(1,3))  /* doesn't exist until 1.3 */	       
	       ClearField(gu,excon);
	  
     }

     if (ver < CSP_VERSION(1,3)) 
	  gufunc_ct = 1;	  

     /* now go through the tree. For each request feature which we don't support, 
	Set to 0/NULL 
     */
     
     
     if (f->mg) { /* request was made for mandatory features, means no other request was made. Clear it. */
	  csp_msg_unset_fieldset(f, "mg");	       	       	  
	  supcount = 3; /* we alway support mandatory features. */
     } else { /* one sub-tree at a time:
	       * mark those that are supported. 
	       * after that, check each sub-tree. If fully supported (all fields unmarked), delete/clear children, 
	       * and leave parent only. 
	       * if fully unsupported (all fields marked), then leave parent only in place. 
	       */
	  GroupFeat_Union_t ff = f->feat;
	  unsigned long fcount, scount, delcount = 0;	  
	  if (ff->gmfunc) {
	       int preq = csp_empty_struct(ff->gmfunc);
	       FeatSupported(preq,ff->gmfunc, creag);  /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->gmfunc,  delgr);
	       FeatSupported(preq,ff->gmfunc,  getgp);
	       FeatSupported(preq,ff->gmfunc,  setgp);
	       
	       if (csp_empty_struct(ff->gmfunc)) {
		    CullSubTree(ff, gmfunc);
		    supcount++;
	       } else if (csp_struct_count_fields(ff->gmfunc, &fcount, &scount) == 0 &&
			scount == fcount) { /* All are set, clear the object. */
		    csp_struct_clear_fields(ff->gmfunc,~0);
		    delcount++;
	       }
	       
	  } else 
	       supcount++;

	  
	  if (ff->gufunc) {
	       int preq = csp_empty_struct(ff->gufunc);
	       FeatSupported(preq,ff->gufunc, subgcn);  /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->gufunc,  grchn);

	       if (ver >= CSP_VERSION(1,3))
		    FeatNotSupported(preq,ff->gufunc,  excon);
	       
	       if (csp_empty_struct(ff->gufunc)) {
		    CullSubTree(ff, gufunc);
		    supcount++;
	       } else if (csp_struct_count_fields(ff->gufunc, &fcount, &scount) == 0 &&
			scount == (fcount-gufunc_ct)) { /* All are set, clear the object. */
		    csp_struct_clear_fields(ff->gufunc,~0);
		    delcount++;
	       }
	       
	  } else 
	       supcount++;
	  
	  if (ff->gafunc) {
	       int preq = csp_empty_struct(ff->gafunc);
	       FeatSupported(preq,ff->gafunc, getgm); /* XXX edit these to control what is supported. */
	       FeatSupported(preq,ff->gafunc, addgrm);
	       FeatSupported(preq,ff->gafunc, rmvgm);
	       FeatSupported(preq,ff->gafunc, mbrac);
	       FeatSupported(preq,ff->gafunc, rejec); 
	       FeatSupported(preq,ff->gafunc, getju);
	       
	       if (csp_empty_struct(ff->gafunc)) {
		    CullSubTree(ff, gafunc);
		    supcount++;
	       }  else if (csp_struct_count_fields(ff->gafunc, &fcount, &scount) == 0 &&
			scount == fcount) { /* All are set, clear the object. */
		    csp_struct_clear_fields(ff->gafunc,~0);	       
		    delcount++;
	       }
	  } else 
	       supcount++;
	 	  
	  /* Finally if all the children of GroupFeat are marked as unsupported, then clear them all, leaving itself. */
	  if (delcount == 3)  
	       csp_struct_clear_fields(f,~0);  /* clear fields of top-level itself. */
	  
     }
     
     
     if (supcount == 3) {       /* this means that inverted tree is empty (we support all that was asked for
				 * under presenceFeat, so return it as empty. 
				 */
	  csp_msg_free(f);
	  f = NULL;
     }
     
     return f;
}

static Functions_t handle_funcs_request(Functions_t req, int ver, int *dflt_notify)
{
     WVCSPFeat_t wv;

     gw_assert(req);
     gw_assert(req->feat);
     
     wv = csp_msg_copy(req->feat);
     
     /* now we need to build the reply. */
     
     if (csp_empty_struct(wv)) { /* build them. */
	  wv->ffeat = csp_msg_new(FundamentalFeat, NULL, NULL);
	  wv->pfeat = csp_msg_new(PresenceFeat, NULL, NULL);
	  wv->ifeat = csp_msg_new(IMFeat, NULL, NULL);
	  wv->gfeat = csp_msg_new(GroupFeat, NULL, NULL);
     }

     /* handle session issues. */
     if (wv->pfeat == NULL ||
	 wv->pfeat->feat == NULL ||
	 wv->pfeat->feat->pafunc == NULL || 
	 wv->pfeat->feat->pafunc->r)        /* request for reactive notification should be honoured. */
	  *dflt_notify = 1;
     else 
	  *dflt_notify = 0;

       
     
     wv->ffeat = fill_fundamental_feat(wv->ffeat, ver); /* invert the trees. */
     wv->pfeat = fill_presence_feat(wv->pfeat, ver);
     wv->ifeat = fill_im_feat(wv->ifeat, ver);
     wv->gfeat = fill_group_feat(wv->gfeat,ver); 

     /* XXX suppose all that was asked is supported?? What do we return ?? */     
     if (wv->ffeat == NULL && wv->pfeat == NULL &&
	 wv->ifeat == NULL && wv->gfeat == NULL) {
	  csp_msg_free(wv);
	  wv = NULL;
     }
     
     return  csp_msg_new(Functions, NULL, FV(feat, wv));     
}

Service_Response_t handle_serviceRequest(RequestInfo_t *ri, Service_Request_t req)
{
     Service_Response_t resp;
     Functions_t fns;
     int dflt_notify;
     PGconn *c = ri->c;
     
     gw_assert(req);
     gw_assert(req->funcs);     
     
     fns = handle_funcs_request(req->funcs, ri->ver, &dflt_notify);
     
     resp = csp_msg_new(Service_Response, NULL,
			FV(funcs, fns),
			FV(clid, csp_msg_copy(req->clid)));

     if (req->clid == NULL)  /* No client, e.g. for ver > 1.1 */
	  csp_msg_unset_fieldset(resp, "clid"); /* not strictly required. */
     
     if (req->allfuncs != 0)  /* request for all functions -- just say we support all :-> */
	  CSP_MSG_SET_FIELD(resp, allfuncs, csp_msg_new(AllFunctions, NULL,
							FV(feat, csp_msg_new(WVCSPFeat, NULL, NULL))));
     update_session_notify(c,ri->sessid,dflt_notify);
	  
     
     return resp;
}


static void save_sess_ctypes(PGconn *c, u_int64_t sessid, int ver,  List *ctypes)
{
     int i, n;
     char tmp1[64], tmp2[5], cmd[256];
     PGresult *r;
     /* first Delete any old ones. */
     sprintf(cmd, "DELETE from session_content_types WHERE sessionid = %llu", sessid);

     r = PQexec(c, cmd);
     PQclear(r);
     for (i = 0, n = gwlist_len(ctypes); i< n; i++) {
	  AcceptedContentType_t ct = gwlist_get(ctypes, i); 
	  char *ctype = ct->ctype ? (void *)ct->ctype->str : octstr_get_cstr(ct->_content);
	  unsigned  clen = (ver >= CSP_VERSION(1,3)) ? ct->rich_clen : DEFAULT_MAX_CLEN;
	  unsigned clim = (ver >= CSP_VERSION(1,3)) ? ct->cpolicy_lim : DEFAULT_MAX_CLEN;
	  char *cpolicy = (ver >= CSP_VERSION(1,3)) && ct->cpolicy ? (char *)ct->cpolicy->str : "N";
	
	  
	  PQ_ESCAPE_STR(c, ctype, tmp1);
	  PQ_ESCAPE_STR(c, cpolicy, tmp2);	  
	  sprintf(cmd, "INSERT INTO session_content_types (sessionid,ctype, max_len, cpolicy, cpolicy_limit) "
		  " VALUES (%llu, '%.64s', %u, '%.1s', %u)",
		  sessid, tmp1, clen, tmp2, clim);
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_COMMAND_OK) 
	       error(0, "save_cypes failed for session with ID [%llu]: %s", 
		     sessid, PQerrorMessage(c));
	  PQclear(r);
	  
     }
     
}

static void save_sess_charsets(PGconn *c, u_int64_t sessid, int ver, List *charsets)
{

     int i, n;
     char cmd[256];
     PGresult *r;
     /* first Delete any old ones. */
     sprintf(cmd, "DELETE from session_charsets WHERE sessionid = %llu", sessid);

     r = PQexec(c, cmd);
     PQclear(r);
     for (i = 0, n = gwlist_len(charsets); i< n; i++) {
	  PlainTextCharset_t ch = (PlainTextCharset_t)gwlist_get(charsets, i); 
		  	  
	  sprintf(cmd, "INSERT INTO session_charsets (sessionid,charset) "
		  " VALUES (%llu,  %d)",  sessid, (int)ch);
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_COMMAND_OK) 
	       error(0, "save_charsets failed for session with ID [%llu]: %s", 
		     sessid, PQerrorMessage(c));
	  PQclear(r);
	  
     }

}

static void *handle_capabilitylist(PGconn *c, CapabilityList_t cl,
				   RequestInfo_t *ri, int *utype)
{
     int64_t sid = ri->sessid;
     char cmd[1024], *s;
     char  client[64], lang[10], dmethod[5], offlinem[16], onlinem[16];
     int pull_len, push_len, txt_len, prio, i, n;
     int set_server_poll;
     int sudp_port;
     SupportedCIRMethod_t cirm;
     SupportedBearer_t b;
     CIRHTTPAddress_t cirhttp = NULL;
     CIRURL_t cir_url = NULL;
     _TCPAddr_t cirstcp = NULL;
     void *uval = NULL; /* result type. */
     int has_stcp = 0, has_shttp = 0, has_wapudp = 0, has_wapsms = 0, cir_mask = 0; 
     PGresult *r;
	       
     if (ri->ver <= CSP_VERSION(1,2)) { /* defaults for 1.2 and below */
	  pull_len = txt_len = DEFAULT_MAX_CLEN;
	  push_len = (cl->aclen > 0) ? cl->aclen : DEFAULT_MAX_CLEN;
	  prio = 0;
     } else {
	  pull_len = cl->pull_len;
	  push_len = cl->push_len;
	  txt_len = cl->txt_len;
	  prio = cl->sess_pri;
     }
     
     /* escape the dodgy ones... */
     s = cl->cltype ? (void *)cl->cltype->str : "N/A";
     PQ_ESCAPE_STR(c, s, client);

     s = cl->dfl_lang ? (void *)cl->dfl_lang->str : "en";
     PQ_ESCAPE_STR(c, s, lang);

     s = cl->dmethod ? (void *)cl->dmethod->str : "P";
     PQ_ESCAPE_STR(c, s, dmethod);
       
     s = cl->offline_m ? (void *)cl->offline_m->str : "SENDSTORE";
     PQ_ESCAPE_STR(c, s, offlinem);
       
     s = cl->online_m ? (void *)cl->online_m->str : "SERVERLOGIC";
     PQ_ESCAPE_STR(c, s, onlinem);  
     
     /* now worry about some defaults. */
     if (cl->poll_min <  ri->conf->min_ttl) {
	  cl->poll_min = ri->conf->min_ttl;
	  set_server_poll = 1;
     } else 
	  set_server_poll = 0;
     
     /* Get SUDP/IP port. */
     if (csp_msg_field_isset(cl, udp_port))
	  sudp_port = cl->udp_port;
     else 
	  sudp_port = SUDP_PORT;

     /* find requested CIR methods, provide HTTP and/or STCP, WAPUDP, WAPSMS. */

     for (i = 0, n = gwlist_len(cl->cir_methods); i< n; i++) 
	  if ((cirm = gwlist_get(cl->cir_methods, i)) == NULL || cirm->str == NULL) /* an error ?? */
	       continue;
	  else if (strcasecmp((char *)cirm->str, "STCP") == 0) {
	       has_stcp = 1;
	       cir_mask  |= HAS_STCP;
	  } else if (strcasecmp((char *)cirm->str, "SHTTP") == 0) {
	       has_shttp = 1;
	       cir_mask  |= HAS_SHTTP;
	  } else if (strcasecmp((char *)cirm->str, "WAPUDP") == 0) {
	       has_wapudp = 1;
	       cir_mask  |= HAS_WAPUDP;
	  } else if (strcasecmp((char *)cirm->str, "WAPSMS") == 0) {
	       has_wapsms = 1;
	       cir_mask  |= HAS_WAPSMS;
	  }


     sprintf(cmd, 
	     "UPDATE sessions SET csp_version='%d.%d', pull_len=%d, push_len=%d, text_len=%d, "
	     "anycontent=%s, client_type='%.64s', lang='%.10s', deliver_method='%.10s', multi_trans=%d, "
	     "offline_ete_m_handling='%.16s', online_ete_m_handling='%.16s', parse_size=%d, "
	     "server_poll_min=%d, priority=%d, ip='%.32s', caps = true,cir_mask = %d,sudp_port=%d WHERE id = %lld", 
	     CSP_MAJOR_VERSION(ri->ver), CSP_MINOR_VERSION(ri->ver), 
	     pull_len, push_len, txt_len, 
	     cl->ctype_all ? "true" : "false",
	     client, lang, dmethod, (int)cl->mtrans,
	     offlinem, onlinem, (int)cl->psize, 
	     (int)cl->poll_min, prio, 
	     octstr_get_cstr(ri->req_ip), 
	     cir_mask, sudp_port,
	     sid);

     r = PQexec(c, cmd);
     if (PQresultStatus(r) != PGRES_COMMAND_OK) 
	  error(0, "handle_cap_request: DB error for session with ID [%.64s]: %s", 
		ri->xsessid, PQerrorMessage(c));
     PQclear(r);
     
     save_sess_ctypes(c, sid, ri->ver, cl->ctypes);
     save_sess_charsets(c, sid, ri->ver, cl->pt_charset);
     if (has_shttp && 
	 ri->ver >= CSP_VERSION(1,2)) { /* supports HTTP. */
	  char xid[64];
	  Octstr *url;
	  Octstr *salt = make_salt(ri);
	  
	  sprintf(xid, "%lld", ri->sessid);
	  url = octstr_format("http://%s:%d%s/%S/%s", ri->conf->cir_ip, 
			      ri->conf->external_http_port, CIR_URI, salt, xid);	  
	  if (ri->ver == CSP_VERSION(1,2))
	       cir_url = csp_msg_new(CIRURL, NULL,
				     FV(url, csp_String_from_bstr(url, Imps_URL)));
	  else 
	       cirhttp = csp_msg_new(CIRHTTPAddress, NULL,
				     FV(url, csp_String_from_bstr(url, Imps_URL)));
	  octstr_destroy(url);
	  octstr_destroy(salt);
     } 
     
     if (has_stcp && 
	 cir_url == NULL && cirhttp == NULL) { /* only then do we use TCP */
	  cirstcp = csp_msg_new(_TCPAddr, NULL,
				FV(addr, csp_String_from_cstr(ri->conf->cir_ip, Imps_TCPAddress)),
				FV(port, ri->conf->cir_stcp_port));
     }
          
     /* now make the response. */
     if (ri->ver <= CSP_VERSION(1,1)) {
	  CapabilityList_t cnew = uval = csp_msg_copy(cl); /* copy it .*/
	  void *cir = has_stcp ? csp_String_from_cstr("STCP", Imps_SupportedCIRMethod) : NULL;
	  List *cirl = cir ?  gwlist_create_ex(cir) : gwlist_create();

	  
	  /* handle other methods. */
	  if (has_wapudp && ri->client_ip)
	       gwlist_append(cirl, 
			     csp_String_from_cstr("WAPUDP", Imps_SupportedCIRMethod));

	  if (has_wapsms 
#if 0
	      && ri->msisdn 
#endif
	      && ri->conf->send_sms_url[0])
	       gwlist_append(cirl, 
			     csp_String_from_cstr("WAPSMS", Imps_SupportedCIRMethod));
	  
	  /* ... then do some fixups. */
	  if (has_stcp) {
	       if (cnew->tcp_addr)  { 
		    csp_msg_free(cnew->tcp_addr);
		    cnew->tcp_addr = cirstcp;
	       } else 
		    CSP_MSG_SET_FIELD(cnew, tcp_addr, cirstcp);
	  }

	  if (cnew->cir_methods) {
	       gwlist_destroy(cnew->cir_methods, _csp_msg_free);
	       cnew->cir_methods = cirl;
	  } else 
	       CSP_MSG_SET_FIELD(cnew, cir_methods, cirl);

#if 0
	  if (!csp_msg_field_isset(cnew, poll_min))
	       CSP_MSG_SET_FIELD(cnew, poll_min, DEFAULT_POLL_MIN);
#else 
	  /* if it was not set, don't reply with it (says SCR??) */
	  if (csp_msg_field_isset(cnew, poll_min) && 
	      cnew->poll_min < ri->conf->min_ttl)
	       cnew->poll_min = ri->conf->min_ttl;
#endif
	  /* clear accepted content type. */
	  if (csp_msg_field_isset(cnew, ctypes)) {
	       gwlist_destroy(cnew->ctypes, _csp_msg_free);
	       cnew->ctypes = NULL;
	  }
	  /* ... then say we support all. */
	  if (!csp_msg_field_isset(cnew, ctype_all)) 
	       CSP_MSG_SET_FIELD(cnew, ctype_all, 1);
	  else 
	       cnew->ctype_all = 1; /* Macro above barfs if the thingie is set. */

	  /* free ones not to be used. */
	  csp_msg_free(cir_url);
	  csp_msg_free(cirhttp);

	  /* the rest we accept as given. wise?? */
	  *utype = Imps_CapabilityList;	  
     } else {	  
	  List *l = gwlist_create();
	  List *resp_te; /* response transfer encoding. */
	  List *bearers; /* bearer list. */

	  /* if user requested many transfer encoding types, force base64 only on them (without looking
	   * at what they asked for!)
	   */
	  if (cl->te && gwlist_len(cl->te) > 1) 
	       resp_te = gwlist_create_ex(csp_String_from_cstr("BASE64", Imps_AcceptedTransferEncoding));
	  else 
	       resp_te = NULL;
	  
	  /* filter out all un-supported bearers. */
	  bearers = gwlist_create();
	  for (i = 0, n = gwlist_len(cl->bearers); i<n; i++) 
	       if ((b = gwlist_get(cl->bearers, i)) != NULL && 
		   b->str && 
		   (strcasecmp((char *)b->str, "wsp") == 0 || 
		    strcasecmp((char *)b->str, "http") == 0 /* and others ... */))
		    gwlist_append(bearers, csp_String_from_cstr(b->str, Imps_SupportedBearer));
	  
	  if (cirhttp || cir_url)
	       gwlist_append(l, csp_String_from_cstr("SHTTP", 
						     Imps_SupportedCIRMethod));
	  else if (has_stcp)
	       gwlist_append(l, csp_String_from_cstr("STCP", 
						     Imps_SupportedCIRMethod));

	  /* handle other methods. */
	  if (has_wapudp && ri->client_ip)
	       gwlist_append(l, 
			     csp_String_from_cstr("WAPUDP", Imps_SupportedCIRMethod));
	  
	  if (has_wapsms 
#if 0
	      && ri->msisdn 
#endif
	      && ri->conf->send_sms_url[0])
	       gwlist_append(l, 
			     csp_String_from_cstr("WAPSMS", Imps_SupportedCIRMethod));

	  uval = csp_msg_new(AgreedCapabilityList, NULL,
			     FV(cir_http, cirhttp),
			     FV(cir_url, cir_url),
			     FV(poll_min, cl->poll_min),
			     FV(bearers, bearers), 
			     FV(cir_methods, l),
			     FV(te, resp_te),
			     FV(tcp_addr, cirstcp));
	  *utype = Imps_AgreedCapabilityList;
	  
	  /* only one of tcp address and cir http address SHOULD set?? */
     }

#if 0
     if (!set_server_poll)
	  csp_msg_unset_fieldset(uval, "poll_min");
#endif 

     /* handle group auto join */     
     join_all_auto_groups(ri);

     return uval;
}

ClientCapability_Response_t handle_cap_request(RequestInfo_t *ri, ClientCapability_Request_t req)
{
     PGconn *c = ri->c;

     ClientCapability_Response_t resp = NULL;
     
     void *uval; /* result type and value. */
     int utype; 

     gw_assert(req);
     
     if (req->clist == NULL)
	  goto done;

     uval = handle_capabilitylist(c, req->clist, ri, &utype);
     if (uval) 
	  resp = csp_msg_new(ClientCapability_Response, NULL, 
			     FV(clid, csp_msg_copy(req->clid)),
			     UFV(aclist, utype, uval));     
 done:
          
     return resp;
}


Search_Response_t handle_search(RequestInfo_t *ri, Search_Request_t req)
{
     int lim, start = -1;
     char tmp1[128], cmd[512];
     int64_t uid = ri->uid, min; /* userid... */
     Search_Response_t resp = NULL;
     int64_t s_id = ri->sessid, srchid = 0, res_start = 0;
     int  scount = 0;    
     char qtype = 'U';
     
     PGconn *c = ri->c;
     PGresult *r;

     if (req->slist) { /* starting search... */
	  int i, j, n, m;
	  Octstr *crit = octstr_create(""), *sql = NULL; /* build sql in here. */
	  
	  SearchPairList_t spl;
	  SearchPair_t sp;
	  char *fld1, *fld2, *tbl;
	  
	  lim = req->slim;
	  if (lim == 0)
	       lim = 5;

	  /* XXX GET the userid here... */
	  for (i = 0, n = gwlist_len(req->slist); i<n; i++) 
	       if ((spl = gwlist_get(req->slist,i)) != NULL) 
		    for (j = 0, m = gwlist_len(spl->slist); j<m; j++)
			 if ((sp = gwlist_get(spl->slist, j)) != NULL) {
			      char *elem = sp->elem ? (void *)sp->elem->str : NULL;
			      char *val  = sp->str ? (void *)sp->str->str : ""; 
			      char xuid[64];
			      
			      sprintf(xuid, "%lld", uid);

			      PQ_ESCAPE_STR(c, val, tmp1);			      
			      if (elem == NULL || val == NULL)
				   error(0, "missing search element/value in search request for session [%s]!",
					 ri->xsessid);
#define DBFIELD(fld,qry,typ,_val) else if (strcasecmp(elem,#fld) == 0) do {\
                                octstr_format_append(crit, "%s " qry, octstr_len(crit) == 0 ? "" : " AND ", _val); \
                                qtype = (#typ)[0]; \
                              } while (0)
			      
			      			      
			      DBFIELD(USER_AGE_MIN, "extract(YEAR FROM age(dob,current_timestamp)) >= %.32s",U, tmp1);
			      DBFIELD(USER_AGE_MAX, "extract(YEAR FROM age(dob,current_timestamp)) < %.32s ",U, tmp1);
			      DBFIELD(USER_COUNTRY, "country LIKE '%%%.64s%%'",U, tmp1);
			      DBFIELD(USER_FRIENDLY_NAME, "nickname LIKE '%%%.64s%%'",U, tmp1);
			      DBFIELD(USER_CITY, "city LIKE  '%%%.64s%%'",U, tmp1);
			      DBFIELD(USER_GENDER, "gender = '%.1s'",U, tmp1);
			      DBFIELD(USER_INTENTION, "intention LIKE '%%%.128s%%'",U, tmp1);
			      DBFIELD(USER_INTERESTS_HOBBIES, "hobbies  LIKE '%%%.128s%%'",U, tmp1);
			      DBFIELD(USER_MARITAL_STATUS, "marital_status='%.1s'",U, tmp1);
			      DBFIELD(USER_ALIAS, "nickname='%.64s'",U, tmp1);
			      DBFIELD(USER_ONLINE_STATUS, "online_status='%.64s'",U, tmp1); /* doesn't work! */
			      DBFIELD(USER_EMAIL_ADDRESS, "email ILIKE '%%%.128s%%'",U, tmp1);
			      DBFIELD(USER_FIRST_NAME, "firstname ILIKE  '%%%.128s%%'",U, tmp1);
			      DBFIELD(USER_ID, "full_userid ILIKE '%%%.128s%%'",U, tmp1);
			      DBFIELD(USER_LAST_NAME, "lastname ILIKE '%%%.128s%%'",U, tmp1);
			      DBFIELD(USER_MOBILE_NUMBER, "phone ILIKE '%%%.128s%%'",U, tmp1);
			      
			      /* now the group ones. */
			      DBFIELD(GROUP_ID,"group_id ILIKE '%%%.128s%%'",G,tmp1);
			      DBFIELD(GROUP_NAME,"group_name ILIKE '%%%.128s%%'",G,tmp1);
			      DBFIELD(GROUP_TOPIC,"topic ILIKE '%%%.128s%%'",G,tmp1);
			      DBFIELD(GROUP_USER_ID_JOINED,"id IN (SELECT groupid FROM group_members WHERE local_userid = %s and isjoined = true)",
				      G,xuid);

			      DBFIELD(GROUP_USER_ID_OWNER,"creator = %s",G,xuid);
			      DBFIELD(GROUP_USER_ID_AUTOJOIN,"id IN (SELECT groupid FROM group_members_view WHERE local_userid = %s AND auto_join = 'T')",G,xuid);
			      /* XXXX how will SSP integrate with this cleanly?? */
			      else 
				   error(0, "unknown/unsupported search field [%.32s]", elem);
			 }
	  if (octstr_len(crit) == 0) 
	       goto sdone;
	  
	  /* make a new search */
	  sprintf(cmd, "INSERT INTO searches (session, stype) VALUES (%lld, '%c') RETURNING id", s_id, qtype);
	  r  = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
	       error(0, "failed to create new stored search for session [%s]: %s",
		     ri->xsessid, PQerrorMessage(c));
	       srchid = 0;
	  } else 
	       srchid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
	  PQclear(r);

	  if (qtype == 'U') {
	       tbl =  "users_view";
	       fld1 = "full_userid";
	       fld2 = "nickname";
	  } else {
	       tbl = "groups_view";
	       fld1 = "group_id";
	       fld2 = "''";
	  }
	  sprintf(tmp1, "%lld", srchid);
	  sql = octstr_format("INSERT INTO search_results (sid,v1,v2) "
			      "SELECT %s,%s,%s FROM %s WHERE %S LIMIT %d RETURNING id", tmp1, fld1,fld2,tbl, crit,
			      DEFAULT_MAX_SEARCH_LIMIT); 

	  r = PQexec(c, octstr_get_cstr(sql));
	  
	  if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	       char *s = PQgetvalue(r, 0, 0);
	       int ii;

	       min = strtoull(s, NULL, 10);	      
	       scount = PQntuples(r);
	       for (ii = 1; ii < scount; ii++) {		   
		    u_int64_t x;
		    s = PQgetvalue(r, ii, 0);
		    x = strtoull(s, NULL, 10);
		    
		    if (x < min) min = x;
	       }
	       
	  } else {
	       min = 0;
	       scount = 0;
	  }
	  PQclear(r);

	  start = 1; /* where to start the listing. */
	  res_start = min;
	  /* UPDATE the top-level. */
	  sprintf(cmd, "UPDATE searches SET slimit=%d, start_results_id = %lld, result_count=%d WHERE id = %lld", 
		  lim, min, scount, srchid);
	  r = PQexec(c, cmd);
	  if (PQresultStatus(r) != PGRES_COMMAND_OK)
	       error(0, "handle_search: failed to update new stored search for session [%s]: %s",
		     ri->xsessid, PQerrorMessage(c));
	  PQclear(r);

     sdone:
	  octstr_destroy(crit);
	  octstr_destroy(sql);	  
     } else if (req->id) { /* ... continuing a download of results. */
	  char *s;
	  srchid  = req->id;
	  start = req->index;	  

	  /* now query for the results sought. */
	  sprintf(cmd, "SELECT slimit, stype, start_results_id, result_count FROM searches WHERE id = %lld", srchid);
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) {
	       void *rs = csp_msg_new(Result, NULL, 
				      FV(code,424), 
				      FV(descr, csp_String_from_cstr("Invalid SearchID", Imps_Description)));
	       resp = (void *)csp_msg_new(Status,NULL,
				  FV(res,rs));	  
	       PQclear(r);
	       goto done;
	  } 
	  
	  lim = strtoul(PQgetvalue(r, 0, 0), NULL, 10);
	  s = PQgetvalue(r, 0, 1);
	  qtype = s ? s[0] : 'U';

	  res_start = strtoull(PQgetvalue(r, 0, 2), NULL, 10);	  
	  scount = strtoul(PQgetvalue(r, 0, 3), NULL, 10);	  
	  PQclear(r);
     }
     
     /* finally get the results, list them. */
     if (start >= 0) {
	  List *l;
	  void *rl;
	  u_int64_t rstart = res_start + start - 1; /* off by one... */
	  int i, rcount, has_tuples, sindex;
	  SearchResult_t sr;
	  char xsid[128];
	  
	  sprintf(xsid, "%lld", srchid);
	  
	  sprintf(cmd, "SELECT v1,v2 from search_results WHERE sid = %lld AND id >= %lld ORDER BY id LIMIT %d",
		  srchid, rstart, lim);
	  r = PQexec(c, cmd);
	  if (PQresultStatus(r) != PGRES_TUPLES_OK) {
	       has_tuples = 0;
	       rcount = 0;
	       error(0, "failed to find results for search id [%s], session [%s]: %s",
		     xsid, 
 		     ri->xsessid, PQerrorMessage(c));
	  } else {
	       has_tuples = 1;
	       rcount = PQntuples(r); 
	  }
	  if ((!has_tuples || rcount <= 0) && req->slist == NULL)  { /* continuing and no results... */
	       void *rs = csp_msg_new(Result, NULL, 
				      FV(code,425), 
				      FV(descr, csp_String_from_cstr("Invalid Search Index", Imps_Description)));
	       resp = (void *)csp_msg_new(Status,NULL,
				  FV(res,rs));	  
	       PQclear(r);
	       
	       goto done;
	  }
	  
	  /* else, attempt to get and build results. */
	  
	  l = gwlist_create();
	  for (i = 0; i<rcount; i++) {
	       char *v1 = PQgetvalue(r, i, 0);
	       char *v2 = PQgetvalue(r, i, 1);
	       
	       if (qtype == 'U') {
		    User_t u = csp_msg_new(User,NULL, 
					   FV(user, csp_String_from_cstr(v1, Imps_UserID)));
		    if (ri->ver > CSP_VERSION(1,2) && v2 && v2[0])  /* only this one supports friendlyname. */
			 CSP_MSG_SET_FIELD(u,fname, csp_String_from_cstr(v2, Imps_FriendlyName));
		    gwlist_append(l, u);
	       } else  /* group. */
		    gwlist_append(l, csp_String_from_cstr(v1, Imps_GroupID));
	       	       
	  }
	  PQclear(r);
	  
	  sindex = start + rcount;
	  
	  /* make the search result. */
	  rl = (qtype == 'U') ? (void *)csp_msg_new(UserList, NULL, FV(ulist, l)) : csp_msg_new(GroupList, NULL, FV(glist, l));
	  sr = csp_msg_new(SearchResult, NULL, UFV(u,(qtype == 'U') ? Imps_UserList : Imps_GroupList, rl));
	  
	  /* then make the response. */
	
	  
	  resp = csp_msg_new(Search_Response, NULL,
			    FV(sfindings, scount),
			    FV(sidx, sindex),
			    FV(cflag, (rcount <= 0 || sindex > scount)), /* we are done when index exceeds. */
			    FV(sres, sr));
	  if (req->slist)  /* first request, insert search ID. */
	       CSP_MSG_SET_FIELD(resp, id, srchid);

	  if (resp->cflag) /* if complete remove search index. */
	       csp_msg_unset_fieldset(resp, "sidx");
     } else { /* else we did not understand the request. */
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,562), 
				 FV(descr, csp_String_from_cstr("Invalid Search", Imps_Description)));
	  resp = (void *)csp_msg_new(Status,NULL,
			     FV(res,rs));	  
	  
     }
 done:
     
     
     return resp;
}

Status_t handle_stopsearch(RequestInfo_t *ri, StopSearch_Request_t req)
{
     void *rs;
     PGconn *c = ri->c;
     PGresult *r;
     Status_t resp;
     
     int64_t srchid = req->id;
     char cmd[512];
     
     sprintf(cmd, "DELETE from searches WHERE id = %lld", srchid);
     
     r = PQexec(c, cmd);
     PQclear(r);
     
     rs = csp_msg_new(Result, NULL, 
		      FV(code,200), 
		      FV(descr, csp_String_from_cstr("Success", Imps_Description)));
     resp = (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  	  	  
          
     return resp;
}

/* verify the sender, return true if ok, false otherwise. */
int verify_sender(PGconn *c, Sender_t *xsender, int64_t uid, 
			 Octstr *userid,
			 Octstr *clientid, int64_t *mygid, char **err)
{
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN];
     char cmd[512];
     int res;
     PGresult *r;
     Sender_t sender = xsender ? *xsender : NULL;
     
     if (sender == NULL || sender->u.val == NULL) {
	  *err = "Missing UserID/Group ID";
	  return 427; 
     }
     
     *mygid = -1;
     if (sender->u.typ == Imps_Group) {
	  Group_t grp = sender->u.val;
	  int64_t gid;	 
	  ScreenName_t s;
	  char *fld;
	  
	  if (grp->u.typ != Imps_ScreenName || grp->u.val == NULL) {
	       *err = "invalid user!";
	       return 427; /* invalid user type. */
	  }
	  s = grp->u.val;


	  if (s->gid == NULL) {
	       *err = "Missing group ID";
	       return 429; /* missing group ID. */
	  }
	  if (s->sname == NULL) {
	       *err = "Empty/Missing Screen Name";
	       return 427;
	  }
	  /* find the group, then find out if the user is in the group with the given screen name. */
	  extract_id_and_domain((char *)s->gid->str, xid, xdomain);
	  
	  PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	  PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);

	  /* if it is not a local domain, don't check further. */
	  if (get_islocal_domain(c, tmp2) == 0) {
	       csp_msg_free(*xsender);
	       *xsender = make_sender_struct2(userid, clientid, NULL, NULL);
	       return 200;
	  }
	  
	  sprintf(cmd, "SELECT id FROM groups WHERE groupid = '%.128s' AND domain = '%.128s'", tmp1, tmp2);
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
	       PQclear(r);
	       *err = "No such group";
	       return 800; /* no such group. */
	  }
	  
	  *mygid = gid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
	  
	  PQclear(r);
	  
	  /* now verify screen name. */
	  PQ_ESCAPE_STR_LOWER(c, (char *)s->sname->str, tmp1);	
	  if (uid >= 0) {
	       fld = "local_userid";
	       sprintf(tmp2, "%lld", uid);
	  } else {
	       fld = "foreign_userid";
	       PQ_ESCAPE_STR_LOWER(c, octstr_get_cstr(userid), tmp2);	       
	  }

	  sprintf(cmd, "SELECT id FROM group_members WHERE %s = '%.128s' AND screen_name = '%.128s' AND isjoined = true", 
		  fld, tmp2, tmp1);
	  r = PQexec(c, cmd);
	  
	  res = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) ? 200 : 810;
	  *err = (res == 800) ? "Missing group or screen name mismatch" : "";
	  PQclear(r);
     } else if (uid >= 0) { /* only check this for local users. */
	  User_t u = sender->u.val;
	  UserID_t user = u->user;
	  ClientID_t _c = (u->u.typ == Imps_ClientID) ? u->u.val : NULL;
	  ApplicationID_t _a = (u->u.typ == Imps_ApplicationID) ? u->u.val : NULL;
	  Octstr *x = (_c || _a) ? make_clientid(_c, _a) : NULL;
	  int islocal;
	  
	  extract_id_and_domain((char *)user->str, xid, xdomain);
	  PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	  PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);

	  if (get_userid(c, tmp1, tmp2, &islocal) != uid) {
	       res = 427;
	       *err = "User mismatch!";
	  } else if (clientid && x && octstr_compare(x, clientid) != 0) {
	       res = (_a) ? 450 : 428;
	       *err = "Client and/or Application ID mismatch";
	  } else 
	       res = 200;
	  
	  octstr_destroy(x);
     } else 
	  res = 200;
     return res;
}

Status_t handle_invite_request(RequestInfo_t *ri, Invite_Request_t req)
{
     PGconn *c = ri->c;

     int64_t uid = ri->uid, mygid;
     Octstr *clientid = ri->clientid, *x; 
     Status_t resp;
     InviteUser_Request_t iv = NULL;
     int ret;
     char *err = "", *itype;
     int is_group_invite;
     Dict *d = NULL;
     List *el = NULL, *l = NULL;
     struct QLocalUser_t *localids = NULL;
     int lcount = 0, code = 200;
     long validity;
     time_t expiryt;
     Recipient_t tmpr;
     Result_t rs;
     struct QSender_t qs;
     Octstr *msgid = NULL;
     Sender_t sender = NULL;
     
     if (req->sender && 
	 (ret = verify_sender(c, &req->sender, uid,ri->userid, clientid, &mygid, &err)) != 200) {
	  rs = csp_msg_new(Result, NULL, 
				 FV(code,ret), 
				 FV(descr, csp_String_from_cstr(err, Imps_Description)));	  
	  goto done;	  
     }
     
     if (req->sender)
	  sender = csp_msg_copy(req->sender);
     else 
	  sender = make_sender_struct(c, uid, clientid, NULL, NULL);
     
     gw_assert(req->invtype);
     itype = (char *)req->invtype->str;
     is_group_invite =  (strcasecmp(itype, "GR") == 0 ||
			 strcasecmp(itype, "GM") == 0 ||
			 strcasecmp(itype, "EC") == 0 ||
			 strcasecmp(itype, "EG") == 0);
     
     /* some basic checks. */
     if (strcasecmp(itype, "AP") == 0 && req->appid == NULL) {
	  rs = csp_msg_new(Result, NULL, 
				 FV(code,450), 
				 FV(descr, csp_String_from_cstr("Missing ApplicationID", Imps_Description)));	  
	  goto done;	  
     } else if ((strcasecmp(itype, "GM") == 0 ||
		 strcasecmp(itype, "GR") == 0) && req->gid == NULL) {
	  rs = csp_msg_new(Result, NULL, 
				 FV(code,429), 
				 FV(descr, csp_String_from_cstr("Missing GroupID", Imps_Description)));	  
	  goto done;	  
     } else if (strcasecmp(itype, "SC") == 0 && req->url_list == NULL) {
	  rs = csp_msg_new(Result, NULL, 
				 FV(code,400), 
				 FV(descr, csp_String_from_cstr("Missing Content", Imps_Description)));
	  goto done;	  	  
     }
     
     /* Get the list of recipients. */

     FILL_QSENDER(qs,ri->is_ssp, uid, ri->userid, ri->clientid);
     d = queue_split_rcpt(c, qs, req->rcpt, is_group_invite, &localids, &lcount, &el, &sender, ri->is_ssp);

     /* XXX check:
      * - Attempting to do a group invite when not in the group
      * - Using a screen name but not strictly with the group in question.
      */

     /* Build the inviteuser request: 
      * We don't check its validity! If client screws up, that's their problem 
      */
     
     validity = req->valid;
     expiryt = time(NULL) + validity;
     iv = csp_msg_new(InviteUser_Request, NULL,
		      FV(invid, csp_msg_copy(req->invid)),
		      FV(itype, csp_msg_copy(req->invtype)),
		      FV(sender, csp_msg_copy(sender)),
		      FV(rcpt, csp_msg_copy(req->rcpt)),
		      FV(appid, csp_msg_copy(req->appid)),
		      FV(gid, csp_msg_copy(req->gid)),
		      FV(pslist, csp_msg_copy(req->pslist)),
		      FV(url_list, csp_msg_copy(req->url_list)),
		      FV(inote, csp_msg_copy(req->inote)),
		      FV(sname, csp_msg_copy(req->sname)));

     if (csp_msg_field_isset(req, valid))
	  CSP_MSG_SET_FIELD(iv,valid, validity);

     msgid = make_msg_id(c);
    
     /* Send to the foreign recipients (the original request) */
     tmpr = req->rcpt;
     if (d && (l = dict_keys(d)) != NULL)
	  while ((x = gwlist_extract_first(l)) != NULL) {
	       Recipient_t r = dict_get(d, x);
	       
	       req->rcpt = r;
	       
	       /* ignore error for now?? */
	       queue_foreign_msg_add(c, req, sender,
				     uid, clientid ? octstr_get_cstr(clientid) : "",
				     msgid,
				     octstr_get_cstr(x), NULL, ri->ver, expiryt);
	       octstr_destroy(x);
	       }
     gwlist_destroy(l, NULL);
     req->rcpt = tmpr;
     
     /* send to local ones: Don't bother with rcpt  field. It will be fixed at final delivery. */
     lcount = remove_disallowed_local_recipients(c, sender, uid, localids, lcount, el);
     if (localids && lcount > 0) 
	  queue_local_msg_add(c, iv, sender, localids, lcount, 
			      0, msgid, "rcpt",
			      expiryt);
     
     /* report errors here. */
     if (el && gwlist_len(el) > 0) 
	  code = 201;
     else 
	  code = 200;

     rs = csp_msg_new(Result, NULL, 
		      FV(code,code), 
		      FV(descr, csp_String_from_cstr(code == 200 ? "Success" : "Partial Success",
						     Imps_Description)),
		      FV(drlist, el));

     el = NULL; /* used! */
 done:
     resp = csp_msg_new(Status,NULL,  FV(res,rs));	  
          
     octstr_destroy(msgid);
     if (localids)
	  gw_free(localids);
     gwlist_destroy(el, _csp_msg_free);
     dict_destroy(d);
     
     csp_msg_free(iv);
     csp_msg_free(sender);
     
     return resp;
}


Status_t handle_invite_user_response(RequestInfo_t *ri, InviteUser_Response_t req)
{
     PGconn *c = ri->c;

     int64_t uid = ri->uid, mygid;
     Octstr *clientid = ri->clientid, *x; 
     Status_t resp;

     Invite_Response_t ir = NULL;
     int ret;
     char *err = "";

     Dict *d = NULL;
     List *el = NULL, *l = NULL;
     struct QLocalUser_t *localids = NULL;
     int lcount = 0, code = 200;

     time_t expiryt;
     Recipient_t tmpr;
     Result_t rs;
     struct QSender_t qs;
     Octstr *msgid = NULL;
     ResponseNote_t rnote = NULL;
     InviteNote_t inote = NULL;

     
     if (req->sender && 
	 (ret = verify_sender(c, &req->sender, uid, ri->userid, clientid, &mygid, &err)) != 200) {
	  rs = csp_msg_new(Result, NULL, 
				 FV(code,ret), 
				 FV(descr, csp_String_from_cstr(err, Imps_Description)));	  
	  goto done;	  
     }
     

     if (req->rcpt) { /* we don't store invites, so we only route if recipient is given. */
	  /* Get the list of recipients. */
	  Sender_t sender = NULL;

	  if (req->sender)
	       sender = csp_msg_copy(req->sender);
	  else 
	       sender = make_sender_struct(c, uid, clientid, NULL, NULL);
	  

	  qs.type = QLocal_User;
	  qs.u.uid = uid;
	  strncpy(qs.clientid, octstr_get_cstr(ri->clientid), sizeof qs.clientid);
	  d = queue_split_rcpt(c, qs, req->rcpt, (req->sname != NULL), &localids, &lcount, &el, &sender,
			       ri->is_ssp);
     
	  expiryt = time(NULL) + DEFAULT_EXPIRY;
	  if (req->rnote) {
	       if (ri->ver <= CSP_VERSION(1,2)) 
		    rnote = csp_String_from_cstr(req->rnote->str, Imps_ResponseNote);
	       else 
		    inote = csp_String_from_cstr(req->rnote->str, Imps_InviteNote);
	  }
	  
	  ir = csp_msg_new(Invite_Response, NULL,
			   FV(invid, csp_msg_copy(req->invid)),
			   FV(accept, req->accept),
			   FV(sender, sender),
			   FV(rcpt, csp_msg_copy(req->rcpt)),
			   
			   FV(inote, inote),
			   FV(rnote, rnote),
			   FV(sname, csp_msg_copy(req->sname))
	       );
	  
	  msgid = make_msg_id(c);
	  /* Send to the foreign recipients. */
	  tmpr = ir->rcpt;
	  if (d && (l = dict_keys(d)) != NULL)
	       while ((x = gwlist_extract_first(l)) != NULL) {
		    Recipient_t r = dict_get(d, x);
		    
		    ir->rcpt = r;
		    
		    /* ignore error for now?? */
		    queue_foreign_msg_add(c, ir, sender, 
					  uid, clientid ? octstr_get_cstr(clientid) : "",
					  msgid,
					  octstr_get_cstr(x), NULL, ri->ver, expiryt);
		    octstr_destroy(x);
	       }
	  gwlist_destroy(l, NULL);
	  ir->rcpt = tmpr;
	  
	  /* send to local ones: Don't bother with rcpt  field. It will be fixed at final delivery. */
	  lcount = remove_disallowed_local_recipients(c, req->sender, uid, localids, lcount, el);
	  if (localids && lcount > 0) 
	       queue_local_msg_add(c, ir,  sender, localids, lcount, 
				   0, msgid, "rcpt",  expiryt);
     }

     /* report errors here. */
     if (el && gwlist_len(el) > 0) 
	  code = 201;
     else 
	  code = 200;
     
     rs = csp_msg_new(Result, NULL, 
		      FV(code,code), 
		      FV(descr, csp_String_from_cstr(code == 200 ? "Success" : "Partial Success",
						     Imps_Description)),
		      FV(drlist, el));
     
     el = NULL; /* used! */
done:
     resp = csp_msg_new(Status,NULL,  FV(res,rs));	  
          
     octstr_destroy(msgid);
     if (localids)
	  gw_free(localids);
     gwlist_destroy(el, _csp_msg_free);
     dict_destroy(d);
     csp_msg_free(ir);
     
     return resp;
}


Status_t handle_cancel_invite_request(RequestInfo_t *ri, CancelInvite_Request_t req)
{
     PGconn *c = ri->c;

     int64_t uid = ri->uid, mygid;
     Octstr *clientid = ri->clientid, *x; 
     Status_t resp;
     CancelInviteUser_Request_t iv = NULL;
     int ret;
     char *err = "";

     Dict *d = NULL;
     List *el = NULL, *l = NULL;
     struct QLocalUser_t *localids = NULL;
     int lcount = 0, code = 200;

     time_t expiryt;
     Recipient_t tmpr;
     Result_t rs;
     struct QSender_t qs;
     Octstr *msgid = NULL;
     Sender_t sender = NULL;
     
     gw_assert(req);
     
     
     if (req->sender && 
	 (ret = verify_sender(c, &req->sender, uid, ri->userid,clientid, &mygid, &err)) != 200) {
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,ret), 
			   FV(descr, csp_String_from_cstr(err, Imps_Description)));	  
	  goto done;	  
     }

     if (req->sender)
	  sender = csp_msg_copy(req->sender);
     else 
	  sender = make_sender_struct(c, uid, clientid, NULL, NULL);
          
     /* Get the list of recipients. */
     FILL_QSENDER(qs, ri->is_ssp, uid, ri->userid, ri->clientid);
     d = queue_split_rcpt(c, qs, req->rcpt, 0, &localids, &lcount, &el, &sender, ri->is_ssp); /* slight bug: Cancel invite sent to all in group. */

     /* XXX check:
      * - Attempting to do a group invite when not in the group
      * - Using a screen name but not strictly with the group in question.
      */

     /* Build the inviteuser request: 
      * We don't check its validity! If client screws up, that's their problem 
      */
     expiryt = time(NULL) + DEFAULT_EXPIRY;
     iv = csp_msg_new(CancelInviteUser_Request, NULL,
		      FV(invid, csp_msg_copy(req->invid)),
		      
		      FV(sender, csp_msg_copy(sender)),
		      FV(rcpt, csp_msg_copy(req->rcpt)),
		      FV(appid, csp_msg_copy(req->appid)),
		      FV(gid, csp_msg_copy(req->gid)),
		      FV(pslist, csp_msg_copy(req->pslist)),
		      FV(url_list, csp_msg_copy(req->ulist)),
		      FV(inote, csp_msg_copy(req->inote)),
		      FV(sname, csp_msg_copy(req->sname)));

     msgid = make_msg_id(c);
     /* Send to the foreign recipients. */
     tmpr = req->rcpt;
     if (d && (l = dict_keys(d)) != NULL)
	  while ((x = gwlist_extract_first(l)) != NULL) {
	       Recipient_t r = dict_get(d, x);
	       
	       req->rcpt = r;
	       
	       /* ignore error for now?? */
	       queue_foreign_msg_add(c, req, sender, 
				     uid, clientid ? octstr_get_cstr(clientid) : "",
				     msgid, 
				     octstr_get_cstr(x), NULL, ri->ver, expiryt);
	       octstr_destroy(x);
     }
     gwlist_destroy(l, NULL);
     req->rcpt = tmpr;

     /* send to local ones: Don't bother with rcpt  field. It will be fixed at final delivery. */
     if (localids) {
	  lcount = remove_disallowed_local_recipients(c, sender, uid, localids, lcount, el);
	  queue_local_msg_add(c, iv,  sender, localids, lcount, 
			      0, msgid, "rcpt", 
			      expiryt);
     }
     
     /* report errors here. */
     if (el && gwlist_len(el) > 0) 
	  code = 201;
     else 
	  code = 200;

     rs = csp_msg_new(Result, NULL, 
		      FV(code,code), 
		      FV(descr, csp_String_from_cstr("", Imps_Description)),
		      FV(drlist, el));

     el = NULL; /* used! */
 done:
     resp = csp_msg_new(Status,NULL,  FV(res,rs));	  
     
     
     
     octstr_destroy(msgid);
     if (localids)
	  gw_free(localids);
     gwlist_destroy(el, _csp_msg_free);
     dict_destroy(d);
     csp_msg_free(sender);

     return resp;
}

#define VRFYID_RESULT_PUT(code, fld, val) do { \
     		 Octstr *_key = octstr_imm(#code); \
                 _UserResult_t _ur; \
		    if ((_ur = dict_get(d, _key)) == NULL) { \
			 _ur = csp_msg_new(_UserResult, NULL, NULL); \
			 dict_put(d, _key, _ur); \
		    } \
		    if (_ur->fld == NULL) \
                        CSP_MSG_SET_FIELD(_ur, fld, gwlist_create()); \
                    gwlist_append(_ur->fld, (val)); \
        } while (0)
 

Status_t handle_verifyID(RequestInfo_t *ri, VerifyID_Request_t req)
{
     PGconn *c = ri->c;
     PGresult *r;
     int64_t uid = ri->uid;
     int i;
     char tmp1[2*DEFAULT_BUF_LEN+1], tmp2[2*DEFAULT_BUF_LEN+1], tmp3[2*DEFAULT_BUF_LEN + 1];
     char xid[DEFAULT_BUF_LEN+1], xdomain[DEFAULT_BUF_LEN+1];
     Result_t rs = NULL;
     UserID_t u;
     GroupID_t g;
     ContactList_t cl;
     ScreenName_t s;
     Domain_t dm;
     List *drl = NULL, *l = NULL;
     Octstr *x;
     Dict *d = dict_create(7, NULL); /* for keeping track of errors. */
     
     gw_assert(req);
     gw_assert(req->idlist);
     
     /* verify each in turn: contact lists, groups, users, screen names. 
      * for domains: lets just verify DNs exists. 
      */

     for (i = 0; i<gwlist_len(req->idlist->ulist); i++)
	  if ((u = gwlist_get(req->idlist->ulist, i)) != NULL) {
	       char *user = (char *)u->str;
	       int local;
	       
	       extract_id_and_domain(user, xid, xdomain);

	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);

	       if (get_userid(c, tmp1, tmp2, &local) < 0)
		    VRFYID_RESULT_PUT(531, users, csp_msg_copy(u)); /* 531 error, not found */
	       else  /* success, report it. */
		    VRFYID_RESULT_PUT(200, users, csp_msg_copy(u));
	  }

     sprintf(tmp3, " userid = %lld", uid);
     for (i = 0; i<gwlist_len(req->idlist->clist); i++)
	  if ((cl = gwlist_get(req->idlist->clist, i)) != NULL) {
	       char *x = (char *)cl->str;
	       int local;
	       
	       extract_id_and_domain(x, xid, xdomain);

	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       
	       if (get_contactlist(c, tmp1, tmp2, tmp3, &local) < 0)
		    VRFYID_RESULT_PUT(700, clist, csp_msg_copy(cl));
	       else  /* success, report it. */
		    VRFYID_RESULT_PUT(200, clist, csp_msg_copy(cl));
	  }
     
     for (i = 0; i<gwlist_len(req->idlist->glist); i++)
	  if ((g = gwlist_get(req->idlist->glist, i)) != NULL) {
	       char *x = (char *)g->str;
	       int local;
	       
	       extract_id_and_domain(x, xid, xdomain);

	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       
	       if (get_groupid(c, tmp1, tmp2, &local) < 0)
		    VRFYID_RESULT_PUT(800, grps, csp_msg_copy(g));
	       else  /* success, report it. */
		    VRFYID_RESULT_PUT(200, grps, csp_msg_copy(g));
	  }

     for (i = 0; i<gwlist_len(req->idlist->slist); i++)
	  if ((s = gwlist_get(req->idlist->slist, i)) != NULL && s->gid != NULL && s->sname != NULL) {
	       GroupID_t g = s->gid;
	       char *x = (char *)g->str;
	       int local;
	       int64_t xgid;
	       
	       extract_id_and_domain(x, xid, xdomain);

	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       
	       if ((xgid = get_groupid(c, tmp1, tmp2, &local)) < 0)
		    VRFYID_RESULT_PUT(901, snames, csp_msg_copy(s));
	       else  { /* look for the screen name. Do we check if user is in group?? */
		    char cmd[512];
		    char *sname = (char *)s->sname->str;
		    
		    PQ_ESCAPE_STR_LOWER(c, sname, tmp3);
	       
		    sprintf(cmd, "SELECT id FROM group_members WHERE groupid = %lld AND screen_name='%.128s' AND "
			    "%lld IN (SELECT local_userid FROM group_members WHERE groupid = %lld AND local_userid = %lld)",
			    xgid, tmp3, uid, xgid, uid);
		    r = PQexec(c, cmd);
		     
		    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0)
			 VRFYID_RESULT_PUT(200, snames, csp_msg_copy(s));
		    else 
			 VRFYID_RESULT_PUT(901, snames, csp_msg_copy(s));
		    PQclear(r);
	       }
	  }
     
     for (i = 0; i<gwlist_len(req->idlist->dlist); i++)
	  if ((dm = gwlist_get(req->idlist->dlist, i)) != NULL) {
	       char *x = (char *)dm->str;
	       
	       if (res_query(x, C_IN, T_ANY, (void *)tmp1, sizeof tmp1) < 0)
		    VRFYID_RESULT_PUT(404, domains, csp_msg_copy(dm));
	       else 
		    VRFYID_RESULT_PUT(200, domains, csp_msg_copy(dm));
	  }
     
     drl = gwlist_create();
     if ((l = dict_keys(d)) != NULL)
	  while ((x = gwlist_extract_first(l)) != NULL) {
	       _UserResult_t ur = dict_get(d, x);
	       int code = atoi(octstr_get_cstr(x));
	       DetailedResult_t dr = csp_msg_new(DetailedResult, NULL, 
						 FV(code, code),
						 UFV(details, Imps__UserResult, ur));
	       gwlist_append(drl, dr);	       
	  }
     rs = csp_msg_new(Result, NULL, 
		      FV(code,201),
		      FV(descr, csp_String_from_cstr("Partial success", Imps_Description)),
		      FV(drlist, drl));
     
     dict_destroy(d);
     gwlist_destroy(l, (void *)octstr_destroy);
     return  csp_msg_new(Status,NULL,  FV(res,rs));	  
}

void *handle_poll_req(RequestInfo_t *ri, void *unused)
{
     time_t t = time(NULL); /* use time to make a transid. */
     Octstr *x  = octstr_format("%ld %S %s",  t, ri->clientid, ri->xsessid);
     void *msg = get_pending_msg(ri);
     
     if (ri->transid == NULL) /* which it should be */
	  ri->transid = md5digest(x);
     else 
	  warning(0, "polling request with non-empty transid?? Sessid: %s", ri->xsessid);
     
     octstr_destroy(x);
     
     return msg;
}

GetSPInfo_Response_t handle_get_spinfo(RequestInfo_t *ri, GetSPInfo_Request_t req)
{
     Octstr *name = get_setting(ri->c, "name");
     Octstr *logo = get_setting(ri->c, "logo");
     Octstr *logo_ctype = get_setting(ri->c, "logo-content-type");
     Octstr *descr = get_setting(ri->c, "description");
     Octstr *url = get_setting(ri->c, "url");
     GetSPInfo_Response_t resp;
     Logo_t xlogo;
     
     if (logo_ctype == NULL)
	  logo_ctype = octstr_imm("image/jpeg"); /* default is JPEG. */
     if (name == NULL)
	  name = octstr_imm(SYSTEM_NAME);
     if (url == NULL)
	  url = octstr_imm(SYSTEM_HOME_URL);
     if (descr == NULL)
	  descr = octstr_imm(SYSTEM_DESCR);
     
     if (logo) { /* handle encoding issue for the message. */
	  ContentData_t ldata = csp_String_from_bstr(logo, Imps_ContentData);
	  ContentEncoding_t lenc = NULL;
	  int mod;
	  
	  
	  mod = do_conditional_msg_encoding(&ldata, ri->binary, &lenc);
	  xlogo = csp_msg_new(Logo, NULL,
			      FV(ctype, csp_String_from_bstr(logo_ctype, Imps_ContentType)),
			      FV(encoding, lenc),
			      FV(data, ldata));	  
     } else 
	  xlogo = NULL;
     
     resp = csp_msg_new(GetSPInfo_Response, NULL,
			FV(id, csp_msg_copy(req->id)),
			FV(name, csp_String_from_bstr(name, Imps_Name)),
			FV(logo, xlogo),
			FV(descr, csp_String_from_bstr(descr, Imps_Description)),
			FV(url, csp_String_from_bstr(url, Imps_URL)));
     
     octstr_destroy(name);
     octstr_destroy(logo);
     octstr_destroy(logo_ctype);
     octstr_destroy(descr);
     octstr_destroy(url);

     return resp;
}
