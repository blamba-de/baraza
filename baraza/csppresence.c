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
#include "csppresence.h"
#include "pgconnpool.h"
#include "utils.h"
#include "mqueue.h"


#if 0
static int pa_version (char *xmlns)
{
     const char *endmarker = "PA";
     
     char *p;
     int major = 1, minor = 0;
     
     if (xmlns == NULL)
	  return 0x10;
     else if ((p = strstr(xmlns, endmarker)) != NULL)
	  p += strlen(endmarker);
     else 
	  return 0x10; /* assume version 1.0 */
     
     sscanf(p, "%d.%d", &major, &minor);
     return ((major&0x0F)<<4) | (minor&0x0F);     
}

#endif

GetList_Response_t handle_get_list(RequestInfo_t *ri, void *unused)
{
     char cmd[512];
     GetList_Response_t resp;
     DefaultContactList_t dcontact = NULL;
     int64_t uid = ri->uid;
     PGresult *r;
     int i, n;
     List *cl = NULL;
     PGconn *c = ri->c;
     List *clist_11; /* v1.1 uses a different format. */
     ContactListIDList_t clist;
     
     sprintf(cmd, "SELECT cid, domain, isdefault FROM contactlists WHERE userid=%lld", uid);

     r = PQexec(c, cmd);
     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ?  PQntuples(r) : 0;
     
     cl = gwlist_create();
     for (i = 0; i<n; i++) {
	  char *u = PQgetvalue(r, i, 0);
	  char *d = PQgetvalue(r, i, 1);
	  char *v = PQgetvalue(r, i, 2);
	  int has_domain = (d && d[0]);
	  int isdefault = _str2bool(v);
	  Octstr *clist = octstr_format("wv:%s%s%s", 
					u, 
					has_domain ? "@" : "",
					has_domain  ? d : "");
	  
	  if (isdefault && dcontact == NULL) { /* only one default list */
	       dcontact = csp_String_from_bstr(clist, Imps_DefaultContactList);
	       if (ri->ver > CSP_VERSION(1,1)) goto loop; /* default is not included */
	  }
	  
	  gwlist_append(cl, csp_String_from_bstr(clist, Imps_ContactList));
	  
     loop:
	  octstr_destroy(clist);
     }

     PQclear(r);

     
     if (ri->ver <= CSP_VERSION(1,2)) {
	  clist_11 = cl;
	  clist = NULL;
     } else  {
	  clist = csp_msg_new(ContactListIDList, NULL, 
			      FV(clist, cl));
	  clist_11 = NULL;
     }
     
     resp = csp_msg_new(GetList_Response, NULL,
			FV(clist, clist),
			FV(clist_11, clist_11),
			FV(dlist, dcontact));     
     return resp;
}

static List *add_nicks_to_clist(PGconn *c, List *nl, int64_t cid, RequestInfo_t *ri, int auto_attribs)
{
     int i, n;
     _NickU_t nu;
     List *l = gwlist_create();
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char cmd[512], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN], tmp3[DEFAULT_BUF_LEN];
     char cmemb[DEFAULT_BUF_LEN];
     PGresult *r;
     
     for (i = 0, n = gwlist_len(nl); i < n; i++) 
	  if ((nu = gwlist_get(nl, i)) != NULL) {
	       UserID_t u;
	       Name_t nm;
	       int islocal;
	       int64_t xuid;
	       
	       if (nu->u.typ == Imps_NickName) {
		    NickName_t x = nu->u.val;
		    u = (x) ? x->user : NULL;
		    nm = (x) ? x->name : NULL;
	       } else {
		    u = nu->u.val;
		    nm = NULL;
	       }
	       if (u == NULL) {
		    void *rs = csp_msg_new(DetailedResult, NULL, 
					   FV(code,531), 
					   FV(descr, csp_String_from_cstr("Missing User-ID",
									  Imps_Description)));	  
		    gwlist_append(l, rs);
		    continue;			 
	       }
		    
	       extract_id_and_domain((char *)u->str, xid, xdomain);
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       xuid = get_userid(c, tmp1, tmp2, &islocal);
	       
	       if (xuid < 0 && islocal) {
		    Octstr *_x = octstr_format("Unknown UserID: %s", (char *)u->str);
		    void *rs = csp_msg_new(DetailedResult, NULL, 
					   FV(code,531), 
					   FV(descr, csp_String_from_bstr(_x,
									  Imps_Description)));	  
		    gwlist_append(l, rs);
		    octstr_destroy(_x);
		    continue;
	       }
	       	      
	       PQ_ESCAPE_STR(c, nm ? (char *)nm->str : "", tmp3);
	       if (xuid >= 0)
		    sprintf(cmemb, "%lld", xuid);
	       else 
		    sprintf(cmemb, "'%.64s%s%.64s'", tmp1, (tmp2[0]) ? "@" : "", tmp2);
			    
	       /* first check to see if the contact exists already: in which case an update is done */
	       sprintf(cmd, "SELECT id FROM contactlist_members WHERE %s = %s AND cid = %lld ",
		       xuid >= 0 ? "local_userid" : "foreign_userid",
		       cmemb, cid);
	       r = PQexec(c, cmd);
	       if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
		    int64_t x = strtoull(PQgetvalue(r, 0, 0), NULL, 10);		    
		    sprintf(cmd, "UPDATE contactlist_members SET cname='%.128s' WHERE id = %lld",
			    tmp3, x);
	       } else 
		    sprintf(cmd, "INSERT INTO contactlist_members (cid, %s, cname) VALUES "
			    "(%lld, %s, '%.128s')", 
			    xuid >= 0 ? "local_userid" : "foreign_userid",
			    cid, cmemb, tmp3);
	       PQclear(r);
	       
	       r = PQexec(c, cmd);
	       if (PQresultStatus(r) != PGRES_COMMAND_OK) 
		    warning(0, "failed to add/update contact: %s", PQerrorMessage(c));
	       PQclear(r);		    		    
	       
	       if (auto_attribs) { /* auto-subscribe. */
		    UserIDList_t ul = csp_msg_new(UserIDList, NULL,
						  FV(ulist, gwlist_create_ex(csp_msg_copy(u))));
		    SubscribePresence_Request_t sp = csp_msg_new(SubscribePresence_Request, NULL,
								 FV(uidlist, ul),
								 FV(plist, 
								    csp_msg_new(PresenceSubList, NULL, NULL)));
		    void *pres;
		    /* now kludge the requested bits. XXX caution */
		    MSG_SET_BITS(sp->plist, auto_attribs);
		    pres = handle_pres_subscribe(ri, sp); /* subscribe for this user. */
		    csp_msg_free(pres);
		    csp_msg_free(sp);
	       }
	  }
     
     return l;	  
}

/* for v1.2 or less, return status, for v1.3 return CreateList_Response_t. */
CreateList_Response_t handle_create_list(RequestInfo_t *ri, CreateList_Request_t req )
{
     char xuser[DEFAULT_BUF_LEN], xudomain[DEFAULT_BUF_LEN];
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN], *p, *fname = "", *isdefault = "f";
     Property_t pdefault = NULL;          
     char cmd[512], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN], tmp3[DEFAULT_BUF_LEN];
     char tmp4[DEFAULT_BUF_LEN];
     CreateList_Response_t resp = NULL;     
     List *el = NULL;
     Property_t pp;

     int64_t uid = ri->uid, cid;
     PGresult *r;
     int i, n, x;
     
     PGconn *c = ri->c;

     gw_assert(req);
     
     if (req->clist == NULL)
	  goto done; /* bad request. */

     extract_id_and_domain((char *)req->clist->str, xid, xdomain);
     
     extract_id_and_domain(octstr_get_cstr(ri->userid), xuser, xudomain);
     /* verify contact list format. */
     n = strlen(xuser);
     if (strncmp(xudomain, xdomain, sizeof xudomain) != 0 || 
	 (p = strstr(xid, xuser)) != xid ||
	 xid[n] != '/' || 
	 isvalid_nameid(xid + n + 1) != 1) { /* invalid format. */
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,752), 
				 FV(descr, csp_String_from_cstr("Invalid contactlist ID format", 
								Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  
	  goto done;
     }
     
     if (req->clist_prop && req->clist_prop->plist) 
	  for (i = 0, n = gwlist_len(req->clist_prop->plist); i<n; i++) 
	       if ((pp = gwlist_get(req->clist_prop->plist, i)) != NULL) 
		    if (pp->name && pp->value) {
			 if (strcasecmp((char *)pp->name->str, "DisplayName") == 0)
			      fname = (char *)pp->value->str;
			 else if (strcasecmp((char *)pp->name->str, "Default") == 0) {
			      isdefault = (char *)pp->value->str;			
			      pdefault = pp;
			 }
		    }
     PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
     PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
     PQ_ESCAPE_STR(c, fname, tmp3);
     
     /* A list is the default if none is the default, or if it is designated default. */
     sprintf(tmp4, "%s OR (SELECT count(*) = 0 FROM contactlists WHERE userid = %lld)", 
	     _str2bool(isdefault) ? "true" : "false",
	     uid);
     
     sprintf(cmd, "INSERT INTO contactlists (cid,domain,userid,friendly_name,isdefault) VALUES "
	     "(lower('%.128s'), lower('%.128s'), %lld, '%.128s', %s) RETURNING id, isdefault", 
	     tmp1, tmp2, uid, tmp3, tmp4);
     r = PQexec(c, cmd);

     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,701), 
				 FV(descr, csp_String_from_cstr("Contact list exists", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  
	  warning(0, "createlist [%s]: %s", ri->xsessid, PQerrorMessage(c));
	  PQclear(r);
	  goto done;
     }

     cid = strtoull(PQgetvalue(r, 0,0), NULL, 10);
     p = PQgetvalue(r, 0, 1);
     x = _str2bool(p);
     if (pdefault) { 
	  pdefault = csp_msg_copy(pdefault);
	  pdefault->value->str[0] = x ? 'T' : 'F';
     } else 
	  pdefault = csp_msg_new(Property, NULL,
				 FV(name, csp_String_from_cstr("Default", Imps_Name)),
				 FV(value, csp_String_from_cstr(x ? "T" : "F", Imps_Value)));
     PQclear(r);
     if (x)  {/* It is a default: clear all others. */
	  sprintf(cmd, "UPDATE contactlists SET isdefault = false WHERE userid = %lld AND id <> %lld",
		  uid, cid);
	  r = PQexec(c, cmd);
	  PQclear(r);
     }
     
     /* Now add the members, if any. */
     if (req->nlist)
	  el =  add_nicks_to_clist(c, req->nlist->nlist, cid, ri, 0);
     
     if ((el && gwlist_len(el) > 0) || ri->ver < CSP_VERSION(1,3)) {
	  int code = (el && gwlist_len(el) > 0) ? 201 : 200;
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,code), 
				 FV(drlist, el),
				 FV(descr, csp_String_from_cstr(code == 200 ? "Success" : "Partial Success",
								Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  	  
	  el = NULL;
     } else {
	  ContactListProperties_t cp = csp_msg_new(ContactListProperties, NULL,
						   FV(plist, gwlist_create()));
	  gwlist_append(cp->plist, pdefault);
	  gwlist_append(cp->plist, 
			csp_msg_new(Property, NULL,
				    FV(name, csp_String_from_cstr("DisplayName", Imps_Name)),
				    FV(value, csp_String_from_cstr(fname, Imps_Value))));
	  resp = csp_msg_new(CreateList_Response, NULL, 
			     FV(clist, csp_msg_copy(req->clist)),
			     FV(clist_prop, cp));
	  pdefault = NULL; /* so it is not freed below! */
     }
 done:

     csp_msg_free(pdefault); 
     gwlist_destroy(el, _csp_msg_free);
     return resp;
}

Status_t handle_delete_list(RequestInfo_t *ri, DeleteList_Request_t req)
{
     int64_t cid;
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char cmd[512], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN];
     char *p;
     int isdefault;
     int64_t uid = ri->uid;
     PGresult *r;
     Result_t rs;
     int attribs = 0, islocal = 0;
     
     PGconn *c = ri->c;

     gw_assert(req);

     if (req->clist == NULL) {
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,402), 
			   FV(descr, csp_String_from_cstr("Invalid Request", Imps_Description)));	  	  
	  goto done; /* bad request. */
     }

     extract_id_and_domain((char *)req->clist->str, xid, xdomain);
     
     PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
     PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
     
     cid = get_contactlist(c, xid, xdomain, NULL, &islocal);
     if (cid < 0) {
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,700), 
			   FV(descr, csp_String_from_cstr("No such contact list", Imps_Description)));	  
	  
	  goto done;
     } 

     /* get the auto_attributes for this list: Note we ensure it is user owned! */
     
     sprintf(cmd, "SELECT presence_attribs_auto_subscribe FROM contactlists WHERE id = %lld AND userid = %lld", cid, uid);
     r = PQexec(c, cmd);
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  char *s = PQgetvalue(r, 0, 0);
	  attribs = s  ? strtoul(s, NULL, 10)  : 0;
     }
     PQclear(r);
     
     if (attribs) { /* Handle auto unsubscribe. */
	  int i, n;
	  sprintf(cmd, "SELECT localuserid, foreign_userid FROM contactlist_members_view WHERE cid = %lld", cid);
	  r = PQexec(c, cmd);
	  n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
	  
	  for (i = 0; i<n; i++) {
		    char *xu = PQgetvalue(r, i, 0);
		    char *fu = PQgetvalue(r, i, 1);
		    UserID_t u = csp_String_from_cstr(xu && xu[0] ? xu : fu, Imps_UserID);
		    
		    UserIDList_t ul = csp_msg_new(UserIDList, NULL,
						  FV(ulist, gwlist_create_ex(u)));
		    UnsubscribePresence_Request_t up = csp_msg_new(UnsubscribePresence_Request, NULL,
								   FV(uidlist, ul));
		    void *pres = handle_pres_unsubscribe(ri, up);
		    csp_msg_free(pres);
		    csp_msg_free(up);
	  }
	  PQclear(r);
     }
     
     
     sprintf(cmd, 
	     "DELETE FROM contactlists WHERE userid=%lld AND id=%lld RETURNING isdefault",
	     uid, cid);
	
     r = PQexec(c, cmd);
     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) {
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,700), 
			   FV(descr, csp_String_from_cstr("No such contact list", Imps_Description)));	  
	  PQclear(r);
	  goto done;
     }
     p = PQgetvalue(r, 0, 0);
     isdefault = _str2bool(p);
     PQclear(r);

     if (isdefault) { /* if we deleted default one, then choose another at random to be default. */	  
	  sprintf(cmd, "UPDATE contactlists SET isdefault = true WHERE id = "
		  "(SELECT id from contactlists WHERE userid=%lld LIMIT 1)", uid);
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_COMMAND_OK) {
	       warning(0, "failed to choose new default contact list in session[%s]: %s",
		       ri->xsessid, PQerrorMessage(c));
	       rs = csp_msg_new(Result, NULL, 
				FV(code,500), 
				FV(descr, csp_String_from_cstr("Internal Error", Imps_Description)));
	       PQclear(r);
	       goto done;
	  }
	  PQclear(r);
     }
     
     rs = csp_msg_new(Result, NULL, 
		      FV(code,200), 
		      FV(descr, csp_String_from_cstr("Success", Imps_Description)));	       
 done:
     ;
     return csp_msg_new(Status, NULL, FV(res,rs));;
}

ListManage_Response_t handle_manage_list(RequestInfo_t *ri, ListManage_Request_t req)
{
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];

     char cmd[512], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN];
     int attribs = 0;
     ListManage_Response_t resp = NULL;     
     ContactListProperties_t cpresp = NULL;
     List *el = NULL;

     NickList_t nl = NULL;
     int64_t cid;
     PGresult *r;
     int  islocal;
     Result_t res;
     int code;
     PGconn *c = ri->c;
     
     gw_assert(req);
     
     
     if (req->clist == NULL)
	  goto done; /* bad request. */
     
     extract_id_and_domain(csp_String_to_cstr(req->clist), xid, xdomain);
     
     PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
     PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);

     /* Get the info about the list */
     
     cid = get_contactlist(c, xid, xdomain, NULL, &islocal);
     if (cid < 0) {
	  void *rs = csp_msg_new(Result, NULL, 
				 FV(code,700), 
				 FV(descr, csp_String_from_cstr("No such contact list", Imps_Description)));	  
	  resp = (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  
	  goto done;
     } else { /* Get auto-subscribe attributes. */
	  sprintf(cmd, "SELECT presence_attribs_auto_subscribe FROM contactlists WHERE id = %lld", cid);
	  r = PQexec(c, cmd);
	  if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	       char *s = PQgetvalue(r, 0, 0);
	       attribs = s  ? strtoul(s, NULL, 10)  : 0;
	  }
	  PQclear(r);
     }
     
     if (req->u.typ == Imps_AddNickList) {
	  List * nul = ((AddNickList_t)req->u.val)->nlist;
	  if (nul)
	       el = add_nicks_to_clist(c, nul, cid, ri, attribs);	       
     } else if (req->u.typ == Imps_RemoveNickList) {
	  List *ul = ((RemoveNickList_t)req->u.val)->ulist;
	  UserID_t u;
	  int i, n;
	  for (i = 0, n = gwlist_len(ul); i<n; i++) 
	       if ((u = gwlist_get(ul, i)) != NULL) {
		    int64_t xuid;
		    
		    extract_id_and_domain((char *)u->str, xid, xdomain);		    
		    PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
		    PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
		    xuid = get_userid(c, tmp1, tmp2, &islocal);

		    if (xuid >= 0)
			 sprintf(cmd, "DELETE from contactlist_members WHERE cid = %lld AND local_userid = %lld",
				 cid, xuid);
		    else 
			 sprintf(cmd, "DELETE FROM contactlist_members WHERE cid = %lld AND "
				 "foreign_userid = '%.64s%s%.64s'", cid, tmp1, (tmp2[0]) ? "@" : "", tmp2);
		    r = PQexec(c, cmd);
		    PQclear(r); /* don't care about result. */		    

		    if (attribs) { /* unsubscribe to it. */
			 UserIDList_t ul = csp_msg_new(UserIDList, NULL,
						       FV(ulist, gwlist_create_ex(csp_msg_copy(u))));
			 UnsubscribePresence_Request_t up = csp_msg_new(UnsubscribePresence_Request, NULL,
									FV(uidlist, ul));
			 void *pres = handle_pres_unsubscribe(ri, up);
			 csp_msg_free(pres);
			 csp_msg_free(up);
		    }
	       }
     }  else if (req->u.typ == Imps_ContactListProperties) {
	  ContactListProperties_t cp = req->u.val;
	  Property_t pp;
	  char *fname = NULL, *p;
	  int  xdefault, i, n;
	  char cond1[DEFAULT_BUF_LEN], cond2[16], *isdefault = NULL;
	  
	  for (i = 0, n = gwlist_len(cp->plist); i<n; i++) 
	       if ((pp = gwlist_get(cp->plist, i)) != NULL) 
		    if (pp->name && pp->value) {
			 if (strcasecmp((char *)pp->name->str, "DisplayName") == 0)
			      fname = (char *)pp->value->str;
			 else if (strcasecmp((char *)pp->name->str, "Default") == 0) 
			      isdefault = (char *)pp->value->str;			
		    }
	  if (fname) {
	       PQ_ESCAPE_STR(c, fname, tmp1);
	       sprintf(cond1, ", friendly_name='%.102s' ", tmp1);
	  }  else 
	       cond1[0] = 0;
	  if (isdefault && _str2bool(isdefault)) /* only allowed to change to true. */ 
	       sprintf(cond2, ", isdefault=true");
	  else 
	       cond2[0] = 0;

	  sprintf(cmd, "UPDATE contactlists SET descr=descr %s %s WHERE id = %lld RETURNING isdefault, friendly_name",
		  cond1, cond2, cid);
	  
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) {
	       DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
						 FV(code, 500),
						 FV(descr, csp_String_from_cstr("Failed to update contact list!",
										Imps_Description)));
	       gwlist_append(el, dr);
	       warning(0, "update of contact list failed for session %s: %s", 
		       ri->xsessid, PQerrorMessage(c));
	       PQclear(r);
	       goto done;
	  }

	  cpresp = csp_msg_new(ContactListProperties, NULL,
			       FV(plist, gwlist_create()));
	  
	  /* make and add properties for name and is default */
	  fname = PQgetvalue(r, 0, 1);
	  p = PQgetvalue(r, 0, 0);
	  xdefault = _str2bool(p);
	  pp = 	csp_msg_new(Property, NULL,
			    FV(name, csp_String_from_cstr("DisplayName", Imps_Name)),
			    FV(value, csp_String_from_cstr(fname, Imps_Value)));
	  gwlist_append(cpresp->plist, pp);
	  pp = 	csp_msg_new(Property, NULL,
			    FV(name, csp_String_from_cstr("Default", Imps_Name)),
			    FV(value, csp_String_from_cstr(xdefault ? "T" : "F", Imps_Value)));
	  gwlist_append(cpresp->plist, pp);
	  
	  PQclear(r);
	  if (xdefault && isdefault && _str2bool(isdefault))  {/* default list changed */ 
	       sprintf(cmd, "UPDATE contactlists SET isdefault = false WHERE id <> %lld", cid);
	       r = PQexec(c, cmd);
	       
	       if (PQresultStatus(r) != PGRES_COMMAND_OK) {
		    warning(0, "failed to unset old default contact list in session[%s]: %s",
			    ri->xsessid, PQerrorMessage(c));
		    DetailedResult_t rs = csp_msg_new(DetailedResult, NULL, 
						      FV(code,500), 
						      FV(descr, csp_String_from_cstr("Internal Error", 
										     Imps_Description)));
		    gwlist_append(el, rs);
		    PQclear(r);
		    goto done;
	       }
	       PQclear(r);
	  }
	  
	       
     } 
     
     if (req->rl || ri->ver <= CSP_VERSION(1,1)) { /* generate the list of members. */
	  _NickU_t nu;
	  int i,n;

	  nl = csp_msg_new(NickList, NULL, FV(nlist,gwlist_create()));	  
	  sprintf(cmd, "SELECT localuserid,foreign_userid,cname FROM "
		  " contactlist_members_view WHERE cid=%lld", cid);
	  r = PQexec(c, cmd);
	  if (PQresultStatus(r) != PGRES_TUPLES_OK) {
	       warning(0, "failed to queury contact list members in session[%s]: %s",
		       ri->xsessid, PQerrorMessage(c));
	       DetailedResult_t rs = csp_msg_new(DetailedResult, NULL, 
						 FV(code,500), 
						 FV(descr, csp_String_from_cstr("Internal Error", 
										Imps_Description)));
	       gwlist_append(el, rs);
	       PQclear(r);
	       goto done;	       
	  }
	  
	  for (i = 0, n = PQntuples(r); i<n; i++) {
	       char *u = PQgetvalue(r, i, 0);
	       char *f = PQgetvalue(r, i, 1);
	       char *nm = PQgetvalue(r, i, 2);
	       NickName_t nn = csp_msg_new(NickName, NULL, 
					   FV(name, csp_String_from_cstr(nm ? nm : "", Imps_Name)),
					   FV(user, csp_String_from_cstr(u && u[0] ? u : f, Imps_UserID)));

	       nu = csp_msg_new(_NickU, NULL, 
				UFV(u, Imps_NickName, nn));
	       gwlist_append(nl->nlist, nu);
	  }
	  PQclear(r);
     }
     code = (el && gwlist_len(el) > 0) ? 201 : 200;
     res = csp_msg_new(Result, NULL,
		       FV(code, code),
		       FV(descr, csp_String_from_cstr(code == 200 ? "Success" : "Partial Success", 
						      Imps_Description)),
		       FV(drlist, el));
     if (nl && gwlist_len(nl->nlist) == 0) {
	  csp_msg_free(nl);
	  nl = NULL;
     }
     resp = csp_msg_new(ListManage_Response, NULL, 
			FV(res, res),
			FV(nlist, nl),
			FV(clist, cpresp));
 done:
     
     return resp;
}

static void fixup_server_pres(PresenceSubList_t p, char *client, char *client_type, char *alias)
{
     Octstr *xclnt = octstr_create(client ? client : "");
     ClientID_t clnt = NULL;
     ApplicationID_t appid = NULL;
     
     
     parse_clientid(xclnt, &clnt, &appid);
     
     /* fix up online status */
     if (p) {
	  
	  OnlineStatus_t os = csp_msg_new(OnlineStatus, NULL,
					  FV(qual, 1),
					  FV(pvalue, csp_String_from_cstr("T", 
									  Imps_PresenceValue)),
					  FV(client, clnt));
	  int i, n;
	  
	  if (csp_msg_field_isset(p, ostatus)) {
	       gwlist_destroy(p->ostatus, _csp_msg_free);
	       csp_msg_unset_fieldset(p,"ostatus");
	  }
	  
	  CSP_MSG_SET_FIELD(p,ostatus, gwlist_create_ex(os));

	  /* fixup client type... */
	  if (csp_msg_field_isset(p, cinfo) == 0) 
	       CSP_MSG_SET_FIELD(p, cinfo, gwlist_create());
	  if (gwlist_len(p->cinfo) == 0) {
	       void *x = csp_msg_new(ClientInfo, NULL,
				   FV(qual,  1),
				   FV(ctype, csp_String_from_cstr(client_type, 
								  Imps_ClientType)),
				   FV(client, csp_msg_copy(clnt)));
	       gwlist_append(p->cinfo, x);
	  } else {
	       ClientInfo_t  cinfo = gwlist_get(p->cinfo, 0);
	       if (csp_msg_field_isset(cinfo, client) == 0)
		    CSP_MSG_SET_FIELD(cinfo, client, csp_msg_copy(clnt));
	       
	       if (csp_msg_field_isset(cinfo, ctype) == 0)
		    CSP_MSG_SET_FIELD(cinfo, ctype, 
				      csp_String_from_cstr(client_type, 
							   Imps_ClientType));	       
	  }
	  
	  if (alias && alias[0] && csp_msg_field_isset(p, alias) == 0) { /* Set the alias field */
	       Alias_t x =  csp_msg_new(Alias, NULL,
					FV(qual, 1),
					FV(pvalue, csp_String_from_cstr(alias, 
									Imps_PresenceValue)));
	       CSP_MSG_SET_FIELD(p,alias, x);
	  }
	  /* finally pass through all the ones that are lists, and fixup client info */
	  n = csp_type_field_count(Imps_PresenceSubList);
	  for (i = 0; i<n; i++)
	       if (MSG_GET_BIT(p, i) && 
		   struct_types[Imps_PresenceSubList][i].nature == IList) {
		    int etype = struct_types[Imps_PresenceSubList][i].type;
		    int cfnum = csp_get_field_num_from_type(etype,client);
		    List *l = csp_msg_get_field_value(p, i);
		    int j, m;
		    
		    if (cfnum >= 0) /* each list should really be of length 1.. */
			 for (j = 0, m = gwlist_len(l); j<m; j++) {
			      void *obj = gwlist_get(l, j);
			      
			      if (!csp_get_nth_field_isset(obj, cfnum)) 
				   csp_msg_set_field_value(obj, cfnum, 
							   csp_msg_copy(clnt));
			 }
		    
	       }
     }
     
     octstr_destroy(xclnt);
     csp_msg_free(appid);          
}

/* Make basic presence info for a Bot: Always reported as online. */
static PresenceSubList_t make_pres_for_bot(char *url, char *name)
{
     URL_t x = csp_String_from_cstr(url ? url : "x", Imps_URL);
     ClientID_t clnt = csp_msg_new(ClientID, NULL, FV(url, x));
     OnlineStatus_t os = csp_msg_new(OnlineStatus, NULL,
				     FV(qual, 1),
				     FV(pvalue, csp_String_from_cstr("T", 
								     Imps_PresenceValue)),
				     FV(client, clnt));
     ClientInfo_t cinfo = csp_msg_new(ClientInfo, NULL,
				      FV(qual, 1), 
				      FV(ctype, csp_String_from_cstr("COMPUTER", Imps_ClientType)),
				      FV(devmanufacturer, csp_String_from_cstr(SYSTEM_NAME "Bot", 
									       Imps_DevManufacturer)),
				      FV(cproducer, csp_String_from_cstr(name ? name : "Bot", 
									Imps_ClientProducer)));
     FreeTextLocation_t ft = url ? csp_msg_new(FreeTextLocation, NULL,
					       FV(qual, 1), 					 
					       FV(pvalue, csp_String_from_cstr(url, 
									       Imps_PresenceValue))) : 
	  NULL;
     UserAvailability_t ua = csp_msg_new(UserAvailability, NULL,
					 FV(qual, 1), 
					 FV(pvalue, csp_String_from_cstr("AVAILABLE", 
									 Imps_PresenceValue)));
     StatusText_t st = csp_msg_new(StatusText, NULL,
				   FV(qual, 1), 
				   FV(pvalue, csp_String_from_cstr(name && name[0] ? name : SYSTEM_SHORT_HOME " Bot", 
								   Imps_PresenceValue)));	       
     Alias_t al = csp_msg_new(Alias, NULL,
			      FV(qual, 1), 
			      FV(pvalue, csp_String_from_cstr(name && name[0] ? name :  SYSTEM_SHORT_HOME  " Bot", 
							      Imps_PresenceValue)));	       
     return csp_msg_new(PresenceSubList, NULL,
			FV(ostatus,gwlist_create_ex(os)),
			FV(cinfo, gwlist_create_ex(cinfo)),
			FV(txtloc, gwlist_create_ex(ft)),
			FV(avail, ua),
			FV(status_txt, st),
			FV(alias, al));          
}

static PresenceSubList_t get_pres(PGconn *c, int64_t uid, int64_t sessid, int csp_version)
{
     int i, n, fcount;
     char cmd[512], tmp1[DEFAULT_BUF_LEN],  tmp2[DEFAULT_BUF_LEN], *last_cid = NULL;
     PGresult *r;
     
     PresenceSubList_t p;
     
     if (is_bot(c, uid, tmp1, tmp2))
	  return make_pres_for_bot(tmp1, tmp2);
     
     p = csp_msg_new(PresenceSubList, NULL, NULL);
     /* are we getting session specific or all ? */
     if (sessid >= 0) 
	  sprintf(tmp1, " AND id = %lld", sessid);
     else 
	  tmp1[0] = 0;
     
     /* get all the individual presences, and then union them. The ordering ensures we get latest first. */
     sprintf(cmd, "SELECT presence,clientid,client_type,nickname  FROM session_users WHERE userid = %lld %s " 
	     " ORDER BY last_pres_update DESC", uid, tmp1);

     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
	  /* Not online. */
	  OnlineStatus_t os = csp_msg_new(OnlineStatus, NULL,
					  FV(qual, 1),
					  FV(pvalue, csp_String_from_cstr("F", 
									  Imps_PresenceValue)));
	  
	  CSP_MSG_SET_FIELD(p, ostatus, gwlist_create_ex(os));
	  goto done;
     } 

     fcount = csp_type_field_count(Imps_PresenceSubList);	  
     for (i = 0, n = PQntuples(r); i<n; i++) {
	  Octstr *in;
	  
	  char *x = PQgetvalue(r, i, 1);
	  char *y = PQgetvalue(r, i, 2);
	  char *z = PQgetvalue(r, i, 3);	  
	  PresenceSubList_t p2;
	  int j;
	  	
	  
	  if (last_cid && strcmp(last_cid, x) == 0) /* Same ClientID as last one we look at: Skip this one! */
	       continue;
	  
	  last_cid = x;
	  in = get_bytea_data(r, i, 0);	  
	  p2 = csp_msg_from_str(in, Imps_PresenceSubList);
	  if (p2 == NULL)
	       p2 = csp_msg_new(PresenceSubList, NULL, NULL); /* make an empty one. */
	  /* fix server-generated presence attributes. */
	  fixup_server_pres(p2, x, y, z);
	  
	  /* now go through all the fields of the session presence, union them with 
	   * what we have already:
	   * if the presence value is a list, append, if not, set if not set
	   */
	  for (j = 0; j<fcount; j++) 
	       if (MSG_GET_BIT(p2, j)) { /* field is set in new object, so set in union too... */
		    int islist = (struct_types[Imps_PresenceSubList][j].nature == IList);
		    void *fval = csp_msg_get_field_value(p2, j);
		    
		    /* if not yet set in union, it must be set, so set it. */
		    if (MSG_GET_BIT(p, j) == 0) {
			 void *x = islist ? (void *)gwlist_create() : csp_msg_copy(fval);
			 csp_msg_set_field_value(p, j, x);
		    }
			 
		    if (islist) { /* for lists, we must add to. */
			 List *oldl = csp_msg_get_field_value(p, j);
			 List *newl = fval;
			 void *x;
			 
			 /* ideally each list should have length = 1, but... */
			 while ((x = gwlist_extract_first(newl)) != NULL)
			      gwlist_append(oldl, x); /* move to first one */
		    }
		    
	       }
	  octstr_destroy(in);	 
	  csp_msg_free(p2);
     }

done:
     PQclear(r);
     if (csp_version>0)
	  fixup_pres_for_cspversion(p, csp_version);
     return p;
}

/* fixup the presence for a given version. */
void fixup_pres_for_cspversion(PresenceSubList_t p, int csp_version)
{
     int i;
     int n = csp_type_field_count(Imps_PresenceSubList);
     char *nm;
     
     /* first things first: all lists must not exceed len = 1, if the CSP version is less than 1.3. Crude! */
     if (csp_version < CSP_VERSION(1,3))
	  for (i = 0; i < n; i++)
	       if (MSG_GET_BIT(p, i) && 
		   struct_types[Imps_PresenceSubList][i].nature == IList) {
		    void *x;
		    List *l = csp_msg_get_field_value(p, i);
		    
		    while (gwlist_len(l) > 1) {
			 x = gwlist_get(l, 1);
			 
			 gwlist_delete(l, 1, 1); /* delete second one until only one left. */
			 csp_msg_free(x);
		    }
		    if (gwlist_len(l) > 0) { 
			 /* remove client field. */
			 int etype = struct_types[Imps_PresenceSubList][i].type;
			 int cfnum = csp_get_field_num_from_type(etype,client);
			 
			 x = gwlist_get(l, 0);
			 if (cfnum>= 0 && x)
			      csp_struct_clear_fields(x, BIT_MASK(cfnum));
			 
		    }
		    
	       }
     
     if (csp_version <= CSP_VERSION(1,1)) {
#if 0
	  int i, n, j, m;
	  CommCap_t cc;
	  CommC_t ct;
#endif
	  if (p->info_link)  /* not supported, clear it. */
	       CSP_MSG_CLEAR_SFIELD(p,info_link);
#if 0
	  if (csp_msg_field_isset(p,commcap))  /* Song and dance over Note field: Nokia CSP v1.1 doesn't like it empty. */
	       for (i = 0, n = gwlist_len(p->commcap); i<n; i++) 
		    if ((cc = gwlist_get(p->commcap, i)) != NULL && cc->commc)
			 for (j = 0, m = gwlist_len(cc->commc); j<m; j++)
			      if ((ct = gwlist_get(cc->commc, j)) != NULL) {
				   if (ct->note && csp_String_len(ct->note) == 0) /* fix note field: if empty, remove! */
					CSP_MSG_CLEAR_SFIELD(ct, note);     
				   if (ct->status && ct->status->_content) {
					octstr_destroy(ct->status->_content);
					ct->status->_content = octstr_imm("OPEN");
				   }
				   if (!csp_msg_field_isset(ct, contact))
					CSP_MSG_SET_FIELD(ct, contact, csp_String_from_cstr("bagyenda@baraza.im", 
											    Imps_Contact));
			      }
#endif
     }
     /* Finally set the xmlns string */
     if (csp_version <= CSP_VERSION(1,1))
	  nm = "http://www.wireless-village.org/PA1.1";
     else if (csp_version <= CSP_VERSION(1,2)) 
	  nm = "http://www.openmobilealliance.org/DTD/WV-PA1.2";     
     else /* assumed to be 1.3 */
	  nm = "http://www.openmobilealliance.org/DTD/IMPS-PA1.3";     
     csp_update_xmlns(p, nm);
}

static void save_pres(PGconn *c, PresenceSubList_t p, int64_t sessid)
{
     Octstr *out = csp_msg_to_str(p, Imps_PresenceSubList);
     char *xdata, xuid[128];
     Octstr *s;
     size_t dlen;
     PGresult *r;
     
     gw_assert(out);

     sprintf(xuid, "%lld", sessid);
     xdata = (void *)PQescapeBytea((void *)octstr_get_cstr(out), octstr_len(out), &dlen);    
     s = octstr_format("UPDATE sessions SET presence = E'%s'::bytea,last_pres_update = current_timestamp WHERE id = %s", xdata, xuid);

     r = PQexec(c, octstr_get_cstr(s));

     if (PQresultStatus(r) != PGRES_COMMAND_OK) 
	  warning(0, "failed to update presence info: %s", PQerrorMessage(c));
     PQclear(r);
     octstr_destroy(s);
     
     /* Find the alias, update the users info. */
     if (p->alias && p->alias->pvalue && p->alias->qual) {
	  char *alias = (char *)p->alias->pvalue->str;
	  char cmd[512];
	  
	  PQ_ESCAPE_STR(c, alias, xuid);
	  sprintf(cmd, "UPDATE users SET nickname = '%.128s' WHERE id = (SELECT userid FROM sessions WHERE id = %lld)",
		  xuid, sessid);
	  r = PQexec(c, cmd);
	  PQclear(r);
     }
     octstr_destroy(out);
     PQfreemem(xdata);
}

/* Get authorised presence attribute mask. */
static int get_pres_auth(PGconn *c, int64_t watched_uid, int64_t watcher_uid, 
			 char *watcher_foreign_uid,
			 char auth_type[64],
			 int *notify,
			 unsigned long *auth_attrib)
{
     int m = -1;
     char cmd[512];
     PGresult *r;

     if (is_bot(c, watched_uid, NULL, NULL) ||  /* All attributes allowed for  Bot, or... */
	 (watcher_uid >= 0 && 
	  watcher_uid == watched_uid) ) {  /* a user requesting their own presence (nokia!). */
	  if (notify) *notify = 0;
	  if (auth_attrib) *auth_attrib = ALL_PRES_ATTRIBS;
	  return 0;
     } else  if (watcher_uid >= 0) 
	  sprintf(cmd, "SELECT attribs,auth_type,notify from get_local_user_auth(%lld, %lld)", 
		  watched_uid, watcher_uid);/* Get the authorised attributes. */
     else {
	  char tmp1[DEFAULT_BUF_LEN];
	  PQ_ESCAPE_STR_LOWER(c, watcher_foreign_uid, tmp1);
	  sprintf(cmd, "SELECT attribs,auth_type,notify from get_foreign_user_auth(%lld, '%.256s')", 
		  watched_uid, tmp1);/* Get the authorised attributes. */
     }
     
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) != PGRES_TUPLES_OK) 
	  warning(0, "failed to query for presence authorisations: %s", PQerrorMessage(c));     
     else if ((m = PQntuples(r)) > 0) {
	  char *x;
	  if (auth_attrib) 
	       *auth_attrib = atoi(PQgetvalue(r, 0, 0));
	  if (auth_type) 
	       strncpy(auth_type, PQgetvalue(r, 0,1), 64);		    
	  if (notify) {
	       x = PQgetvalue(r, 0,2);
	       *notify = _str2bool(x);
	  }
     }
     
     PQclear(r);

     if (auth_attrib && m>0) {
	  /* here we permit the ones that are allowed always XXX - a hack to allow for devices 
	   * that depend on this information
	   */
	  *auth_attrib |= csp_msgtype_get_field_bitmask(Imps_PresenceSubList, commcap);
     }
     return m>0 ? 0 : -1;
}

#if 0
#define ADD_LOCAL_UID(_uid) do {\
 		     if (nusers >= nalloc) { \
			      nalloc += MIN_ALLOC; \
			      lu = gw_realloc(lu, nalloc*sizeof lu[0]); \
			 } \
			 lu[nusers].uid = _uid; lu[nusers++].clientid[0]  = 0;\
                 } while (0)
#define ADD_TO_DOMAIN_PLIST(_val) do { \
			 List *l; \
			 Octstr *_x = octstr_create(xdomain); \
			 if ((l = dict_get(d, _x)) == NULL) {		\
			      l = gwlist_create(); \
			      dict_put(d, _x, l); \
			 } \
			 octstr_destroy(_x); \
			 gwlist_append(l, csp_String_from_cstr(fu, Imps_UserID)); \
              } while (0)
#endif 


Presence_t make_presence_info_for_watcher(PGconn *c, PresenceSubList_t p, 
					  int64_t watcher_localid, 
					  char *watcher_foreign_id,
					  UserID_t watched_u, int64_t watched, 
					  unsigned long mask)
{
     _User_Presence_t up;
     unsigned long attribs;

     if (p == NULL)
	  return NULL;
          
     if (get_pres_auth(c, watched, watcher_localid, watcher_foreign_id, NULL, NULL, &attribs) < 0)
	  attribs = 0;
     
     attribs &= mask; /* only allow requested attributes out. */
     csp_struct_clear_fields(p, ~attribs);

#if 1 /* allow an empty one to go out. */
     if (csp_empty_struct(p)) { /* nothing authorised. */
	  csp_msg_free(p);
	  p = NULL;
     }
#endif
 
     up = csp_msg_new(_User_Presence, NULL,
		      FV(user,csp_msg_copy(watched_u)));
     
     return  csp_msg_new(Presence, NULL, 
			 UFV(pres,Imps__User_Presence,up),
			 FV(pslist, p ? gwlist_create_ex(p) : NULL));	       
}

Presence_t get_authorised_presence_ex(PGconn *c, int64_t watcher_localid, 
				      char *watcher_foreign_id,
				      UserID_t watched_u, int64_t watched, 
				      unsigned long mask, int csp_ver)

{

     return make_presence_info_for_watcher(c, get_pres(c, watched, -1, csp_ver),
					   watcher_localid, watcher_foreign_id, watched_u, watched, mask);    
}
#define get_authorised_presence(c, uid, xuser, xuid, csp_ver) get_authorised_presence_ex(c, uid, NULL, xuser, xuid, ALL_PRES_ATTRIBS, csp_ver)

struct PresWatcher  {
     enum {Pres_LocalUser, Pres_ForeignUser} type;
     union {int64_t uid; char *foreign_userid;} w;
};

static int send_user_presence(PGconn *c, int64_t source_uid, unsigned long attrib_mask, 
			      char *watcher_subs_tmptbl, struct PresWatcher *single_rcpt)
{
     /* Get the presence information for the user, send it to all the identified users, according to their 
      * subscriptions/authorisation. 
      * Only sends if the mask matches as well for the user (is non-zero).
      * 
      */
     PresenceSubList_t p = get_pres(c, source_uid,-1, -1);
     char xid[DEFAULT_BUF_LEN], tmp1[DEFAULT_BUF_LEN];
     char xdomain[DEFAULT_BUF_LEN];
     char cmd[512];
     int i, n = 0;
     PGresult *r;
     
     UserID_t selfu = NULL;
     
     if (attrib_mask  == 0 || p == NULL)
	  goto done; /* nothing to do. */
     
     get_userid_and_domain(c, source_uid, xid, xdomain);
     sprintf(cmd, "wv:%.128s%s%.128s", 
	     xid, xdomain[0] ? "@" : "", xdomain);
     selfu = csp_String_from_cstr(cmd, Imps_UserID);

     if (single_rcpt != NULL) {
	  int64_t watcher_local = (single_rcpt->type == Pres_LocalUser) ? 
	       single_rcpt->w.uid : -1;
	  char *watcher_foreign = (single_rcpt->type == Pres_LocalUser) ? 
	       NULL : single_rcpt->w.foreign_userid;
	  Presence_t p2 = make_presence_info_for_watcher(c, csp_msg_copy(p), 
							 watcher_local, watcher_foreign,
							 selfu, source_uid, 
							 attrib_mask);	  
	  if (!csp_empty_struct(p2)) {
	       struct QLocalUser_t lu = {0};	       
	       PresenceNotification_Request_t pn;
	       pn = csp_msg_new(PresenceNotification_Request, NULL, 
				FV(plist, gwlist_create_ex(p2)));
	       if (single_rcpt->type == Pres_LocalUser) {
		    lu.uid = watcher_local;
		    
		    queue_local_msg_add(c, pn, Imps_PresenceNotification_Request, NULL, &lu, 1,
					0, NULL, NULL,
					time(NULL) + SHORT_EXPIRY);  	   
	       } else {
		    char *fu = watcher_foreign;
		    List *l = gwlist_create_ex(csp_String_from_cstr(fu, Imps_UserID));
		    
		    extract_id_and_domain(fu, xid, xdomain);
		    
		    queue_foreign_msg_add(c, pn, Imps_PresenceNotification_Request, NULL, 
					  source_uid, NULL,
					  NULL, xdomain, l,
					  CSP_VERSION(1,2),
					  time(NULL) + SHORT_EXPIRY);
		    gwlist_destroy(l, (void *)_csp_msg_free);    
	       }
	       csp_msg_free(pn);
	  } else 
	       csp_msg_free(p2);

	  goto done;
     }
     
     if (watcher_subs_tmptbl) 
	  sprintf(tmp1, "AND id IN (SELECT id from %s)", watcher_subs_tmptbl);
     else 
	  tmp1[0] = 0;

     /* Get the sessions (users, clients) that are watching this source of presence. */
     sprintf(cmd, "SELECT foreign_userid, local_userid, attribs_requested,clientid FROM pr_watchlist_userid_view WHERE userid = %lld "
	     " AND (attribs_requested & %lu) <> 0 %s", 
	     source_uid, attrib_mask, tmp1);
     
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) != PGRES_TUPLES_OK)
	  error(0, "Error trying to get presence recipients: %s", PQerrorMessage(c));
     else 
	  n = PQntuples(r);
     
     for (i = 0; i<n; i++) {
	  char *fu = PQgetvalue(r, i, 0);
	  char *uu = PQgetvalue(r, i, 1);	       
	  unsigned long sattribs = strtoul(PQgetvalue(r, i, 2), NULL, 10);
	  char *clid = PQgetvalue(r, i, 3);
	  int64_t xuid = -1;
	  Presence_t p2 = NULL;
	  PresenceNotification_Request_t pn = NULL;
	  
	  if (uu && uu[0]) { /* userid field is set. */
	       xuid = strtoull(uu, NULL, 10);
	       fu = NULL;
	  }
	  p2 = make_presence_info_for_watcher(c, csp_msg_copy(p), 
					      xuid, fu, selfu, source_uid, 
					      attrib_mask & sattribs);
	  if (csp_empty_struct(p2)) {
	       csp_msg_free(p2);
	       continue;
	  }

	  pn = csp_msg_new(PresenceNotification_Request, NULL, FV(plist, gwlist_create_ex(p2)));
	  if (xuid >= 0) {
	       struct QLocalUser_t lu = {0};
	       lu.uid = xuid;	       
	       if (clid)
		    strncpy(lu.clientid, clid, sizeof lu.clientid);
	       queue_local_msg_add(c, pn, Imps_PresenceNotification_Request, NULL, &lu, 1, 
				   0, NULL, NULL,
				   time(NULL) + DEFAULT_EXPIRY);
	  } else {
	       List *l = gwlist_create_ex(csp_String_from_cstr(fu, Imps_UserID));
	       
	       extract_id_and_domain(fu, xid, xdomain);
	       queue_foreign_msg_add(c, pn, Imps_PresenceNotification_Request, NULL, 
				     source_uid, NULL, NULL, 
				     xdomain, l, 
				     CSP_VERSION(1,2),
				     time(NULL) + DEFAULT_EXPIRY);
	       gwlist_destroy(l, (void *)_csp_msg_free);
	  }
	  
	  csp_msg_free(pn);
     }	  

     PQclear(r);
 done:     
     csp_msg_free(p);
     csp_msg_free(selfu);
     return 0;
}

Status_t handle_create_attribs(RequestInfo_t *ri, CreateAttributeList_Request_t req )
{
     int64_t uid = ri->uid;
     List *ul, *cl, *dl;
     
     int i, n, defNotify = 0, cNotify = 0, uNotify ;
     Result_t res;
     Status_t resp;
     UserID_t u;
     ContactList_t ctl;
     unsigned long attribs;
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char cmd[512],  tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN];
     char field[32], value[DEFAULT_BUF_LEN];
     char tmptbl[DEFAULT_BUF_LEN];
     PGresult *r;
     PGconn *c = ri->c;
     
     gw_assert(req);


     defNotify = csp_msg_field_isset(req,dfltNotify);
     cNotify = csp_msg_field_isset(req,clNotify);
     uNotify = csp_msg_field_isset(req,uNotify);
     
     ul = req->uidlist ? req->uidlist->ulist : req->ulist; /* difference between 1.3 and earlier... */
     cl = req->cidlist ? req->cidlist->clist : req->clist; /* difference between 1.3 and earlier... */

     dl = gwlist_create(); /* detailed results list. */
     
     make_temp_ids_table(c, tmptbl); /* make a temp table for storing IDs. */
     
     attribs = req->pres ? MSG_GET_BITS(req->pres) : 0;     /* attributes. */
     for (i = 0, n = gwlist_len(ul); i<n; i++)
	  if ((u = gwlist_get(ul, i)) != NULL) {
	       int64_t xuid, aid = 0; /* if a local user. */
	       int islocal;
	       unsigned long old_attribs;
	       int new;

	       extract_id_and_domain((char *)u->str, xid, xdomain);
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       xuid = get_userid(c, tmp1, tmp2, &islocal);
	       
	       if (xuid < 0 && islocal) {
		    Octstr *_x = octstr_format("Unknown UserID: %s", (char *)u->str);
		    void *rs = csp_msg_new(DetailedResult, NULL, 
					   FV(code,531), 
					   FV(descr, csp_String_from_bstr(_x,
									  Imps_Description)));	  
		    gwlist_append(dl, rs);
		    octstr_destroy(_x);
		    continue;
	       } 	       /* check if already authorised. */
	       
	       if (xuid >= 0) {
		    strcpy(field, "local_userid");
		    sprintf(value, "%lld", xuid);		    
	       } else {
		    strcpy(field, "foreign_userid");
		    sprintf(value, "'%.64s%s%.64s'", 	
			    tmp1, tmp2[0] ? "@" : "",
			    tmp2);
	       }
	       
	       sprintf(cmd, "SELECT attribs_authorised, id FROM presence_user_authorisations "
		       "WHERE userid = %lld AND %s = %s", 
		       uid, field, value);
	       
	       r = PQexec(c, cmd);
	       
	       if (PQresultStatus(r) != PGRES_TUPLES_OK || 
		   PQntuples(r) < 1) {
		    old_attribs = 0;
		    new = 1;
	       } else {
		    old_attribs = strtoul(PQgetvalue(r, 0,0), NULL, 10);
		    aid = strtoull(PQgetvalue(r, 0,1), NULL, 10);
		    new = 0;
	       }
	       PQclear(r);

	       
	       /* now update or add. */
	       if (!new)
		    sprintf(cmd, "UPDATE presence_user_authorisations SET "
			    " attribs_authorised = %lu %s WHERE id = %lld",
			    attribs, 
			    uNotify ? (req->uNotify ? ",user_notify=true" : ",user_notify=false") : "",
			    aid);
	       else 
		    sprintf(cmd, "INSERT INTO presence_user_authorisations (userid, %s,attribs_authorised %s) "
			    " VALUES (%lld, %s, %lu %s)",
			    field, 
			    uNotify ? ", user_notify"  : "",
			    uid, value, attribs,
			    uNotify ? (req->uNotify ? ",true" : ",false"): "");
	       
	       r = PQexec(c, cmd);
	       if (PQresultStatus(r) != PGRES_COMMAND_OK) 
		    warning(0, "failed to save authorisation: %s", PQerrorMessage(c));
	       PQclear(r);
	       
	       if (attribs && attribs != old_attribs) { /* if some authorisation was given, and it 
						       * differs from previous,
						       *  then inform users.
						       */
		    sprintf(cmd, "INSERT INTO %s (id) SELECT id FROM pr_watchlist_userid_view WHERE "
			    " %s = %s AND userid = %lld",
			    tmptbl, field, value, uid);
		    r = PQexec(c, cmd); 
		    PQclear(r); /* ignore errors. */
	       }
	       
	  }


     for (i = 0, n = gwlist_len(cl); i<n; i++)
	  if ((ctl = gwlist_get(cl, i)) != NULL) {
	       unsigned long old_attribs;
	       int64_t cid;
	       
	       extract_id_and_domain((char *)ctl->str, xid, xdomain);
	       
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       
	       sprintf(cmd, "SELECT presence_attribs_authorised, id FROM contactlists WHERE "
		       " userid=%lld AND cid='%.128s' AND domain='%.128s'",
		       uid, tmp1, tmp2);

	       r = PQexec(c, cmd);
	       
	       if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
		    Octstr *s = octstr_format("No such contact list: %s", (void *)ctl->str);
		    DetailedResult_t rs = csp_msg_new(DetailedResult, NULL, 
						      FV(code,700), 
						      FV(descr, csp_String_from_bstr(s, 
										     Imps_Description)));	  
		    PQclear(r);
		    gwlist_append(dl, rs);
		    octstr_destroy(s);
		    continue;
	       }
	       
	       old_attribs = strtoul(PQgetvalue(r, 0, 0), NULL, 10);
	       cid = strtoull(PQgetvalue(r, 0, 1), NULL, 10);
	       PQclear(r);
	       
	       sprintf(cmd, "UPDATE contactlists SET presence_attribs_authorised=%lu %s WHERE id=%lld",
		       attribs, 
		       cNotify ? (req->clNotify ? "contact_list_notify=true" : "contact_list_notify=false") : "",
		       cid);
	       r = PQexec(c, cmd);
	       PQclear(r); /* it should work, no need to test result. Right?? */

	       if (attribs && attribs != old_attribs) { /* ... as above. */
		    sprintf(cmd, "INSERT INTO %s (id) SELECT id FROM pr_watchlist_userid_view p WHERE "
			    "p.userid = %lld AND "
			    "(p.foreign_userid IN (SELECT foreign_userid FROM contactlist_members WHERE cid = %lld) "
			    "OR p.local_userid IN (SELECT local_userid FROM contactlist_members WHERE cid = %lld))",
			    tmptbl, uid, cid, cid);
		    r = PQexec(c, cmd); 
		    PQclear(r); /* ignore errors, even though above is pretty nasty. */		    
	       }
	  }

     if (req->isdflt || defNotify) { /* default one to be updated as well. */
	  char fld1[128];

	  fld1[0] = 0;	  
	  if (req->isdflt) 
	       sprintf(fld1, ",default_attr_list = %lu", attribs);
	  if (defNotify) 
	       strcat(fld1, 
		      req->dfltNotify ? ",default_notify=true" : ",default_notify=false");
	  
	  sprintf(cmd, "UPDATE users SET lastt=current_timestamp %s WHERE id = %lld",
		  fld1, uid);
	  r = PQexec(c, cmd);
	  PQclear(r);	  
     }
     
     /* send presence info. */
     send_user_presence(c, uid, attribs, tmptbl,NULL); 
     
     res = csp_msg_new(Result, NULL,
		       FV(code, (dl && gwlist_len(dl) > 0) ? 201 : 200),
		       FV(descr, csp_String_from_cstr("Complete", Imps_Description)),
		       FV(drlist, dl));     
     resp = csp_msg_new(Status, NULL,
			FV(res,res));
     
     return resp;
}


Status_t handle_delete_attribs(RequestInfo_t *ri, DeleteAttributeList_Request_t req )
{
     int64_t uid = ri->uid;
     List *ul, *cl, *dl;
     Result_t res;
     int i, n;
     Status_t resp;
     UserID_t u;
     ContactList_t ctl;

     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char cmd[512], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN];
     PGresult *r;
     PGconn *c = ri->c;
     
     gw_assert(req);


     ul = req->uidlist ? req->uidlist->ulist : req->ulist; /* difference between 1.3 and earlier... */
     cl = req->cidlist ? req->cidlist->clist : req->clist; /* difference between 1.3 and earlier... */

     dl = gwlist_create(); /* detailed results list. */

     for (i = 0, n = gwlist_len(ul); i<n; i++)
	  if ((u = gwlist_get(ul, i)) != NULL) {
	       int64_t xuid; /* if a local user. */
	       int islocal;
	       	      
	       extract_id_and_domain((char *)u->str, xid, xdomain);
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       xuid = get_userid(c, tmp1, tmp2, &islocal);
	       
	       if (xuid < 0 && islocal) {
		    Octstr *_x = octstr_format("Unknown UserID: %s", (char *)u->str);
		    void *rs = csp_msg_new(DetailedResult, NULL, 
					   FV(code,531), 
					   FV(descr, csp_String_from_bstr(_x,
									  Imps_Description)));	  
		    gwlist_append(dl, rs);
		    octstr_destroy(_x);
		    continue;
	       } 	       /* check if already authorised. */
	       
	       if (xuid >= 0)
		    sprintf(cmd, "DELETE FROM presence_user_authorisations "
			    "WHERE userid = %lld AND local_userid = %lld", 
			    uid, xuid);
	       else
		    sprintf(cmd, "DELETE FROM presence_user_authorisations "
			    "WHERE userid = %lld AND foreign_userid = '%.128s%s%.128s'", 
			    uid, 
			    tmp1, tmp2[0] ? "@" : "",
			    tmp2);
	       r = PQexec(c, cmd);
	       PQclear(r); /* we don't check error. */	      	       
	  }
          
     for (i = 0, n = gwlist_len(cl); i<n; i++)
	  if ((ctl = gwlist_get(cl, i)) != NULL) {
	       
	       extract_id_and_domain((char *)ctl->str, xid, xdomain);
	       
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       
	       sprintf(cmd, "UPDATE contactlists SET presence_attribs_authorised=NULL WHERE "
		       " userid=%lld AND cid='%.128s' AND domain='%.128s'",
		       uid, tmp1, tmp2);

	       r = PQexec(c, cmd);
	       
	       PQclear(r);
	  }
     
     if (req->delDflt) { /* default one to be updated as well. */
	  sprintf(cmd, "UPDATE users SET lastt=current_timestamp, "
		  " default_notify=false, default_attr_list = NULL  WHERE id = %lld",
		  uid);
	  r = PQexec(c, cmd);
	  PQclear(r);	  
     }

     res = csp_msg_new(Result, NULL,
		       FV(code, (dl && gwlist_len(dl) > 0) ? 201 : 200),
		       FV(descr, csp_String_from_cstr("Complete", Imps_Description)),
		       FV(drlist, dl));     
     resp = csp_msg_new(Status, NULL,
			FV(res, res));

     return resp;
}

static PresenceSubList_t build_pres_element(unsigned long attribs, int ver)
{
     PresenceSubList_t p;
     char *xmlns;
     
     if (ver >= 0x13)
	  xmlns  = "http://www.openmobilealliance.org/DTD/IMPS-PA1.3";
     else if (ver == 0x12)
	  xmlns  = "http://www.openmobilealliance.org/DTD/WV-PA1.2";
     else if (ver == 0x11)
	  xmlns =  "http://www.wireless-village.org/PA1.1";
     else 
	  xmlns =   "http://www.wireless-village.org/PA1.0";;

     p = csp_msg_new(PresenceSubList,octstr_imm(xmlns), NULL);
     csp_msg_init_fields(p, attribs);
     return p;
}

static int add_user_attribs(PGconn *c, int64_t uid, int ver, char *crit, List *pl)
{
     int i, n;
     PGresult *r;
     char cmd[512];
     sprintf(cmd, "SELECT localuserid,foreign_userid,attribs_authorised,user_notify FROM pr_users_view "
	     " WHERE userid = %lld AND %s", 
	     uid, crit ? crit : "TRUE");
     
     r = PQexec(c, cmd);
     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
     for (i = 0; i<n; i++) {
	  char *u = PQgetvalue(r, i, 0);
	  char *f = PQgetvalue(r, i, 1);
	  unsigned long attribs =  strtoul(PQgetvalue(r, i, 2), NULL, 10); 
	  char *x = PQgetvalue(r, i, 3);
	  int notif = _str2bool(x);
	  PresenceSubList_t p = build_pres_element(attribs, ver);
	  UserID_t usid = csp_String_from_cstr(u && u[0] ? u : f, Imps_UserID);
	  _User_Presence_t up;
	  
	  up = csp_msg_new(_User_Presence, NULL,
			   FV(user,usid));
	  if (ver>=CSP_VERSION(1,3)) 
	       CSP_MSG_SET_FIELD(up,notify, notif);
	  gwlist_append(pl, 
			csp_msg_new(Presence, NULL, 
				    UFV(pres,Imps__User_Presence,up),
				    FV(pslist, gwlist_create_ex(p))));
	  
     }
     PQclear(r);
     return n;
}

static int add_clist_attribs(PGconn *c, int64_t uid, int ver, char *crit, List *pl)
{
     char cmd[512];
     int i, n;
     PGresult *r;
     
     /* query the contact lists */
     sprintf(cmd, "SELECT contactlistid,presence_attribs_authorised,contact_list_notify FROM contactlists_view"
	     " WHERE userid = %lld AND presence_attribs_authorised IS NOT NULL AND %s",
	     uid, 
	     crit ? crit : "TRUE");
     
     r = PQexec(c, cmd);	  
     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
     
     for (i = 0; i<n; i++) {
	  char *u = PQgetvalue(r, i, 0);
	  unsigned long attribs =  strtoul(PQgetvalue(r, i, 1), NULL, 10); 
	  char *x = PQgetvalue(r, i, 2);
	  int notif = _str2bool(x);
	  PresenceSubList_t p = build_pres_element(attribs, ver);
	  ContactList_t ct = csp_String_from_cstr(u, Imps_ContactList);
	  _Clist_Presence_t cp;
	  
	  cp = csp_msg_new(_Clist_Presence, NULL,
			   FV(clist, ct));
	  
	  if (ver>=CSP_VERSION(1,3)) 
	       CSP_MSG_SET_FIELD(cp,notify, notif);
	  
	  gwlist_append(pl, 
			csp_msg_new(Presence, NULL, 
				    UFV(pres,Imps__Clist_Presence,cp),
				    FV(pslist, gwlist_create_ex(p))));
     }
     PQclear(r);     
     
     return n;
}

GetAttributeList_Response_t handle_get_attribs(RequestInfo_t *ri, GetAttributeList_Request_t req)
{
     int64_t uid = ri->uid;
     List *ul, *cl, *dl, *pl;
     
     int i, n;
     Result_t res;
     GetAttributeList_Response_t resp;
     DefaultAttributeList_t defa;
     void *u;
     ContactList_t ctl;
     
     char cmd[512], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN*2];
     PGresult *r;
     PGconn *c = ri->c;
     
     gw_assert(req);
     

     ul = req->uidlist ? req->uidlist->ulist : req->ulist; /* difference between 1.3 and earlier... */
     cl = req->cidlist ? req->cidlist->clist : req->clist; /* difference between 1.3 and earlier... */
          
     pl = gwlist_create();
     dl = gwlist_create();
     if (ul == NULL && cl == NULL) { /* return all. */
	  add_user_attribs(c, uid, ri->ver, NULL, pl);
	  add_clist_attribs(c, uid,ri->ver, NULL, pl);	  
     } 

     if (ul) 
	  for (i = 0, n = gwlist_len(ul); i<n; i++)
	       if ((u = gwlist_get(ul, i)) != NULL) {
		    char *s = NULL;
		    if (CSP_MSG_TYPE(u) == Imps_User) /* < v1.2 */
			 s = ((User_t)u)->user ? (void *)((User_t)u)->user->str : "";
		    else if (CSP_MSG_TYPE(u) == Imps_UserID) /* v1.3 */
			 s = (void *)((UserID_t)u)->str;
		    else 
			 panic(0, "unexpected object type: %d [%s]", 
			       CSP_MSG_TYPE(u), csp_obj_name(CSP_MSG_TYPE(u)));
		    PQ_ESCAPE_STR_LOWER(c,  s, tmp1);
		    
		    sprintf(tmp2, "(localuserid='%.128s' OR foreign_userid = '%.128s')", 
			    tmp1, tmp1);
		    if (add_user_attribs(c, uid, ri->ver, tmp2, pl) < 1) {
			 Octstr *_x = octstr_format("Unknown UserID: %s", (char *)s);
			 void *rs = csp_msg_new(DetailedResult, NULL, 
						FV(code,531), 
						FV(descr, csp_String_from_bstr(_x,
									       Imps_Description)));	  
			 gwlist_append(dl, rs);
			 octstr_destroy(_x);			 
		    }
		    
	       }

     if (cl) 
	  for (i = 0, n = gwlist_len(cl); i<n; i++)
	       if ((ctl = gwlist_get(cl, i)) != NULL) {
		    char *s = (void *)ctl->str;

		    PQ_ESCAPE_STR_LOWER(c,  s, tmp1);
		    
		    sprintf(tmp2, "contactlistid='%.128s'", 
			    tmp1);
		    if (add_clist_attribs(c, uid, ri->ver, tmp2, pl) < 1) {
			 Octstr *_x = octstr_format("Unknown Contactlist: %s", (char *)s);
			 void *rs = csp_msg_new(DetailedResult, NULL, 
						FV(code,700), 
						FV(descr, csp_String_from_bstr(_x,
									       Imps_Description)));	  
			 gwlist_append(dl, rs);
			 octstr_destroy(_x);			 
		    }		    
	       }

     if (req->dlist) { /* wants default list too */
	  unsigned long attribs;
	  PresenceSubList_t p;
	  int dnotify = 0;
	  char *x;
	  sprintf(cmd, "SELECT default_attr_list,default_notify FROM users WHERE id = %lld", uid);

	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) == PGRES_TUPLES_OK && 
	      PQntuples(r) > 0) {
	       attribs = strtoul(PQgetvalue(r, 0,0), NULL, 10);
	       x = PQgetvalue(r, 0, 1);
	       dnotify = _str2bool(x);
	  }  else 
	       attribs = 0;
	  PQclear(r);

	  p  =  build_pres_element(attribs, ri->ver);
	  defa = csp_msg_new(DefaultAttributeList, NULL, 
			     FV(dnotify, dnotify),
			     FV(pslist, p));
	  if (ri->ver < CSP_VERSION(1,3)) /* not supported in lower versions. */
	       CSP_MSG_CLEAR_FIELD(defa,dnotify);
     } else 
	  defa = NULL;
 
     res = csp_msg_new(Result, NULL,
		       FV(code, (dl && gwlist_len(dl) > 0) ? 201 : 200),
		       FV(descr, csp_String_from_cstr("Complete", Imps_Description)),
		       FV(drlist, dl));
     resp = csp_msg_new(GetAttributeList_Response,NULL, 
			FV(res, res),
			FV(dalist, defa),
			FV(presence,pl));
     return resp;
}



static void do_pres_req_notify(PGconn *c, Sender_t sender, 	       
			       int64_t watched_uid, int64_t watcher_uid, 
			       char *watcher_foreign_uid,
			       unsigned long attribs,
			       int react)
{
     char auth_type[64];

     int m, notify = 0;
     unsigned long auth_attribs = 0;
     User_t user = sender->u.val;
     UserID_t  watcher_user = user->user;
     
     gw_assert(sender);
     gw_assert(sender->u.typ == Imps_User);

     m = get_pres_auth(c, watched_uid, watcher_uid, watcher_foreign_uid, auth_type, &notify, &auth_attribs);
     
     if (m < 0) {
	  if (react)  {/* no authorisation  and asked (in session) to be informed */
	       PresenceSubList_t p = build_pres_element(attribs, CSP_VERSION(1,1)); /* only a 1.1 or 1.2 client could ask for a REACT authorisation */
	       PresenceAuth_Request_t req = csp_msg_new(PresenceAuth_Request, NULL, 
							FV(user, csp_msg_copy(watcher_user)),
							FV(pslist, p));
	       struct QLocalUser_t x = {0};
	       
	       x.uid = watched_uid;
	       
	       queue_local_msg_add(c, req, Imps_PresenceAuth_Request, sender, &x, 1, 
				   0, NULL, NULL,
				   time(NULL) + DEFAULT_EXPIRY);
	       
	       csp_msg_free(req);	 
	  }
     } else if ((attribs & (~auth_attribs)) != 0 && notify) { /* there was an authorisation, but it was not enough, 
							       * and user asked to be notified.
							       * this must be a v1.3 client, so we use general notification
							       */
	  
	  /* XXX for now we always send authorisation-needed-user */
	  PresenceSubList_t p = build_pres_element(attribs, CSP_VERSION(1,3)); 
	  NotificationType_t n = csp_String_from_cstr("ANU", Imps_NotificationType);
	  UserIDList_t ul = csp_msg_new(UserIDList, NULL,
					FV(ulist, gwlist_create_ex(csp_msg_copy(watcher_user))));
					
	  _Pres_List_t pl = csp_msg_new(_Pres_List,NULL,
					FV(pslist, p),
					FV(ulist, ul));
	  Notification_Request_t req = csp_msg_new(Notification_Request, NULL,
						   FV(ntype, n),
						   UFV(u, Imps__Pres_List, pl));

	  struct QLocalUser_t x = {0};	  
	  x.uid = watched_uid;
	  
	  queue_local_msg_add(c, req, Imps_Notification_Request, sender, &x, 1,
			      0, NULL, NULL,
			      time(NULL) + DEFAULT_EXPIRY);	  
	  csp_msg_free(req);	 	  
     }

}

#define _X_ADD_UID(_uid,array,elem_counter,alloc_counter) do {\
                     int _i; \
                     for (_i = 0; _i<elem_counter;_i++) if (array[_i] == _uid) break; \
                     if (_i<elem_counter) break; /* it was existent. */ \
 		     if (elem_counter >= alloc_counter) { \
			      alloc_counter += MIN_ALLOC; \
			      array = gw_realloc(array, alloc_counter*sizeof array[0]); \
			 } \
			array[elem_counter++] = _uid; /* keep track of all local ones. */ \
                 } while (0)

#if 0
#define ADD_UID(_uid) do {\
                     int _i; \
                     for (_i = 0; _i<nusers;_i++) if (local_users[_i] == _uid) break; \
                     if (_i<nusers) break; /* it was existent. */ \
 		     if (nusers >= nalloc) { \
			      nalloc += MIN_ALLOC; \
			      local_users = gw_realloc(local_users, nalloc*sizeof local_users[0]); \
			 } \
			 local_users[nusers++] = _uid; /* keep track of all local ones. */ \
                 } while (0)
#endif

#define ADD_UID(_uid) _X_ADD_UID(_uid,local_users,nusers,nalloc)
#if 0
#define ADD_SUID(_uid) _X_ADD_UID(_uid,sub_ids,snusers,snalloc)
#endif
#define ADD_SUB_TO_DOMAIN(_fld, _val) do				\
    if (!ri->is_ssp) {							\
      SubscribePresence_Request_t sp;					\
      Octstr *_x = octstr_create(xdomain);				\
      if ((sp = dict_get(d, _x)) == NULL) {				\
	sp = csp_msg_new(SubscribePresence_Request, NULL,		\
			 FV(ulist, gwlist_create()),			\
			 FV(clist,gwlist_create()),			\
			 FV(plist,csp_msg_copy(req->plist)),		\
			 FV(auto_sub,req->auto_sub));			\
	dict_put(d, _x, sp);						\
      }									\
      octstr_destroy(_x);						\
      gwlist_append(sp->_fld, _val);					\
    } else {								\
      Octstr *err = octstr_format("Forwarding to domain %s is not supported!", (xdomain)); \
      DetailedResult_t _dr = csp_msg_new(DetailedResult, NULL,		\
					 FV(code,516),			\
					 FV(descr, csp_String_from_bstr(err, \
									Imps_Description))); \
      gwlist_append(dl, _dr);						\
      octstr_destroy(err);						\
    }									\
  while (0)
			 

Status_t handle_pres_subscribe(RequestInfo_t *ri, SubscribePresence_Request_t req)
{
     int64_t uid = ri->uid, sid = ri->sessid;
     int64_t *local_users = gw_malloc(MIN_ALLOC*sizeof local_users[0]);
     int nusers = 0, nalloc = MIN_ALLOC;
#if 0
     int64_t *sub_ids =  gw_malloc(MIN_ALLOC*sizeof sub_ids[0]);
     int snusers = 0, snalloc = MIN_ALLOC; /* for the sub IDs. */
#endif
     List *ul, *cl, *dl, *xl = NULL;
     unsigned long attribs;
     int i, n, react = ri->sinfo.react;
     Result_t res;
     Status_t resp;
     Dict *d = dict_create(7, (void *)_csp_msg_free); /* contains subscribe requests, indexed by domain.*/
     void *u;
     ContactList_t ctl;
     char *fld1, *fld2;
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];     
     char cmd[512], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN*2];
     char tmp3[DEFAULT_BUF_LEN*2 + 1], val1[DEFAULT_BUF_LEN], val2[DEFAULT_BUF_LEN];
     Sender_t st = NULL;
     Octstr *clientid = ri->clientid;
     PGresult *r;
     PGconn *c = ri->c;
     struct PresWatcher pw;
     
     gw_assert(req);
          
     ul = req->uidlist ? req->uidlist->ulist : req->ulist; /* difference between 1.3 and earlier... */
     cl = req->cidlist ? req->cidlist->clist : req->clist; /* difference between 1.3 and earlier... */
     
     st = make_sender_struct2(ri->userid, clientid, NULL, NULL);
     
     dl = gwlist_create();
     attribs = req->plist ? MSG_GET_BITS(req->plist) : ALL_PRES_ATTRIBS;
     if (attribs == 0) 
	  attribs = ALL_PRES_ATTRIBS; /* all requested. */

     if (!ri->is_ssp) {
	  fld1 = "sessid";
	  sprintf(val1, "%lld", sid);
	  fld2 = NULL;
     } else  {
	  char tmp[DEFAULT_BUF_LEN];
	  fld1 = "foreign_userid";
	  PQ_ESCAPE_STR(c, octstr_get_cstr(ri->userid), tmp);
	  sprintf(val1, "'%.128s'", tmp);

	  if (octstr_len(clientid) > 0) {
	       fld2 = "foreign_clientid";
	       PQ_ESCAPE_STR(c, octstr_get_cstr(clientid), tmp);
	       sprintf(val2, "'%.128s'", tmp);
	  } else 
	       fld2 = NULL;
     }
     
     for (i = 0, n = gwlist_len(ul); i<n; i++)
	  if ((u = gwlist_get(ul, i)) != NULL) {
	       char *s = NULL;
	       int64_t xuid;
	       int islocal;
	       if (CSP_MSG_TYPE(u) == Imps_User) { /* < v1.2 */
		    User_t xu = u;
		    s = xu->user ? (void *)xu->user->str : "";
	      }  else if (CSP_MSG_TYPE(u) == Imps_UserID) /* v1.3 */
		    s = (void *)((UserID_t)u)->str;
	        else 
		    panic(0, "unexpected object type: %d [%s]", 
			  CSP_MSG_TYPE(u), csp_obj_name(CSP_MSG_TYPE(u)));
	       
	       extract_id_and_domain(s, xid, xdomain);
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       xuid = get_userid(c, tmp1, tmp2, &islocal);
	       
	       if (xuid < 0 && islocal) {
		    Octstr *_x = octstr_format("Unknown UserID: %s", s);
		    DetailedResult_t rs = csp_msg_new(DetailedResult, NULL, 
					   FV(code,531), 
					   FV(descr, csp_String_from_bstr(_x,
									  Imps_Description)));	  
		    gwlist_append(dl, rs);
		    octstr_destroy(_x);
		    continue;
	       }
	       
	       if (xuid >= 0) {
		    int64_t p_id = -1;

		    ADD_UID(xuid);
		    sprintf(cmd, "DELETE FROM presence_watchlists WHERE %s=%s %s %s%s%s AND userid = %lld; "
			    "INSERT INTO presence_watchlists (userid,%s %s %s,attribs_requested) "
			    "VALUES (%lld, %s %s %s, %lu) RETURNING id",
			    
			    fld1, val1, 
			    fld2 ? " AND " : "", /* another criterion? */
			    fld2 ? fld2 : "",
			    fld2 ? "=" : "",
			    fld2 ? val2 : "",
			    xuid, 
			    
			    fld1, 
			    fld2 ? "," : "",
			    fld2 ? fld2 : "",
			    
			    xuid, val1,
			    
			    fld2 ? "," : "",
			    fld2 ? val2 : "",

			    attribs);			 
		    r = PQexec(c, cmd);
		    if (PQresultStatus(r) != PGRES_TUPLES_OK) 
			 warning(0, "failed to queue presence subscription: %s", 
				 PQerrorMessage(c));
		    else 
			 p_id = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
#if 0	    
		    ADD_SUID(p_id);		    
#endif	    
		    PQclear(r);		
		    
		    do_pres_req_notify(c, st, xuid, ri->is_ssp ? -1 : uid, 
				       ri->is_ssp ? octstr_get_cstr(ri->userid) : NULL, 
				       attribs, react);
	       } else {
		    User_t fu = csp_msg_new(User,NULL,
					    FV(user, csp_String_from_cstr(s, Imps_UserID)));
		    
		    /* add this subscribe request to the list of those going out to the domain in question.*/
		    ADD_SUB_TO_DOMAIN(ulist,fu);
	       }
	       
	  }

     /* Now handle the contactlist presence subscription. */
     if (ri->is_ssp)
       sprintf(tmp3, "FALSE");
     else 
       sprintf(tmp3, "userid = %lld", uid); /* must be a list for the user. */
     for (i = 0, n = gwlist_len(cl); i<n; i++)
	  if ((ctl = gwlist_get(cl, i)) != NULL) {
	       int64_t cid;
	       int islocal, j, m;
	       
	       extract_id_and_domain((char *)ctl->str, xid, xdomain);
	       
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       
	       cid = get_contactlist(c, tmp1, tmp2, tmp3, &islocal);
	       
	       if (cid < 0) {
		    Octstr *s = octstr_format("No such contact list: %s", (void *)ctl->str);
		    DetailedResult_t rs = csp_msg_new(DetailedResult, NULL, 
						      FV(code,700), 
						      FV(descr, csp_String_from_bstr(s, 
										     Imps_Description)));	  
		    gwlist_append(dl, rs);
		    octstr_destroy(s);
		    continue;
	       } else if (req->auto_sub) { /* auto subscribe: put in attributes. */
		    sprintf(cmd, "UPDATE contactlists SET presence_attribs_auto_subscribe=%ld WHERE id = %lld", 
			    attribs, cid);
		    r = PQexec(c, cmd);
		    PQclear(r);
	       }
	       
	       /* insert all into watcher list and return them as well. */
	       sprintf(cmd, "SELECT local_userid,foreign_userid FROM contactlist_members WHERE cid = %lld", 
		       cid);
	       r = PQexec(c, cmd);
	       
	       m = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
	       for (j = 0; j<m; j++) {
		    char *lu = PQgetvalue(r, j, 0);
		    char *fu = PQgetvalue(r, j, 1);
		    int64_t xuid = -1, p_id = -1;

		    
		    if (PQgetisnull(r,j,0) == 0) { /* a local user. */
			 PGresult *r2;
			 xuid = strtoull(lu, NULL, 10);
			 ADD_UID(xuid);
			 sprintf(cmd, "DELETE FROM presence_watchlists WHERE sessid=%lld AND userid = %lld; "
				 "INSERT INTO presence_watchlists (userid,sessid,attribs_requested) "
				 "VALUES (%lld, %lld, %lu) RETURNING id",
				 sid, xuid, 
				 xuid, sid, attribs);		
			 
			 r2 = PQexec(c, cmd); 
			 if (PQresultStatus(r2) != PGRES_TUPLES_OK) 
			      warning(0, "failed to queue presence subscription: %s", 
				      PQerrorMessage(c));
			 else 
			      p_id = strtoull(PQgetvalue(r2, 0, 0), NULL, 10);			 
#if 0
			 ADD_SUID(p_id);		    
#endif
			 PQclear(r2);
			 
			 do_pres_req_notify(c, st, xuid, uid, NULL, attribs, react);
		    } else {
			 User_t x = csp_msg_new(User,NULL,
						FV(user, csp_String_from_cstr(fu, Imps_UserID)));
			 extract_id_and_domain((char *)fu, xid, xdomain);
			 /* add the subscribe request to the list of those going out to the domain in question.*/
			 ADD_SUB_TO_DOMAIN(ulist,x);
		    }
	       }
	       PQclear(r);
	  }

     /* for the foreign ones, queue the subscribe message, and send out. */     
     xl = dict_keys(d);	      
     for (i = 0, n = gwlist_len(xl); i < n; i++) {
	  Octstr *x = gwlist_get(xl, i);
	  SubscribePresence_Request_t sp = dict_get(d, x);

#if 1
	  if (ri->ver <= CSP_VERSION(1,1) && 
	      sp->plist) { /* XXX some nokia require this?? */
	       if (!csp_msg_field_isset(sp->plist, commcap)) 
		    CSP_MSG_SET_FIELD(sp->plist, commcap, 
				      gwlist_create_ex(csp_msg_new(CommCap, NULL, NULL))); 
	       if (!csp_msg_field_isset(sp->plist, cinfo))
		    CSP_MSG_SET_FIELD(sp->plist, cinfo,gwlist_create_ex(csp_msg_new(ClientInfo,NULL,NULL)));
	  }
#endif
	  
	  queue_foreign_msg_add(c, sp, Imps_SubscribePresence_Request, st,
				uid, clientid ? octstr_get_cstr(clientid) :  NULL,
				NULL,
				octstr_get_cstr(x), NULL, 
				ri->ver,
				time(NULL) + DEFAULT_EXPIRY);
     }
     
     if (ri->is_ssp) {
	  pw.w.foreign_userid = octstr_get_cstr(ri->userid);
	  pw.type = Pres_ForeignUser;
     } else {
	  pw.type = Pres_LocalUser;
	  pw.w.uid = uid;
     }

     /* finally send presence info FOR all local users. */
     for (i = 0; i < nusers; i++) 
	  send_user_presence(c, local_users[i], ALL_PRES_ATTRIBS, NULL, &pw);	  
     
     res = csp_msg_new(Result, NULL,
		       FV(code, (dl && gwlist_len(dl) > 0) ? 201 : 200),
		       FV(descr, csp_String_from_cstr("Complete", Imps_Description)),
		       FV(drlist, dl));
     resp = csp_msg_new(Status,NULL, 
			FV(res, res));
     
     dict_destroy(d);

     gw_free(local_users);

#if 0
     gw_free(sub_ids);
#endif	     

     gwlist_destroy(xl, (void *)octstr_destroy);
     csp_msg_free(st);

     return resp;
}

#define ADD_USUB_TO_DOMAIN(_fld, _val) do		   \
	  if (!ri->is_ssp) {				   \
	       UnsubscribePresence_Request_t sp;	      \
	       Octstr *_x = octstr_create(xdomain);			\
	       if ((sp = dict_get(d, _x)) == NULL) {			\
		    sp = csp_msg_new(UnsubscribePresence_Request, NULL, \
				     FV(ulist, gwlist_create()),	\
				     FV(clist,gwlist_create()));	\
		    dict_put(d, _x, sp);				\
	       }							\
	       octstr_destroy(_x);					\
	       gwlist_append(sp->_fld, _val);				\
	  } else {							\
	       Octstr *err = octstr_format("Forwarding to domain %s is not supported!", (xdomain)); \
	       DetailedResult_t _dr = csp_msg_new(DetailedResult, NULL, \
						  FV(code,516),		\
						  FV(descr, csp_String_from_bstr(err, \
										 Imps_Description))); \
	       gwlist_append(dl, _dr);					\
	       octstr_destroy(err);					\
	  }	 while (0)


Status_t handle_pres_unsubscribe(RequestInfo_t *ri, UnsubscribePresence_Request_t req)
{
     int64_t uid = ri->uid, sid = ri->sessid;
     List *ul, *cl, *dl, *xl = NULL;
     int i, n;
     Result_t res;
     Status_t resp;
     Dict *d = dict_create(7, (void *)_csp_msg_free); /* contains subscribe requests, indexed by domain.*/
     void *u;
     ContactList_t ctl;
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];     
     char cmd[512], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN*2];
     char tmp3[DEFAULT_BUF_LEN*2 + 1];
     Sender_t st = NULL;
     Octstr *clientid = ri->clientid;
     PGresult *r;
     PGconn *c = ri->c;
     UserID_t selfu = NULL;
     
     gw_assert(req);
              
     ul = req->uidlist ? req->uidlist->ulist : req->ulist; /* difference between 1.3 and earlier... */
     cl = req->cidlist ? req->cidlist->clist : req->clist; /* difference between 1.3 and earlier... */
     
     
     dl = gwlist_create();

     for (i = 0, n = gwlist_len(ul); i<n; i++)
	  if ((u = gwlist_get(ul, i)) != NULL) {
	       char *s = NULL;
	       int64_t xuid;
	       int islocal;
	       if (CSP_MSG_TYPE(u) == Imps_User)  /* < v1.2 */
		    s = ((User_t)u)->user ? (void *)((User_t)u)->user->str : "";
	       else if (CSP_MSG_TYPE(u) == Imps_UserID) /* v1.3 */
		    s = (void *)((UserID_t)u)->str;
	       else 
		    panic(0, "unexpected object type: %d [%s]", 
			  CSP_MSG_TYPE(u), csp_obj_name(CSP_MSG_TYPE(u)));
	       
	       extract_id_and_domain(s, xid, xdomain);
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       xuid = get_userid(c, tmp1, tmp2, &islocal);
	       
	       if (xuid < 0 && islocal) {
		    Octstr *_x = octstr_format("Unknown UserID: %s", s);
		    void *rs = csp_msg_new(DetailedResult, NULL, 
					   FV(code,531), 
					   FV(descr, csp_String_from_bstr(_x,
									  Imps_Description)));	  
		    gwlist_append(dl, rs);
		    octstr_destroy(_x);
		    continue;
	       }
	       
	       if (xuid >= 0) {
		    sprintf(cmd, "DELETE FROM presence_watchlists WHERE sessid=%lld AND userid = %lld",
			    sid, xuid);			 
		    r = PQexec(c, cmd);
		    if (PQresultStatus(r) != PGRES_COMMAND_OK) 
			 warning(0, "failed to queue presence unsubscribe: %s", 
				 PQerrorMessage(c));
		    PQclear(r);		    		    		    
	       } else {
		    User_t fu = csp_msg_new(User,NULL,
					    FV(user, csp_String_from_cstr(s, Imps_UserID)));
		    
		    /* also add this subscribe request to the list of those going out to the domain in question.*/
		    ADD_USUB_TO_DOMAIN(ulist,fu);
	       }
	       
	  }

     if (!ri->is_ssp)
	  sprintf(tmp3, "userid = %lld", uid); /* must be a list for the user. */
     else 
	  sprintf(tmp3, "FALSE");
     for (i = 0, n = gwlist_len(cl); i<n; i++)
	  if ((ctl = gwlist_get(cl, i)) != NULL) {
	       int64_t cid;
	       int islocal;
	       
	       extract_id_and_domain((char *)ctl->str, xid, xdomain);
	       
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       
	       cid = get_contactlist(c, tmp1, tmp2, tmp3, &islocal);
	       
	       if (cid < 0) {
		    Octstr *s = octstr_format("No such contact list: %s", (void *)ctl->str);
		    DetailedResult_t rs = csp_msg_new(DetailedResult, NULL, 
						      FV(code,700), 
						      FV(descr, csp_String_from_bstr(s, 
										     Imps_Description)));	  
		    gwlist_append(dl, rs);
		    octstr_destroy(s);
		    continue;
	       }
	       
	       /* insert all into watcher list and return them as well. */
	       sprintf(cmd, "DELETE FROM presence_watchlists WHERE sessid=%lld AND "
		       " userid IS NOT NULL AND "
		       " userid IN (SELECT local_userid FROM contactlist_members WHERE cid = %lld "
		       " and local_userid IS NOT NULL)", 
		       sid, cid);
	       r = PQexec(c, cmd);
	       PQclear(r);
	  }
	       
     
     /* for the foreign ones, queue the unsubscribe message, and send out. */
     
     selfu = csp_String_from_bstr(ri->userid, Imps_UserID);
     st = make_sender_struct2(ri->userid, clientid, NULL, NULL);

     xl = dict_keys(d);	      
     for (i = 0, n = gwlist_len(xl); i < n; i++) {
	  Octstr *x = gwlist_get(xl, i);
	  UnsubscribePresence_Request_t sp = dict_get(d, x);
	  
	  queue_foreign_msg_add(c, sp, Imps_UnsubscribePresence_Request, 
				st,
				uid, clientid ? octstr_get_cstr(clientid) :  NULL,
				NULL, 
				octstr_get_cstr(x), NULL,
				ri->ver,
				time(NULL) + DEFAULT_EXPIRY);
     }
          
     res = csp_msg_new(Result, NULL,
		       FV(code, (dl && gwlist_len(dl) > 0) ? 201 : 200),
		       FV(descr, csp_String_from_cstr("Complete", Imps_Description)),
		       FV(drlist, dl));
     resp = csp_msg_new(Status,NULL, 
			FV(res, res));

     dict_destroy(d);		     
     csp_msg_free(selfu);
     gwlist_destroy(xl, (void *)octstr_destroy);
     csp_msg_free(st);

     return resp;
}


GetWatcherList_Response_t handle_get_watcher(RequestInfo_t *ri, GetWatcherList_Request_t req  )
{
     int64_t uid = ri->uid;
     List *l, *wl = NULL, *ul = NULL;
     int i, n, max;
     GetWatcherList_Response_t resp;
     char cmd[512];
     PGresult *r;
     PGconn *c = ri->c;
     
     gw_assert(req);
     
     
     l = gwlist_create();
     if (csp_msg_field_isset(req, max_wlist))
	  max = req->max_wlist;
     else 
	  max = -1;
     
     sprintf(cmd, "SELECT local_userid,foreign_userid FROM pr_watchlist_user_view WHERE "
	     " userid = %lld", uid);

     r = PQexec(c, cmd);
     
     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
     for (i = 0; i<n;i++) {
	  char *u = PQgetvalue(r, i, 0);
	  char *f = PQgetvalue(r, i, 1);
	  void *value;
	  Watcher_t w;
	  UserID_t uid;
	  User_t xuser;
	  
	  if (max >= 0 && n > max)
	       break;
	
	  uid = csp_String_from_cstr(u && u[0] ? u : f, Imps_UserID);
	  if (ri->ver > CSP_VERSION(1,1)) {
	       value = w = csp_msg_new(Watcher, NULL, 
				       FV(wstatus, csp_String_from_cstr("CURRENT_SUBSCRIBER", 
									Imps_WatcherStatus)));
	       
	       if (ri->ver<CSP_VERSION(1,3))
		    CSP_MSG_SET_FIELD(w, uid, csp_msg_new(User, NULL, 
							  FV(user,uid)));
	       else 
		    CSP_MSG_SET_FIELD(w, user, uid);
	       
	  } else 
	       value  = xuser = csp_msg_new(User, NULL, FV(user,uid));
	  
	  gwlist_append(l, value);
     }
     
     PQclear(r);
     
     if (ri->ver <= CSP_VERSION(1,1)) /* set the right field. */
	  ul = l;
     else 
	  wl = l;

     resp = csp_msg_new(GetWatcherList_Response,NULL,
			FV(watcher,wl), 
			FV(wusers, ul));
     
     if (ri->ver > CSP_VERSION(1,2) && max>=0)
	  CSP_MSG_SET_FIELD(resp, wcount,n);
     
     
     return resp;
}

/* only used for v1.2 and v1.1 */
Status_t handle_pres_auth_user(RequestInfo_t *ri, PresenceAuth_User_t req  )
{
     unsigned long attribs;
     int64_t uid = ri->uid, xuid;

     int  n, islocal;
     Result_t rs;     
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];     
     char cmd[512],  tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN], tmp4[DEFAULT_BUF_LEN], tmp3[DEFAULT_BUF_LEN], *s;
     char field[32], val[256];
     PGresult *r;
     PGconn *c = ri->c;
     
     gw_assert(req);
     
     /* Find the user, if local. */
     s = req->user ? (char *)req->user->str : "";
     extract_id_and_domain(s, xid, xdomain);
     PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
     PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
     xuid = get_userid(c, tmp1, tmp2, &islocal);
     
     if (xuid < 0 && islocal) {
	  Octstr *_x = octstr_format("Unknown UserID: %s", s);
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,531), 
			   FV(descr, csp_String_from_bstr(_x,
							  Imps_Description)));	  

	  octstr_destroy(_x);
	  goto done;
     }
	
     
     if (req->pslist == NULL)
	  attribs = ALL_PRES_ATTRIBS;
     else 
	  attribs = MSG_GET_BITS(req->pslist);
     
     /* create criteria for update. */
     if (req->accept) 
	  sprintf(tmp3, "attribs_authorised = attribs_authorised | %lu", attribs);
     else 
	  sprintf(tmp3, "attribs_authorised = attribs_authorised & %lu", ~attribs); /* deny any attribs set. */

     if (xuid >= 0) {
	  strcpy(field, "local_userid");
	  sprintf(val, "%lld", xuid);
     } else {
	  strcpy(field, "foreign_userid");
	  sprintf(val, "'%.128s%s%.128s'", 
		  tmp1, tmp2[0] ? "@" : "", tmp2);
     }
     
     sprintf(cmd, "UPDATE presence_auth_authorisations SET %s=%s WHERE userid=%lld AND %s RETURNING id",
	     field, val, uid, tmp4);

     r = PQexec(c, cmd);
     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
     
     PQclear(r);
     
     if (n == 0) { /* an accepted/rejected request for auth with an empty previous authorisation */
	  sprintf(cmd, "INSERT INTO presence_user_authorisations (userid, %s, attribs_authorised) "
		  "VALUES (%lld, %s, %lu)",
		  field, uid, val, 
		  req->accept ? attribs : ~attribs); /* authorise all but mentioned. XXX correct? */
	  r  = PQexec(c, cmd);
	  PQclear(r); /* ignore result. */
     } 
     
     rs = csp_msg_new(Result, NULL, 
		      FV(code,200), 
		      FV(descr, csp_String_from_cstr("Complete",
						     Imps_Description)));	  
     
 done:
     
     
     return csp_msg_new(Status,NULL,  FV(res,rs));
}

#define ADD_GETPR_TO_DOMAIN(_val) do					\
	  if (!ri->is_ssp) {						\
	       GetPresence_Request_t sp;				\
	       _User_List_t _ul;					\
	       Octstr *_x = octstr_create(xdomain);			\
	       if ((sp = dict_get(d, _x)) == NULL) {			\
		    _ul = csp_msg_new(_User_List, NULL, FV(ulist,gwlist_create())); \
		    sp = csp_msg_new(GetPresence_Request, NULL,		\
				     UFV(u, Imps__User_List, _ul),	\
				     FV(pslist,csp_msg_copy(req->pslist)) ); \
		    dict_put(d, _x, sp);				\
	       } else _ul = sp->u.val;					\
	       octstr_destroy(_x);					\
	       gwlist_append(_ul->ulist, _val);				\
	  } else {							\
	       Octstr *err = octstr_format("Forwarding to domain %s is not supported!", (xdomain)); \
	       DetailedResult_t _dr = csp_msg_new(DetailedResult, NULL, \
						  FV(code,516),		\
						  FV(descr, csp_String_from_bstr(err, \
										 Imps_Description))); \
	       gwlist_append(dl, _dr);					\
	       octstr_destroy(err);					\
	  }								\
     while (0)
       

GetPresence_Response_t handle_get_presence(RequestInfo_t *ri, GetPresence_Request_t req )
{
     int64_t uid = ri->uid;
     List *ul = NULL, *cl = NULL, *dl, *xl = NULL, *pl = NULL;
     unsigned long attribs;
     int i, n;
     Result_t res;
     GetPresence_Response_t resp;
     Dict *d = dict_create(7, (void *)_csp_msg_free); /* contains subscribe requests, indexed by domain.*/
     void *u;
     ContactList_t ctl;
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];     
     char cmd[512], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN*2];
     char tmp3[DEFAULT_BUF_LEN*2 + 1];
     Sender_t st = NULL;
     Octstr *clientid = ri->clientid;
     PGresult *r;
     PGconn *c = ri->c;
     UserID_t selfu = NULL;
     
     gw_assert(req);     
     
     /* several options because of differences between 1.1/1.2 and 1.3 */
     if (req->u.typ == Imps_UserIDList)
	  ul = req->u.val ? ((UserIDList_t)req->u.val)->ulist : NULL;
     else if (req->u.typ == Imps__User_List)
	  ul = req->u.val ? ((_User_List_t)req->u.val)->ulist : NULL; /* list of User_t. */
     else if (req->u.typ == Imps__Contact_List)
	  cl = req->u.val ? ((_Contact_List_t)req->u.val)->clist : NULL;
     else if (req->u.typ == Imps_ContactListIDList)
	  cl = req->u.val ? ((ContactListIDList_t)req->u.val)->clist : NULL;
     else 
	  panic(0, "unexpected type %d [%s] in union", req->u.typ, csp_obj_name(req->u.typ));
     
     /* build the sender element: we need it. */
     selfu = csp_String_from_bstr(ri->userid, Imps_UserID);     
     st = make_sender_struct2(ri->userid, clientid, NULL, NULL);

     dl = gwlist_create();
     pl = gwlist_create();


     attribs = req->pslist ? MSG_GET_BITS(req->pslist) : ALL_PRES_ATTRIBS;
     if (attribs == 0) 
	  attribs = ALL_PRES_ATTRIBS; /* all requested. */
     

     for (i = 0, n = gwlist_len(ul); i<n; i++)
	  if ((u = gwlist_get(ul, i)) != NULL) {
	       Presence_t p;
	       char *s = NULL;
	       int64_t xuid;
	       int islocal;
	       UserID_t xuser = NULL;
	       if (CSP_MSG_TYPE(u) == Imps_User)  {/* < v1.2 */
		    User_t xu = u;
		    xuser = xu->user;
	       }  else if (CSP_MSG_TYPE(u) == Imps_UserID)  /* v1.3 */
		    xuser = u;
	       else 
		    panic(0, "unexpected object type: %d [%s]", 
			  CSP_MSG_TYPE(u), csp_obj_name(CSP_MSG_TYPE(u)));
	       
	       s = xuser ? (void *)xuser->str : "";
	       
	       extract_id_and_domain(s, xid, xdomain);
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       xuid = get_userid(c, tmp1, tmp2, &islocal);
	       
	       if (xuid < 0 && islocal) {
		    Octstr *_x = octstr_format("Unknown UserID: %s", s);
		    void *rs = csp_msg_new(DetailedResult, NULL, 
					   FV(code,531), 
					   FV(descr, csp_String_from_bstr(_x,
									  Imps_Description)));	  
		    gwlist_append(dl, rs);
		    octstr_destroy(_x);
		    continue;
	       }
	       
	       if (xuid >= 0) 
		    p = get_authorised_presence_ex(c, uid, 
						   uid >= 0 ? NULL : 
						   octstr_get_cstr(ri->userid),
						   xuser, xuid, attribs, ri->ver);
	        else {
		    User_t fu = csp_msg_new(User,NULL,
					    FV(user, csp_String_from_cstr(s, Imps_UserID)));		    
#if 0
		    /* May be we should report user as offline for now, while real presence comes back?  XXX */
		    UserID_t xuser = csp_String_from_cstr(s, Imps_UserID);
		    _User_Presence_t up = csp_msg_new(_User_Presence, NULL,
						      FV(user,xuser));
		    OnlineStatus_t os = csp_msg_new(OnlineStatus, NULL,
						    FV(qual, 1),
						    FV(pvalue, csp_String_from_cstr("F", 
										    Imps_PresenceValue)));
		    UserAvailability_t ua = csp_msg_new(UserAvailability, NULL,
							FV(qual, 1), 
							FV(pvalue, csp_String_from_cstr("NOT_AVAILABLE", 
											Imps_PresenceValue)));
		    Status_t xcstatus = csp_msg_new(Status, NULL, FV(_content, octstr_imm("OPEN")));
		    CommC_t cc = csp_msg_new(CommC, NULL,
					     FV(cap, csp_String_from_cstr("IM", Imps_Cap)),
					     FV(status, xcstatus),
					     FV(contact, csp_String_from_cstr(xuser, Imps_Contact)),
					     FV(note, csp_String_from_cstr("IM online", Imps_Note)));
		    CommCap_t ccp = csp_msg_new(CommCap, NULL,
						FV(commc, gwlist_create_ex(cc)),
						FV(qual, 1));
			
		    PresenceSubList_t ps = csp_msg_new(PresenceSubList, 
						       octstr_imm("http://www.openmobilealliance.org/DTD/IMPS-PA1.3"),
						       FV(avail, ua),
						       FV(ostatus, gwlist_create_ex(os)),
						       FV(commcap, gwlist_create_ex(ccp)));
		    p = csp_msg_new(Presence, NULL, 
				    UFV(pres,Imps__User_Presence,up),
				    FV(pslist, gwlist_create_ex(ps)));	       
#else 
		    p = NULL;
#endif	    
		    ADD_GETPR_TO_DOMAIN(fu);
	       }
	       if (p)
		    gwlist_append(pl, p);			 			     
	       	       
	  }

     /* Now handle the contactlist presence info request. */
     if (!ri->is_ssp)
	  sprintf(tmp3, "userid = %lld", uid); /* must be a list for the user. */
     else 
	  sprintf(tmp3, "FALSE"); /* no access to contact lists from ssp. */
     for (i = 0, n = gwlist_len(cl); i<n; i++)
	  if ((ctl = gwlist_get(cl, i)) != NULL) {
	       int64_t cid;
	       int islocal, j, m;
	       
	       extract_id_and_domain((char *)ctl->str, xid, xdomain);
	       
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       
	       cid = get_contactlist(c, tmp1, tmp2, tmp3, &islocal);
	       
	       if (cid < 0) {
		    Octstr *s = octstr_format("No such contact list: %s", (void *)ctl->str);
		    DetailedResult_t rs = csp_msg_new(DetailedResult, NULL, 
						      FV(code,700), 
						      FV(descr, csp_String_from_bstr(s, 
										     Imps_Description)));	  
		    gwlist_append(dl, rs);
		    octstr_destroy(s);
		    continue;
	       }
	       
	       sprintf(cmd, "SELECT local_userid,foreign_userid, localuserid FROM contactlist_members_view WHERE cid = %lld ",
		       cid);
	       r = PQexec(c, cmd);
	       
	       m = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
	       for (j = 0; j<m; j++) {
		    char *lu = PQgetvalue(r, j, 0);
		    char *fu = PQgetvalue(r, j, 1);
		    char *xu = PQgetvalue(r, j, 2);
		    
		    if (PQgetisnull(r,j,0) == 0) { /* a local user. */
			 int64_t xuid = strtoull(lu, NULL, 10);
			 UserID_t x = csp_String_from_cstr(xu, Imps_UserID);
			 
			 Presence_t p = get_authorised_presence_ex(c, uid, NULL, x, xuid, attribs, ri->ver);
			 if (p)
			      gwlist_append(pl, p);			 			 
			 csp_msg_free(x);
		    } else {
			 User_t x = csp_msg_new(User,NULL,
						FV(user, csp_String_from_cstr(fu, Imps_UserID)));
			 ADD_GETPR_TO_DOMAIN(x);
		    }
	       }
	       PQclear(r);
	  }
     

     /* for the foreign ones, queue the getpresence message, and send out. */
     
     xl = dict_keys(d);	      
     for (i = 0, n = gwlist_len(xl); i < n; i++) {
	  Octstr *x = gwlist_get(xl, i);
	  GetPresence_Request_t sp = dict_get(d, x);
	  
#if 1
	  if (ri->ver <= CSP_VERSION(1,1) && 
	      sp->pslist) {  /* XXX some nokia require this?? */
	       if (!csp_msg_field_isset(sp->pslist, commcap)) 
		    CSP_MSG_SET_FIELD(sp->pslist, commcap, 
				      gwlist_create_ex(csp_msg_new(CommCap, NULL, NULL)));
	       if (!csp_msg_field_isset(sp->pslist, cinfo))
		    CSP_MSG_SET_FIELD(sp->pslist, cinfo, gwlist_create_ex(csp_msg_new(ClientInfo, NULL, NULL)));
	  }
#endif

	  queue_foreign_msg_add(c, sp, Imps_GetPresence_Request, st, 
				uid, clientid ? octstr_get_cstr(clientid) :  NULL,
				NULL, 
				octstr_get_cstr(x), NULL,
				ri->ver, 
				time(NULL) + DEFAULT_EXPIRY);
     }
     
     
     res = csp_msg_new(Result, NULL,
		       FV(code, (dl && gwlist_len(dl) > 0) ? 201 : 200),
		       FV(descr, csp_String_from_cstr("Complete", Imps_Description)),
		       FV(drlist, dl));
     resp = csp_msg_new(GetPresence_Response,NULL, 
			FV(res, res),
			FV(plist, pl));

     dict_destroy(d);     	     
     csp_msg_free(selfu);
     gwlist_destroy(xl, (void *)octstr_destroy);
     csp_msg_free(st);

     return resp;
}

int update_pres_info(PGconn *c, PresenceSubList_t newps, int64_t sessid, int64_t uid, int pres_src)
{
     PresenceSubList_t oldps;

     if ((oldps = get_pres(c, uid, sessid, -1)) != NULL) { /* patch the previous (session) presence */
	  int i, n = csp_type_field_count(Imps_PresenceSubList);
	  
	  /* Go through the ones that are already set, and which need updating, update them accordingly. */
	  for (i = 0; i < n; i++)
	       if (MSG_GET_BIT(newps, i)) {
		    struct imps_struct_fields_t st = struct_types[Imps_PresenceSubList][i];
		    if (!MSG_GET_BIT(oldps, i))  /* if not previously set, set it. */
			 CSP_COPY_FIELD(newps,oldps,st.nature,i);
		    else {
			 if (st.nature != IList) {/* not a list, just clear old one and replace it. */
			      csp_struct_clear_fields(oldps, BIT_MASK(i));
			      CSP_COPY_FIELD(newps,oldps,st.nature,i);
			 } else { /* ... a list of items. */
			      List *new_l = csp_msg_get_field_value(newps, i);
			      List *l = gwlist_create();
			      int j, m;
			      
			      /* replace with new one. */
			      csp_struct_clear_fields(oldps, BIT_MASK(i));
			      
			      for (j = 0, m = gwlist_len(new_l); j<m; j++)
				   gwlist_append(l, 
						 csp_msg_copy(gwlist_get(new_l, j)));			      
			      csp_msg_set_field_value(oldps, i, l); 			      
			 }			 
		    }		    
	       }
	  
	  newps = oldps; /* replace it with updated one. */
     }
     
     /* Save it. */
     save_pres(c, newps, sessid);
     
     csp_msg_free(oldps);
          
     send_user_presence(c, uid, ALL_PRES_ATTRIBS, NULL, NULL); /* send presence information to all and sundry. */
         
     return 0;
}

Status_t handle_update_presence(RequestInfo_t *ri, UpdatePresence_Request_t req  )
{
     Result_t rs;
     PGconn *c = ri->c;
     
     gw_assert(req);     
     
     update_pres_info(c, req->pslist, ri->sessid, ri->uid, PRES_FROM_CLIENT);
     rs = csp_msg_new(Result, NULL, 
		      FV(code,200), 
		      FV(descr, csp_String_from_cstr("Complete", Imps_Description)));     
     
     return   csp_msg_new(Status,NULL,  FV(res,rs));	  
}
