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
/* queue handling */
#include <gwlib/gwlib.h>
#include <libpq-fe.h>

#include "mqueue.h"
#include "utils.h"
#include "pgconnpool.h"
#include "cspmessages.h"
#include "cspcir.h"
#include "ssp.h"

Octstr *format_sender(Sender_t sender);
extern struct imps_conf_t *config;
int64_t queue_foreign_msg_add(PGconn *c, void *msg, int type, Sender_t sender, 
			      int64_t sender_uid, 
			      char *clientid,
			      Octstr *msgid, 
			      char *domain, List *dest_userids, 
			      int csp_ver,
			      time_t expiryt)
{
     Octstr *out = csp_msg_to_str(msg, type);
     const char *name = csp_obj_name(type);
     Octstr *sstr = make_sender_str(sender);
     
     time_t tnow = time(NULL);
     char *xdata, tmp1[128], tmp2[128], tmp3[128+4], tmp4[128+2], tmp5[64];
     size_t dlen;
     Octstr *cmd;
     int64_t mid;
     PGresult *r;
     
     gw_assert(out);
     

     /* fix expiry time */
     if (expiryt  <= tnow + config->min_ttl)
	  expiryt = tnow + DEFAULT_EXPIRY;
     
     PQ_ESCAPE_STR(c, octstr_get_cstr(sstr), tmp1);
     PQ_ESCAPE_STR_LOWER(c, domain, tmp2);
     
     xdata = (void *)PQescapeBytea((void *)octstr_get_cstr(out), octstr_len(out), &dlen);
     
     if (msgid)
	  sprintf(tmp3, "'%.128s'", octstr_get_cstr(msgid));
     else 
	  sprintf(tmp3, "NULL");
     
     if (clientid) {
	  char tmp[128];
	  PQ_ESCAPE_STR(c, clientid, tmp);
	  sprintf(tmp4, "'%.128s'", tmp);
     } else 
	  sprintf(tmp4, "NULL");

     if (sender_uid >= 0)
	  sprintf(tmp5, "%lld", sender_uid);
     else 
	  sprintf(tmp5, "NULL");

     cmd = octstr_format("INSERT INTO ssp_message_queue (edate, sender, domain, msg_type,msg_data, "
			 "msgid, userid, clientid, csp_ver) "
			 " VALUES ('epoch'::timestamp with time zone + '%ld secs'::interval, "
			 " '%.128s', '%.128s', '%.64s', E'%s'::bytea, %s, %s, %s, %d) RETURNING id",
			 expiryt, tmp1, tmp2, name, xdata, tmp3, tmp5, tmp4, csp_ver);
     
     r = PQexec(c, octstr_get_cstr(cmd));     
     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
	  error(0, "failed to (ssp)queue message type [%s] from [%.128s]: %s",
		name, octstr_get_cstr(sstr), PQerrorMessage(c));
	  mid = -1;
     } else { 	  
	  int i, n;
	  UserID_t u;
	  User_t xu;
	  void *x;
	  char *ssp_id = PQgetvalue(r, 0, 0);

	  
	  mid = strtoull(ssp_id, NULL, 10);	  
	  for (i = 0, n = gwlist_len(dest_userids); i<n;i++) 
	       if ((x = gwlist_get(dest_userids, i)) != NULL) {
		    char cmd[512];
		    Octstr *clid;
		    PGresult *r2;

		    if (CSP_MSG_TYPE(x) == Imps_UserID) {
			 u = x;			 
			 clid = octstr_imm("");
		    } else {
			 xu = x;
			 u = xu->user;
			 
			 clid = make_clientid(xu->u.typ == Imps_ClientID ? xu->u.val : NULL,
					      xu->u.typ == Imps_ApplicationID ? xu->u.val : NULL);	 
		    }
		    PQ_ESCAPE_STR_LOWER(c, u ? (char *)u->str : "", tmp1);
		    PQ_ESCAPE_STR(c, (char *)octstr_get_cstr(clid), tmp2);
		    sprintf(cmd, "INSERT INTO ssp_message_recipients (messageid, foreign_userid, clientid) "
			    " VALUES (%lld, '%.128s', '%.128s')", mid, tmp1, tmp2);
		    r2 = PQexec(c, cmd);
		    PQclear(r2);

		    octstr_destroy(clid);
	       }	  
	  pg_cp_on_commit(c, (void *)notify_sspd, octstr_create(ssp_id)); /* Tell ssp of this message.*/
     }
     PQclear(r);

     
     octstr_destroy(sstr);
     octstr_destroy(cmd);
     PQfreemem(xdata);
     octstr_destroy(out);
     
     return mid;     
}

int64_t queue_local_msg_add(PGconn *c, void *msg, int type, Sender_t sender, struct QLocalUser_t localids[],
			    int num, 
			    int dlr,
			    Octstr *msgid, 
			    char *rcpt_struct_path,
			    time_t expiryt)
{
     Octstr *out = csp_msg_to_str(msg, type);
     const char *name = csp_obj_name(type);
     Octstr *sstr = make_sender_str(sender);
     time_t tnow = time(NULL);
     char *xdata, tmp1[128+4], tmp3[128+4];
     int i;
     size_t dlen;
     Octstr *cmd;
     int64_t mid;
     PGresult *r;
     
     gw_assert(out);

     /* fix expiry time */
     if (expiryt <= tnow + config->min_ttl)
	  expiryt = tnow + DEFAULT_EXPIRY;


     PQ_ESCAPE_STR(c, octstr_get_cstr(sstr), tmp1);

     xdata = (void *)PQescapeBytea((void *)octstr_get_cstr(out), octstr_len(out), &dlen);
     
     if (msgid)
	  sprintf(tmp3, "'%.128s'", octstr_get_cstr(msgid));
     else 
	  sprintf(tmp3, "NULL");

     cmd = octstr_format("INSERT INTO csp_message_queue (edate, sender, msg_type,msg_data, delivery_report, "
			 "internal_rcpt_struct_path, msgid) "
			 " VALUES ('epoch'::timestamp with time zone + '%ld secs'::interval, "
			 " '%.128s', '%.64s', E'%s'::bytea, %s, '%s', %s) RETURNING id",
			 expiryt, tmp1, name, xdata, dlr ? "true" : "false",
			 rcpt_struct_path ? rcpt_struct_path : "", /* XXX we trust this one since it is internal. */
			 tmp3);
     
     r = PQexec(c, octstr_get_cstr(cmd));     
     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
	  error(0, "failed to queue message type [%s] from [%.128s]: %s",
		name, octstr_get_cstr(sstr), PQerrorMessage(c));
	  mid = -1;
	  PQclear(r);
	  
	  goto done;
     }
     
     mid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
     PQclear(r);
     
     /* Now write the queue entries. */

     for (i = 0; i<num; i++) {
	  u_int64_t uid = localids[i].uid;
	  char *clid = localids[i].clientid;
	  char tmp2[256], cmd[512];
	  char *sname = localids[i].sname;
	  
	  PQ_ESCAPE_STR(c, clid, tmp1);
	  PQ_ESCAPE_STR(c, sname, tmp2);
	  
	  sprintf(cmd, "INSERT INTO csp_message_recipients (messageid, userid,clientid,screen_name) VALUES "
		  " (%lld, %lld, '%.128s', '%.256s')", mid, uid, tmp1, tmp2);
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_COMMAND_OK) {
	       error(0, "csp_message_recipients write failed: %s", PQerrorMessage(c));
	       mid = -1;
	       PQclear(r);
	       break;
	  } else {
	    CIRTarget_t *xcirt = make_cir_target(uid, clid);
	    pg_cp_on_commit(c, (void *)cir_newmsg, xcirt);
	  }
	  PQclear(r);

     }
     

 done:
     octstr_destroy(sstr);
     octstr_destroy(cmd);
     PQfreemem(xdata);
     octstr_destroy(out);

     return mid;
}



#define ADD_UID(xuid, clid, xscreen_name) do { \
                   ADD_QLOCAL_USER(xuid, ulist, clid, xscreen_name); \
                   *localids = ulist; \
                  } while (0)

#define ADD_RCPT_ELEM(fname, dom, val) do \
	  if (!is_ssp) {						\
	       Octstr *x = octstr_create(dom);				\
	       Recipient_t r;						\
	       /* this is a foreign one... lookup the domain in our list, or create it. */ \
	       if ((r = dict_get(d, x)) == NULL) {			\
		    r = csp_msg_new(Recipient,NULL, NULL);		\
		    dict_put(d, x, r);					\
	       }							\
	       if (r->fname == NULL)					\
		    CSP_MSG_SET_FIELD(r, fname, gwlist_create());	\
	       								\
	       gwlist_append(r->fname, val);				\
	       octstr_destroy(x);					\
	  } else { /* SSP, so we have an error. */			\
	       Octstr *err = octstr_format("Forwarding to domain %s is not supported!", (dom));	\
	       DetailedResult_t _dr = csp_msg_new(DetailedResult, NULL, \
						  FV(code,516),		\
						  FV(descr, csp_String_from_bstr(err, \
										 Imps_Description))); \
	       gwlist_append(*error_list, _dr);				\
	       octstr_destroy(err);					\
	  }								\
     while (0)

Dict *queue_split_rcpt(PGconn *c, struct QSender_t xsender, 
		       Recipient_t to, int isinvite, 
		       struct QLocalUser_t **localids,
		       int *localid_count, List **error_list, 
		       Sender_t *fixed_sender, int is_ssp)
{
     Dict *d = dict_create(7, _csp_msg_free);
     int i, n,  nelems, nalloc = ALLOC_BSIZE, islocal;
     char tmp1[DEFAULT_BUF_LEN + 1], tmp2[DEFAULT_BUF_LEN + 1], tmp_sender[DEFAULT_BUF_LEN];
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN], xclientid[DEFAULT_BUF_LEN + 1];
     
     char cmd[512*2];
     PGresult *r;
     User_t u;
     ContactList_t cl;
     Group_t g;
     struct QLocalUser_t *ulist; /* convenience. */

     gw_assert(to);
     gw_assert(localids);
     gw_assert(error_list);
     
     ulist = *localids = gw_malloc(nalloc*sizeof **localids);
     nelems = *localid_count = 0;
     *error_list = gwlist_create();
     
     /* prepare the sender. */
     if (xsender.type == QForeign_User) 
	  PQ_ESCAPE_STR(c, xsender.u.fid, tmp_sender);
          
     PQ_ESCAPE_STR(c, xsender.clientid, xclientid);

     /* first we tackle users (easy ones !) */

     for (i = 0, n = gwlist_len(to->ulist); i<n; i++)
	  if ((u = gwlist_get(to->ulist, i)) != NULL) {
	       int64_t uid;
	       char *user = u->user ? u->user->str : (void *)"";

	       extract_id_and_domain(user, xid, xdomain);

	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       
	       uid = get_userid(c, tmp1, tmp2, &islocal);
	       
	       
	       if (uid < 0 && islocal) {
		    Octstr *err = octstr_format("invalid userid: %.128s", user);
		    DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
						      FV(code,427),
						      FV(descr, 
							 csp_String_from_bstr(err, 
									      Imps_Description)));
		    
		    gwlist_append(*error_list, dr); /* add to list of errors. */
		    octstr_destroy(err);
		    
		    continue;
	       }
	       
	       if (uid >= 0) { /* local user. */
		    ClientID_t _c = (u->u.typ == Imps_ClientID) ? u->u.val : NULL;
		    ApplicationID_t _a = (u->u.typ == Imps_ClientID) ? NULL : u->u.val;
		    Octstr *x = make_clientid(_c, _a);
		    
		    ADD_UID(uid, octstr_get_cstr(x), "");

		    octstr_destroy(x);
	       } else 
		    ADD_RCPT_ELEM(ulist, xdomain, csp_msg_copy(u));
	  }
     

     /* Next tackle contact lists. */

     for (i = 0, n = gwlist_len(to->clist); i<n; i++)
	  if ((cl = gwlist_get(to->clist, i)) != NULL) {
	       
	       extract_id_and_domain((void *)cl->str, xid, xdomain);
	       
	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);

	       if ((islocal = get_islocal_domain(c, xdomain)) != 0) {
		    int64_t cid;
		    char crit[64];
		    int j, m;
		    
		    if (xsender.type == QLocal_User)
			 sprintf(crit, " AND userid = %lld", xsender.u.uid);
		    else if (xsender.type == QForeign_User) 
			 sprintf(crit, " AND FALSE"); /* no access to contact lists from non-local users */
		    else 
			 crit[0] = 0;
		    
		    sprintf(cmd, "SELECT id FROM contactlists WHERE cid='%.128s' AND domain='%.128s' %s",
			    tmp1, tmp2, crit);
		    
		    r = PQexec(c, cmd);
		    
		    if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
			 Octstr *err = octstr_format("invalid contactlist: %.128s", cl->str);
			 DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
							   FV(code,700),
							   FV(descr, 
							      csp_String_from_bstr(err, 
										   Imps_Description)));
			 
			 gwlist_append(*error_list, dr); /* add to list of errors. */
			 octstr_destroy(err);
			 
			 PQclear(r);
			 continue;		    
		    }

		    cid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
		    PQclear(r);

		    /* Get list members, and build the list. */ 
		    sprintf(cmd, "SELECT local_userid, foreign_userid, cname FROM contactlist_members" 
			    " WHERE cid = %lld", cid);
		    r = PQexec(c, cmd);

		    if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 0) {
			 error(0, "failed to query for list elements: %s", PQerrorMessage(c));
			 m = 0;
		    } else
			 m = PQntuples(r);

		    for (j = 0; j < m; j++) {
			 char *user = PQgetvalue(r, j, 0);
			 char *fuser = PQgetvalue(r, j, 1);
			 char *name = PQgetvalue(r, j, 2);
			 
			 if (user && user[0]) 
			      ADD_UID(strtoull(user, NULL, 10),"", "");
			 else if (fuser) { /* foreign user -- add to recipient list for that domain.*/
			      User_t u;
			      FriendlyName_t f;

			      extract_id_and_domain(fuser, xid, xdomain);
			      
			      f = (name) ? csp_String_from_cstr(name, Imps_FriendlyName) : NULL;
			      u = csp_msg_new(User, NULL,
					      FV(user,csp_String_from_cstr(fuser, Imps_UserID)),
					      FV(fname, f));
			      ADD_RCPT_ELEM(ulist, xdomain, u);
			      
			 }
		    }
		    PQclear(r);
		    
	       } else  { /* not a local list. */
		    Octstr *err = octstr_format("invalid contact list refrence: %.128s", cl->str);
		    DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
						      FV(code,700),
						      FV(descr, 
							 csp_String_from_bstr(err, 
									      Imps_Description)));
		    
		    gwlist_append(*error_list, dr); /* add to list of errors. */
		    octstr_destroy(err);
#if 0
		    ADD_RCPT_ELEM(clist, xdomain, csp_msg_copy(cl));	       
#endif
	       }
	  }

     /* now handle groups. */
     for (i = 0, n = gwlist_len(to->glist); i<n; i++)
	  if ((g = gwlist_get(to->glist, i)) != NULL) {
	       char *scrname = NULL;
	       ScreenName_t sname = NULL;
	       GroupID_t grp = NULL;
	       char *xsname;
	       
	       if (g->u.typ == Imps_ScreenName) {
		    sname = g->u.val;
		    gw_assert(sname->gid);
		    grp = sname->gid;
	       } else if (g->u.typ == Imps_GroupID) {
		    sname = NULL;
		    grp = g->u.val;
	       } else 
		    panic(0, "Group contains unexpected element type: %d:%s",
			  g->u.typ, csp_obj_name(g->u.typ));
	       		    
	       /* Get the group ID and  members if local, else pass on responsibility. */
	       extract_id_and_domain((void *)grp->str, xid, xdomain);

	       PQ_ESCAPE_STR_LOWER(c, xid, tmp1);
	       PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
	       
	       if ((islocal = get_islocal_domain(c, tmp2))) {
		    int64_t gid;
		    char crit[256], crit2[256], seln[256];
		    int j, m;
		    
		    crit2[0] = 0;
		    if (xsender.type == QLocal_User) { /* must be a joined. */
			 sprintf(crit, " AND 1 IN (SELECT  1 FROM group_members  WHERE groupid = groups.id AND "
				 " local_userid = %lld AND isjoined = TRUE)", xsender.u.uid);
			 sprintf(crit2, " AND local_userid <> %lld ", xsender.u.uid); /* skip self in broadcast below. */
			 sprintf(seln, "SELECT screen_name FROM group_members gm WHERE gm.groupid = groups.id AND "
				 " local_userid = %lld AND clientid = '%.128s'", xsender.u.uid, xclientid);
		    } else if  (xsender.type == QForeign_User)  {
			 sprintf(crit, " AND 1 IN (SELECT  1 FROM group_members  WHERE groupid = groups.id AND "
				 " foreign_userid = '%.128s' AND isjoined=TRUE)", tmp_sender);
			 sprintf(seln, "SELECT screen_name FROM group_members gm WHERE gm.groupid = groups.id AND "
				 " foreign_userid = '%.128s' AND clientid = '%.128s'", tmp_sender, xclientid);
		    } else {			 
			 crit[0] = 0;
			 strcpy(seln, "'x'");
		    }
		    
		    sprintf(cmd, "SELECT id, "
			    " (%s) AS sname "
			    " FROM groups WHERE groupid='%.128s' AND domain='%.128s' %s",
			    seln, tmp1, tmp2, crit);
		    
		    r = PQexec(c, cmd);
		    
		    if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
			 Octstr *err = octstr_format("invalid group or not joined: %.128s", grp->str);
			 DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
							   FV(code,808),
							   FV(descr, 
							      csp_String_from_bstr(err, 
										   Imps_Description)));
			 
			 gwlist_append(*error_list, dr); /* add to list of errors. */
			 octstr_destroy(err);
			 
			 PQclear(r);
			 continue;		    
		    }
		    
		    gid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);

		    if (fixed_sender && 
			(xsname = PQgetvalue(r, 0, 1))  != NULL && xsname[0]) { /* make a sender. */
			 SName_t sn = csp_String_from_cstr(xsname, Imps_SName);
			 ScreenName_t s = csp_msg_new(ScreenName, NULL,
						      FV(sname, sn),
						      FV(gid, csp_msg_copy(grp)));
			 Group_t xg = csp_msg_new(Group, NULL,
						  UFV(u, Imps_ScreenName, s));

			 csp_msg_free(*fixed_sender); /* free old one. */
			 *fixed_sender = csp_msg_new(Sender, NULL, 
						     UFV(u, Imps_Group, xg));
		    }
		    
		    PQclear(r);
		    
		    /* Get list members or the single recipient and build the list. */ 
		    if (sname) {
			 char tmp3[128];
			 
			 scrname = sname->sname ? sname->sname->str : (void *)"";
			 PQ_ESCAPE_STR_LOWER(c, scrname, tmp3);			 
			 sprintf(crit, " AND screen_name='%.128s'", tmp3);
		    } else if (isinvite) /* ... an invite, sent to a group. */
			 sprintf(crit, " AND member_type IN ('Admin', 'Mod') ");
		    else 
			 crit[0] = 0;
		    
		    sprintf(cmd, "SELECT local_userid, foreign_userid,screen_name,clientid, "
			    " (SELECT value FROM group_properties gp WHERE gp.groupid = gj.groupid AND item = 'PrivateMessaging') AS priv_msg "
			    " FROM group_members gj" 
			    " WHERE groupid = %lld AND isjoined=true %s %s", gid, crit, crit2);
		    r = PQexec(c, cmd);
		    
		    if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 0) {
			 Octstr *err = octstr_format("Group member(s) not found: %.128s", 
						     scrname ? scrname : "(ALL)");
			 DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
							   FV(code,410),
							   FV(descr, 
							      csp_String_from_bstr(err, 
										   Imps_Description)));
			 
			 gwlist_append(*error_list, dr); /* add to list of errors. */
			 octstr_destroy(err);
			 
			 PQclear(r);
			 continue;		    
		    } 
		    
		    for (j = 0, m = PQntuples(r); j < m; j++) {
			 char *user = PQgetvalue(r, j, 0);
			 char *fuser = PQgetvalue(r, j, 1);
			 char *suser = PQgetvalue(r, j, 2);
			 char *cluser = PQgetvalue(r, j, 3);
			 char *x = PQgetvalue(r, j, 4);			 
			 int private_msg = (x && toupper(x[0]) == 'T');
			 Octstr *xsname = format_screen_name_ex(grp->str, scrname ? suser : NULL);
			 /* above: only include screen name if the user was adressed as such. */

			 if (scrname && !private_msg) { /* private messaging not allowed. */
			      Octstr *err = octstr_format("Private Messaging not allowed: %.128s", 
							  scrname);
			      DetailedResult_t dr = csp_msg_new(DetailedResult, NULL,
								FV(code,812),
								FV(descr, 
								   csp_String_from_bstr(err, 
											Imps_Description)));
			      
			      gwlist_append(*error_list, dr); /* add to list of errors. */
			      octstr_destroy(err);			      
			 } if (user && user[0]) 
			      ADD_UID(strtoull(user, NULL, 10),cluser, octstr_get_cstr(xsname));
			 else if (fuser) { /* foreign user -- add to recipient list for that domain.*/
			      User_t u;
			      
			      extract_id_and_domain(fuser, xid, xdomain);			      
			      u = csp_msg_new(User, NULL,
					      FV(user,csp_String_from_cstr(fuser, Imps_UserID)));
			      ADD_RCPT_ELEM(ulist, xdomain, u);			      
			 }
			 octstr_destroy(xsname);
		    }
		    PQclear(r);
	       } else
		    ADD_RCPT_ELEM(glist, xdomain, csp_msg_copy(g)); 
	  }
     
     *localid_count = nelems;

     return d;
}


Octstr *make_msg_id(PGconn *c)
{
     static unsigned long ct;
     PGresult *r;
     Octstr *s;
     Octstr *res;
     unsigned long n = 0;
     
     r = PQexec(c, "SELECT nextval('message_sequence')");
     if (PQresultStatus(r) != PGRES_TUPLES_OK) 
	  warning(0, "failed to make messageid: %s", PQerrorMessage(c));
     else {
	  char *s = PQgetvalue(r, 0, 0);
	  n = strtoul(s ? s : "", NULL, 10);
     }
     PQclear(r);
     s = octstr_format("%ld %d", time(NULL), ct++);
     res = md5digest(s);
     octstr_destroy(s);
     s = octstr_format("%ld%S", n, res);
     octstr_destroy(res);
     return s;
}


int remove_disallowed_local_recipients(PGconn *c, Sender_t sender,
				       int64_t sender_uid,				       
				       struct QLocalUser_t localids[], int count,
				       List *errlist)
{
     int i, j;
     
     for (i = j = 0; i<count; i++) 
	  if (check_csp_grant(c, sender, sender_uid, localids[i].uid) == 1) /* allowed */
	       localids[j++] = localids[i]; 
	  else if (errlist) { /* append an error. */
	       char name1[DEFAULT_BUF_LEN], name[DEFAULT_BUF_LEN*2];
	       char descr[DEFAULT_BUF_LEN*3];
	       DetailedResult_t dr;
	       
	       if (sender == NULL)
		    sprintf(name, "anonymous");
	       else if (sender->u.typ == Imps_Group) {
		    Group_t g = sender->u.val;	  
		    ScreenName_t s = (g->u.typ == Imps_ScreenName) ? g->u.val : NULL;
		    GroupID_t gid = s ? s->gid : g->u.val;
		    
		    sprintf(name, "GroupID: %.128s", gid ? (char *)gid->str : "");
		    if (s) {
			 sprintf(name1, "ScreenName: %.64s", s->sname ? (char *)s->sname->str : "");
			 strcat(name, name1);
		    } 
	       } else {
		    User_t u = sender->u.val;
		    UserID_t uid = u ? u->user : NULL;
		    
		    sprintf(name, "UserID: %.64s", uid ? (char *)uid->str : "");
	       }
	       sprintf(descr, "Recipient user blocked sender - %.200s", name);
	       dr = csp_msg_new(DetailedResult, NULL, 
				FV(code, 532),
				FV(descr, csp_String_from_cstr(descr, Imps_Description)));
	       gwlist_append(errlist, dr);
	  }
     
     return j;
}

Octstr *queue_msg(PGconn *c, Sender_t sender, int64_t sender_uid, Octstr *foreign_sender, 
		  char *clientid, Recipient_t to, 
		  void *msg, int type, Recipient_t *rcpt_ptr,
		  int is_group_invite, int dlr, 
		  char *rcpt_struct_path, time_t expiryt, int is_ssp,
		  int csp_ver,
		  List **errlist)
{
     struct QSender_t qs;
     Dict *d;
     struct QLocalUser_t *localids = NULL;
     int lcount;
     List *l = NULL;
     Recipient_t tmpr;
     Octstr *x;
     Octstr *msgid = make_msg_id(c);
     Sender_t real_sender = NULL;
     
     FILL_QSENDER(qs, is_ssp, sender_uid, foreign_sender, octstr_imm(""));
     d = queue_split_rcpt(c, qs, to, is_group_invite, &localids, &lcount, errlist,
			  &real_sender, is_ssp);
     
     if (real_sender == NULL)
	  real_sender = csp_msg_copy(sender);
     
     /* Send to the foreign recipients. */
     tmpr = rcpt_ptr ? *rcpt_ptr : NULL;
     if (d && (l = dict_keys(d)) != NULL)
	  while ((x = gwlist_extract_first(l)) != NULL) {
	       Recipient_t r = dict_get(d, x);
	       
	       if (rcpt_ptr) *rcpt_ptr = r;
	       
	       /* ignore error for now?? */
	       queue_foreign_msg_add(c, msg, type, real_sender, sender_uid, clientid, msgid, 
				     octstr_get_cstr(x), NULL, csp_ver, expiryt);
	       octstr_destroy(x);
	  }
     gwlist_destroy(l, NULL);
     if (rcpt_ptr) *rcpt_ptr = tmpr;

     if (!is_ssp || 
	 type == Imps_InviteUser_Request ||
	 type == Imps_Invite_Response ||
	 type == Imps_CancelInviteUser_Request ||
	 type == Imps_SendMessage_Request)
	  lcount = remove_disallowed_local_recipients(c, sender, sender_uid, localids, lcount, *errlist);     
     /* send to local ones: Don't bother with rcpt  field. It will be fixed at final delivery. */

     if (localids && lcount > 0) 
	  queue_local_msg_add(c, msg, type, real_sender, localids, lcount, 
			      dlr, msgid, 
			      rcpt_struct_path,
			      expiryt);
     

     if (localids)
	  gw_free(localids);
     dict_destroy(d);
     csp_msg_free(real_sender);

     return msgid;
}

void queue_get_ssp_sender_info(PGconn *c, int64_t tid, int64_t *uid, Octstr **clientid, int *csp_ver, 
			       void **msg)
{
     char buf[DEFAULT_BUF_LEN];
     PGresult *r;
     
     sprintf(buf, 
	     "SELECT userid, clientid, csp_ver,msg_type,msg_data FROM " 
	     " ssp_message_queue WHERE id = %lld", 
	     tid);

     r = PQexec(c, buf);

     if (PQresultStatus(r) != PGRES_TUPLES_OK || 
	 PQntuples(r) < 1) {
	  *uid = -1;
	  *clientid = NULL;
	  *msg = NULL;
     } else {
	  Octstr *msgdata;
	  int mtype;
	  *uid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
	  *clientid = octstr_create(PQgetvalue(r, 0, 1));	  
	  *csp_ver = strtoul(PQgetvalue(r, 0, 2), NULL, 10);
	  
	  mtype = csp_name_to_type(PQgetvalue(r, 0, 3));
	  msgdata = get_bytea_data(r, 0, 4);

	  *msg = csp_msg_from_str(msgdata, mtype);

	  octstr_destroy(msgdata);
     }
     PQclear(r);
}
