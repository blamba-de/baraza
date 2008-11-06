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
#include "cspgroup.h"
#include "pgconnpool.h"
#include "utils.h"
#include "mqueue.h"

static int set_properties(PGconn *c, const char *table, const char *fkey, 
			  int64_t fkey_id, List *plist)
{
     char cmd[512];
     char tmp1[DEFAULT_BUF_LEN];
     char tmp2[DEFAULT_BUF_LEN];
     Property_t p;
     PGresult *r;
     int i, n;
     
     for (i = 0, n = gwlist_len(plist); i<n; i++)
	  if ((p = gwlist_get(plist, i)) != NULL && 
	       p->name != NULL) {
	       PQ_ESCAPE_STR(c, (char *)p->name->str, tmp1);
	       PQ_ESCAPE_STR(c, p->value ? (void *)p->value->str : "", tmp2);

	       /* first delete the item. */
	       sprintf(cmd, "DELETE FROM %s WHERE %s = %lld AND item = '%.128s'", table, fkey, fkey_id, 
		       tmp1);
	       r = PQexec(c, cmd);
	       PQclear(r);
	       
	       sprintf(cmd, "INSERT INTO %s (%s, item, value) VALUES (%lld, '%.128s', '%.128s')", 
		       table, fkey, fkey_id, tmp1, tmp2);
	       r = PQexec(c, cmd);
	       if (PQresultStatus(r) != PGRES_COMMAND_OK) {
		    PQclear(r);
		    return -1;
	       }
	       PQclear(r);
	  }
     return 0;
}

static List *get_properties(PGconn *c, const char *table, const char *fkey, 
			  int64_t fkey_id)
{
     char cmd[512];
     List *pl;

     PGresult *r;
     int i, n;

     sprintf(cmd, "SELECT item, value FROM %s WHERE %s = %lld", table, fkey, fkey_id);
     r = PQexec(c, cmd);
     
     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
     pl = gwlist_create();
     for (i = 0; i<n; i++) {
	  char *name = PQgetvalue(r, i, 0);
	  char *value = PQgetvalue(r, i, 1);
	  Property_t p  = csp_msg_new(Property, NULL,
				      FV(name, csp_String_from_cstr(name, Imps_Name)),
				      FV(value, csp_String_from_cstr(value, Imps_Value)));
	  gwlist_append(pl, p);
     }
     PQclear(r);

     return pl;
}

#define ADD_FUSER(d, fuser,clid) do { \
		    Octstr *x; \
                    List *_l; \
                    User_t xu; \
		    char xuid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN]; \
		    extract_id_and_domain(fuser, xuid, xdomain); \
                    x = octstr_create(xdomain); \
		    if ((_l = dict_get(d, x)) == NULL) { \
                         _l = gwlist_create(); \
			 dict_put(d, x, _l); \
		    } \
		     xu = make_user_struct(NULL, (fuser), (clid)); \
                     gwlist_append(_l, xu); \
		    \
		    octstr_destroy(x); \
              } while (0)

static void msg_to_joined_users(PGconn *c, int64_t gid, GroupID_t grp, void *msg, 
			 int msg_type, char *criteria)
{
     char cmd[512];
     PGresult *r;
     int i,n, nalloc = MIN_ALLOC, nelems = 0;
     struct QLocalUser_t *lu = gw_malloc(nalloc * sizeof lu[0]);
     Dict *d = dict_create(7, NULL);  /* we'll destroy contents ourselves. */
     List *l;
     time_t expiryt;
     Sender_t sender;
     void *x;

     sprintf(cmd,
	     "SELECT local_userid, foreign_userid,clientid,screen_name  "
	     "FROM group_members WHERE groupid=%lld AND "
	     " isjoined = true AND %s", gid, criteria && criteria[0] ? criteria : "TRUE");
     
     r = PQexec(c, cmd);
     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;

     for (i = 0; i<n; i++) {
	  char *u = PQgetvalue(r, i, 0);
	  char *f = PQgetvalue(r, i, 1);
	  char *clid = PQgetvalue(r, i, 2);
	  char *sname = PQgetvalue(r, i, 3);

	  if (u && u[0])
	       ADD_QLOCAL_USER(strtoull(u, NULL, 10), lu, clid, sname);
	  else /* foreign user. */
	       ADD_FUSER(d, f, clid);	  	  
     }
     PQclear(r);

     /* queue the message outgoing. */
     x = csp_msg_copy(grp);
     x = csp_msg_new(Group,NULL,
		     UFV(u, Imps_GroupID, x));
     sender = csp_msg_new(Sender, NULL,
			  UFV(u, Imps_Group, x));
     expiryt = time(NULL) + DEFAULT_EXPIRY;

     l = dict_keys(d);
     
     for (i = 0, n = gwlist_len(l); i<n; i++) {
	  Octstr *xkey = gwlist_get(l, i); 
	  List *ul = dict_get(d, xkey);
	  
	  queue_foreign_msg_add(c, msg, msg_type,sender , -1, NULL, NULL,
				octstr_get_cstr(xkey), ul, CSP_VERSION(1,2), expiryt);
	  gwlist_destroy(ul, _csp_msg_free);
     }	

     if (nelems > 0)
	  queue_local_msg_add(c, msg, msg_type, sender, lu, nelems, 0, NULL, "", expiryt);

     dict_destroy(d);
     gw_free(lu);
     csp_msg_free(sender);
     gwlist_destroy(l, (void *)octstr_destroy);     
     

}

static void notify_change(PGconn *c, int64_t gid, GroupID_t grp, 
			  GroupChangeNotice_t gn, int64_t exclude_uid)
{
     
     char crit[128], tmp1[64];
     
     if (exclude_uid >= 0)
	  sprintf(tmp1, " AND local_userid <> %lld", exclude_uid);
     else 
	  tmp1[0] = 0;
     sprintf(crit, "subscribe_notify = true %s", tmp1);
     
     msg_to_joined_users(c, gid, grp, gn, Imps_GroupChangeNotice, crit);
}

static WelcomeNote_t get_welcome_note(PGconn *c, int64_t gid, int bin)
{
     WelcomeNote_t w;
     char cmd[512], *q;
     Octstr *s;
     PGresult *r;
     sprintf(cmd, "SELECT welcome_note, welcome_note_ctype FROM groups WHERE id = %lld", 
	     gid);

     r = PQexec(c, cmd);

     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 0) {
	  PQclear(r);
	  return NULL;
     }

     s = get_bytea_data(r, 0, 0);
     q = PQgetvalue(r, 0, 1);

     if (s) {
	  ContentEncoding_t enc = NULL;
	  ContentData_t xdata = csp_String_from_bstr(s, Imps_ContentData);
	  
	  
	  do_conditional_msg_encoding(&xdata, bin, &enc);
	  w = csp_msg_new(WelcomeNote, NULL,
			  FV(ctype, csp_String_from_cstr(q, Imps_ContentType)),
			  FV(enc, enc),
			  FV(data, xdata));	  	  
	  octstr_destroy(s);
     } else 
	  w = NULL;
     PQclear(r);
     
     return w;
}

static void set_welcome_note(PGconn *c, int64_t gid, WelcomeNote_t w)
{
     PGresult *r;
     char *tmp5, tmp3[DEFAULT_BUF_LEN], tmp1[64];
     Octstr *cmd;

     PQ_ESCAPE_STR(c, w && w->ctype ? w->ctype->str : (void *)"text/plain" , tmp3);
     if (w && w->data) { /* escape it. */
	  Octstr *x = csp_String_to_bstr(w->data);
	  char *enc = csp_String_to_cstr(w->enc);
	  size_t wdlen;

	  if (x == NULL)
	       x = octstr_create("");
	  if (enc && strcasecmp(enc, "base64") == 0)  /* base64 decode. */
	       octstr_base64_to_binary(x);
	  tmp5 = (void *)PQescapeBytea((void *)octstr_get_cstr(x), octstr_len(x), &wdlen);    
	  octstr_destroy(x);
     } else 
	  tmp5 = NULL;
     sprintf(tmp1, "%lld", gid);
     cmd = octstr_format("UPDATE groups SET welcome_note = E'%s'::bytea, welcome_note_ctype = '%s' "
			 " WHERE id = %s", tmp5 ? tmp5 : "", tmp3, tmp1);

     r = PQexec(c, octstr_get_cstr(cmd));
     octstr_destroy(cmd);
     PQclear(r);

     if (tmp5) 
	  PQfreemem(tmp5);
}

static Result_t join_group(RequestInfo_t *ri, 
			   int64_t gid, 
			   int64_t cgid,
			   ScreenName_t sname, 
			   OwnProperties_t oprop, 
			   int snotify, const char *utype,
			   Octstr *uname, GroupID_t grp, 
			   int is_autojoin, 
			   WelcomeNote_t *w)
{
     char cmd[512], *screen_name;
     char tmp1[DEFAULT_BUF_LEN*2+1];
     char tmp2[DEFAULT_BUF_LEN];
     char val[DEFAULT_BUF_LEN], sid[100];
     int i, sname_exists = 0;
     PGconn *c = ri->c;
     int ver = ri->ver;
     Octstr *clientid = ri->clientid;
     int64_t uid = ri->uid;
     PGresult *r;
     int64_t jid = -1;
     Result_t rs;
     Joined_t j = NULL;
     JoinedBlocked_t jb = NULL;
     char *xs, *fld;
     int n;
     UserList_t ulist;
     UserMapList_t umlist;
     
     /* first do decision tree (Sec. 10.4 of CSP):
      * - check reject list
      * - closed group?
      * - a member?
      */
     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
	  strncpy(sid, "NULL", sizeof sid);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", uid);
	  sprintf(sid, "%lld", ri->sessid);
     }
     sprintf(cmd, "SELECT id FROM group_reject_list WHERE %s = '%.128s' AND groupid=%lld ", 
	     fld, val, gid);
     r = PQexec(c, cmd);

     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  rs = csp_msg_new(Result, NULL,
			   FV(code, 809),
			   FV(descr,csp_String_from_cstr("Rejected", Imps_Description)));
	  
	  PQclear(r);
	  if (ver>= CSP_VERSION(1,3)) /* notify on blocked user. */
	       jb = csp_msg_new(JoinedBlocked, NULL,
				FV(ulist, 
				   csp_msg_new(UserList, NULL, 
					       FV(slist, gwlist_create_ex(csp_msg_copy(sname)))))
		    );
	  goto done;	  
     }
     PQclear(r);

     sprintf(cmd, "SELECT value FROM group_properties WHERE groupid = %lld AND item='AccessType'", gid);
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && 
	 PQntuples(r) > 0 &&  /*  restricted group. */
	 (xs = PQgetvalue(r, 0, 0)) != NULL &&
	 strcasecmp(xs, "Restricted") == 0) {
	  
	  PQclear(r);
	  /* member of creator. */
	  sprintf(cmd, "SELECT id FROM group_members WHERE %s = '%.128s' AND groupid = %lld "
		  " UNION SELECT id FROM groups WHERE id = %lld AND creator = %lld",
		  fld, val,  gid, gid, uid);
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) {
	       rs = csp_msg_new(Result, NULL,
				FV(code, 816),
				FV(descr,csp_String_from_cstr("Non-Member", Imps_Description)));
	       
	       PQclear(r);
	       goto done;	  
	  }
	  PQclear(r);
     }else 
	  PQclear(r);
     
     /* check that screen name is not taken, check if already in here. */
     PQ_ESCAPE_STR(c, octstr_get_cstr(clientid), tmp2);
     screen_name = (sname && sname->sname) ? (void *)sname->sname->str : octstr_get_cstr(uname);
     PQ_ESCAPE_STR_LOWER(c, screen_name, tmp1);
     
     sprintf(cmd, "SELECT gmid,full_userid,screen_name FROM group_members_view WHERE "
	     " group_id = %lld AND "
	     " (screen_name = '%.128s' OR %s = '%.128s') AND (clientid = '%.128s' OR clientid IS NULL)", 
	     gid, tmp1, 
	     fld, val, tmp2);     
     r = PQexec(c, cmd);
     n = PQntuples(r);     
     for (i = 0; i <n; i++) {
	  char *xid = PQgetvalue(r, i, 0);
	  char *lid = PQgetvalue(r, i, 1);
	  char *sid = PQgetvalue(r, i, 2);
	  int umatch = (octstr_str_case_compare(ri->userid, lid) == 0);
	  
	  if (umatch)
	       jid = strtoull(xid, NULL, 10);
	  if (sid && strcmp(sid, screen_name) == 0 && !umatch)
	       sname_exists = 1;
     }
     PQclear(r);

     if (sname_exists) {
	  rs = csp_msg_new(Result, NULL,
			   FV(code, 811),
			   FV(descr,csp_String_from_cstr("Screen name exists", Imps_Description)));
	  goto done;
     }

     if (cgid == uid) /* owner is always admin. */
	  utype = "Admin";
     
     if (jid >= 0)  /* user exists, do update. */
	  sprintf(cmd, "UPDATE group_members SET  screen_name='%.128s', " 
		  " isjoined=true, subscribe_notify=%s, clientid = '%.128s', "
		  " sessionid = %s WHERE id = %lld RETURNING id",
		  tmp1, snotify ? "true" : "false", tmp2, sid, jid);
     else  /* insert. */
	  sprintf(cmd, "INSERT INTO group_members (%s,groupid,member_type,screen_name,clientid,"
		  "isjoined, subscribe_notify, sessionid) VALUES "
		  " ('%.128s', %lld, '%s','%.128s', '%.128s', true, %s, %s) RETURNING id",
		  fld, val, gid, utype, tmp1, tmp2, snotify ? "true" : "false", sid);
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
	  rs = csp_msg_new(Result, NULL,
			   FV(code, 500),
			   FV(descr,csp_String_from_cstr("Server error", Imps_Description)));
	  PQclear(r);
	  goto done;
     }

     if (jid < 0)
	  jid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
     PQclear(r);
     
     if (oprop)
	  set_properties(c, "group_member_properties", "jid", jid, oprop->plist);
     rs = csp_msg_new(Result, NULL,
		      FV(code, 200),
		      FV(descr,csp_String_from_cstr("Complete", Imps_Description)));
     
     /* user joined, make a joined structure. */

     if (ver > CSP_VERSION(1,1)) {
	  void *x;
	  void *y;
	  sprintf(tmp1, "wv:%.256s", octstr_get_cstr(uname));
	  x = csp_String_from_cstr(screen_name, Imps_SName);
	  y = csp_String_from_cstr(tmp1, Imps_UserID);
	  
	  x = csp_msg_new(Mapping, NULL, 
			  FV(sname,x),
			  FV(userid,y));
	  x = csp_msg_new(UserMapping,NULL, 
			  FV(mlist,gwlist_create_ex(x)));
	  umlist = csp_msg_new(UserMapList,NULL, 
			  FV(umap,x));
	  ulist = NULL;
     } else {
	  List *sl = gwlist_create_ex(csp_msg_copy(sname));
	  umlist = NULL;
	  ulist = csp_msg_new(UserList, NULL, FV(slist, sl));
     }

     j = csp_msg_new(Joined, NULL, 
		     FV(umlist, umlist), 
		     FV(ulist, ulist));     
     if (w)
	  *w = get_welcome_note(ri->c, gid, ri->binary);
 done:
     if (j || jb) {
	  GroupChangeNotice_t gchange = 
	       csp_msg_new(GroupChangeNotice, NULL,
			   FV(gid, csp_msg_copy(grp)),
			   FV(joined, j),
			   FV(jblock, jb));
	  notify_change(c, gid, grp, gchange, is_autojoin ? -1 : uid);	  /* if this is an auto-join then we need to inform ourselves as well. */
	  csp_msg_free(gchange);
     }
     return rs;
}


void join_all_auto_groups(RequestInfo_t *ri)
{
     char cmd[512], tmp1[DEFAULT_BUF_LEN*2+10];
     PGresult *r;
     int i, n;
     
     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT groupid, domain, id,screen_name, member_type,subscribe_notify, creator"
	     " FROM group_members_view WHERE auto_join = 'T' AND "
	     " local_userid = %lld AND clientid = '%.128s'",
	     ri->uid, tmp1);
     
     r = PQexec(ri->c, cmd);
     n = PQresultStatus(r) == PGRES_TUPLES_OK ? PQntuples(r) : 0;

     for (i = 0; i<n; i++) {
	  char *x, *g = PQgetvalue(r, i, 0);
	  char *d = PQgetvalue(r, i, 1);
	  int64_t gid = strtoull(PQgetvalue(r, i, 2), NULL, 10);
	  char *s =  PQgetvalue(r, i, 3);
	  char *mtype =  PQgetvalue(r, i, 4);
	  int snotify = (x = PQgetvalue(r, i, 5)) && (tolower(x[0]) == 't');
	  int64_t cgid = strtoull(PQgetvalue(r, i, 6), NULL, 10);
	  ScreenName_t sname;
	  Result_t rs;

	  sprintf(tmp1, "wv:%.128s%s%.128s", 
		  g, d && d[0] ? "@" : "", d);
	  
	  sname = csp_msg_new(ScreenName, NULL,
			      FV(sname, csp_String_from_cstr(s, Imps_SName)),
			      FV(gid, csp_String_from_cstr(tmp1, Imps_GroupID)));
	  
	  rs  = join_group(ri, gid, cgid, sname, NULL, snotify, mtype, ri->userid, 
			   sname->gid, 1, NULL);
	  csp_msg_free(sname);
	  csp_msg_free(rs);
     }
     PQclear(r);
}


static void delete_group(PGconn *c, int64_t gid, GroupID_t grp)
{
     char cmd[128];
     PGresult *r;
     Result_t rs;
     LeaveGroup_Response_t lg;
     
     rs = csp_msg_new(Result, NULL,
		     FV(code, 800),
		     FV(descr,csp_String_from_cstr("Deleted", Imps_Description)));
     lg = csp_msg_new(LeaveGroup_Response, NULL,
		      FV(res, rs),
		      FV(gid, csp_msg_copy(grp)));
     
     msg_to_joined_users(c, gid, grp, lg, Imps_LeaveGroup_Response, NULL);
     
     /* now delete it. */
     sprintf(cmd, "DELETE from groups WHERE id = %lld", gid);
     r = PQexec(c, cmd);

     PQclear(r);
     csp_msg_free(lg);     
}

/* return the code. */
static int leave_group(PGconn *c, int64_t uid, char *fuser, Octstr *clientid, int64_t gid, 
		       GroupID_t grp, int ver, int reason, int send_msg)
{
     char cmd[512], tmp1[2*DEFAULT_BUF_LEN+1];
     PGresult *r;
     int i, n;
     UserList_t ul;
     List *slist = NULL;
     GroupChangeNotice_t gn;
     char *fld, val[DEFAULT_BUF_LEN];

     if (clientid) {
	  char tmp2[DEFAULT_BUF_LEN];
	  PQ_ESCAPE_STR(c, octstr_get_cstr(clientid), tmp2);
	  sprintf(tmp1, " clientid = '%.128s'", tmp2);
     } else 
	  tmp1[0] = 0;
     
     if (fuser) {
	  fld = "foreign_userid";
	  sprintf(val, "%.128s", fuser);
     }else  {
	  fld = "local_userid";
	  sprintf(val, "%lld", uid);
     }

	  
     
     sprintf(cmd, "UPDATE group_members gj SET isjoined=false WHERE groupid = %lld AND %s = '%.128s' AND "
	     " isjoined = true AND "
	     " %s RETURNING id, (SELECT value FROM group_member_properties gjp WHERE gjp.jid = gj.id AND "
	     " gjp.item = 'AutoJoin') AS auto_join, screen_name, ismember, clientid, "
	     "(SELECT full_userid FROM users_view uv WHERE uv.id = gj.local_userid) as full_userid",
	     
	     gid, 
	     fld, val,
	     tmp1[0] ? tmp1 : "True");
     
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) != PGRES_TUPLES_OK || (n = PQntuples(r)) <= 0) {
	  PQclear(r);
	  return 808; /* not joined. */
     }

     slist = gwlist_create();
     for (i = 0; i < n; i++) {
	  int64_t jid = strtoull(PQgetvalue(r, i,0), NULL, 10);
	  char *x = PQgetvalue(r, i, 1);
	  int auto_join = (x && toupper(x[0]) == 'T');
	  char *sname = PQgetvalue(r, i, 2);
	  char *y = PQgetvalue(r, i, 3);
	  int ismember = (y && toupper(y[0]) == 'T');

	  ScreenName_t s = csp_msg_new(ScreenName, NULL, 
				       FV(sname, csp_String_from_cstr(sname, Imps_SName)),
				       FV(gid, csp_msg_copy(grp)));
	  	  
	  if (!auto_join && !ismember) { /* Delete the line item .*/
	       PGresult *r2;
	       sprintf(cmd, "DELETE FROM group_members WHERE id = %lld", jid);
	       r2 = PQexec(c, cmd);
	       PQclear(r2);
	  }
	  gwlist_append(slist, s);	  

	  if (send_msg) {
	       char *cid = PQgetvalue(r, i, 4);
	       Sender_t sender = make_sender_struct(c, -1, NULL, NULL, (char *)grp->str);
	       Result_t r = csp_msg_new(Result, NULL,
					FV(code, reason));
	       
	       LeaveGroup_Response_t lg = csp_msg_new(LeaveGroup_Response, NULL,
						      FV(gid, csp_msg_copy(grp)),
						      FV(res, r));
	       if (fuser) {
		    char xid[DEFAULT_BUF_LEN];
		    char xdomain[DEFAULT_BUF_LEN];
		    User_t ux = make_user_struct(NULL, fuser, cid);
		    List *l = gwlist_create_ex(ux);
		    
		    extract_id_and_domain(fuser, xid, xdomain);
		    
		    queue_foreign_msg_add(c, lg, Imps_LeaveGroup_Response, sender, -1, NULL, NULL,
					  xdomain, l, CSP_VERSION(1,2), time(NULL) + DEFAULT_EXPIRY);
		    gwlist_destroy(l, _csp_msg_free);
	       } else { /* local user. */
		    struct QLocalUser_t lu;
		    Octstr *xg = format_screen_name_ex(grp->str, sname);
		    
		    lu.uid = uid;
		    strncpy(lu.sname, octstr_get_cstr(xg), sizeof lu.sname);
		    strncpy(lu.clientid, cid, sizeof lu.clientid);

		    queue_local_msg_add(c, lg, Imps_LeaveGroup_Response, sender, 
					&lu, 1, 0, NULL, "", time(NULL) + DEFAULT_EXPIRY);
		    
		    octstr_destroy(xg);
	       }
	       
	       csp_msg_free(sender);
	       csp_msg_free(lg);
	  }
     }
     
     PQclear(r);
     
     gn = csp_msg_new(GroupChangeNotice, NULL, FV(gid, csp_msg_copy(grp)));
     ul = csp_msg_new(UserList, NULL, FV(slist, slist));
     
     if (reason != 200 &&  ver>=CSP_VERSION(1,3)) { /* kicked out, and ver > 1.2 */
	  LeftBlocked_t lb = csp_msg_new(LeftBlocked, NULL, FV(ulist, ul));
	  CSP_MSG_SET_FIELD(gn, lblock,lb);
     } else {
	  Left_t lf = csp_msg_new(Left, NULL, FV(ulist, ul));
	  CSP_MSG_SET_FIELD(gn, left,lf);
     }
     notify_change(c, gid, grp, gn, -1);
     
     
     /* DELETE empty group. */
     sprintf(cmd, "DELETE FROM groups g WHERE id = %lld AND "
	     "EXISTS (SELECT id FROM group_properties gp WHERE gp.groupid = g.id "
	     " AND item = 'AutoDelete' AND value = 'T')",
	     gid);
     r = PQexec(c, cmd);
     PQclear(r);
     
     csp_msg_free(gn);

     return 200;
}

/* User leaves all the groups he/she's joined to */
void leave_all_groups(PGconn *c, int64_t uid, Octstr *clientid, int ver, int reason, int send_msg)  
{
     char cmd[512], tmp1[DEFAULT_BUF_LEN*2+10];
     PGresult *r;
     int i, n;
     
     PQ_ESCAPE_STR(c, octstr_get_cstr(clientid), tmp1);
     sprintf(cmd, "SELECT groupid, domain, id FROM group_members_view WHERE isjoined = true AND "
	     " local_userid = %lld AND clientid = '%.128s'",
	     uid, tmp1);

     r = PQexec(c, cmd);
     n = PQresultStatus(r) == PGRES_TUPLES_OK ? PQntuples(r) : 0;

     for (i = 0; i<n; i++) {
	  char *g = PQgetvalue(r, i, 0);
	  char *d = PQgetvalue(r, i, 1);
	  int64_t gid = strtoull(PQgetvalue(r, i, 2), NULL, 10);
	  GroupID_t grp;
	  
	  sprintf(tmp1, "wv:%.128s%s%.128s", 
		  g, d && d[0] ? "@" : "", d);
	  grp = csp_String_from_cstr(tmp1, Imps_GroupID);
	  
	  leave_group(c, uid, NULL, clientid, gid, grp, ver, reason, send_msg);
	  
	  csp_msg_free(grp);
     }
     
     PQclear(r);
}

/* can never be called with ssp set to true (?) */
Status_t handle_create_group(RequestInfo_t *ri, CreateGroup_Request_t req)
{

     int64_t uid = ri->uid, gid;
     char xuid[DEFAULT_BUF_LEN];
     char xgid[DEFAULT_BUF_LEN];
     char xdomain[DEFAULT_BUF_LEN];
     char tmp1[DEFAULT_BUF_LEN];
     char tmp2[DEFAULT_BUF_LEN];
     char tmp3[DEFAULT_BUF_LEN];
     char tmp4[64];
     void *tmp5 = NULL; 
     Octstr *cmd = NULL;
     PGresult *r;
     Result_t rs;
     WelcomeNote_t w;
     int n;
     PGconn *c = ri->c;
     
     extract_id_and_domain(req->gid ? req->gid->str : (void *)"", xgid, xdomain);
     extract_id_and_domain(octstr_get_cstr(ri->userid), xuid, tmp1);

     /* check format of group ID */
     n = strlen(xuid); /* length of userid. */
     if (strncmp(xdomain, tmp1, sizeof xdomain) != 0 ||
	 strstr(xgid, xuid) != xgid ||
	 strlen(xgid) <= n ||
	 xgid[n] != '/' ||
	 isvalid_nameid(xgid + n + 1) != 1) {
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,806), 
			   FV(descr, csp_String_from_cstr("Invalid GroupID", Imps_Description)));	  
	  goto done;	 
     }

     w = (req->gprop) ? req->gprop->wnote : NULL;
     
     PQ_ESCAPE_STR_LOWER(c, xgid, tmp1);
     PQ_ESCAPE_STR_LOWER(c, xdomain, tmp2);
     PQ_ESCAPE_STR(c, w && w->ctype ? w->ctype->str : (void *)"text/plain" , tmp3);
     
     if (w && w->data) { /* escape it. */
	  Octstr *x = csp_String_to_bstr(w->data);
	  char *enc = csp_String_to_cstr(w->enc);
	  size_t wdlen;

	  if (x == NULL)
	       x = octstr_create("");
	  if (enc && strcasecmp(enc, "base64") == 0)  /* base64 decode. */
	       octstr_base64_to_binary(x);
	  tmp5 = (void *)PQescapeBytea((void *)octstr_get_cstr(x), octstr_len(x), &wdlen);    
	  octstr_destroy(x);
     } else 
	  tmp5 = NULL;
     /* Attempt to insert into DB. */
     sprintf(tmp4, "%lld", uid);
     cmd = octstr_format("INSERT INTO groups (groupid, domain,creator, welcome_note,welcome_note_ctype) "
			 " VALUES (lower('%.128s'), lower('%.128s'), %s, E'%s'::bytea, '%.64s') RETURNING id", 
			 tmp1, tmp2, tmp4, tmp5 ? tmp5 : "", tmp3);     
     
     r = PQexec(c, octstr_get_cstr(cmd));    
     if (PQresultStatus(r) != PGRES_TUPLES_OK) { /* reply with group exists. */
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,801), 
			   FV(descr, csp_String_from_cstr("GroupID exists", Imps_Description)));	  
	  PQclear(r);
	  goto done;	 
     }
     gid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
     PQclear(r);

     if (req->gprop)
	  set_properties(c, "group_properties", "groupid", gid, req->gprop ? req->gprop->plist : NULL);
     
     if (req->jgrp) /* wants to join group. */
	  rs = join_group(ri, gid, uid, req->sname, req->oprop, req->snotify,
			  "Admin", ri->userid,
			  req->gid, 0, NULL);
     else 
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,200), 
			   FV(descr, csp_String_from_cstr("Complete", Imps_Description)));	  
 done:
     
     if (tmp5) 
	  PQfreemem(tmp5);

     octstr_destroy(cmd);

     return csp_msg_new(Status,NULL,  FV(res,rs));	  
}


static Result_t get_grp_info(RequestInfo_t *ri, char *grpname, 
			     void *msg, int msgtype,
			     char xdomain[], char xgid[], int64_t *gid, int64_t *cgid)
{
     char tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN];
     int islocal = 0;
     Result_t rs;
     
     extract_id_and_domain(grpname, xgid, xdomain);
     
     PQ_ESCAPE_STR_LOWER(ri->c, xgid, tmp1);
     PQ_ESCAPE_STR_LOWER(ri->c, xdomain, tmp2);
     *gid = get_groupid(ri->c, tmp1, tmp2, &islocal);

     if (*gid < 0 && islocal) 
	  rs = csp_msg_new(Result, NULL,
			   FV(code,800),
			   FV(descr, 
			      csp_String_from_cstr("No such group", 
						   Imps_Description)));
     else if (!islocal) {
	  if (!ri->is_ssp) {
	       Sender_t sender = make_sender_struct2(ri->userid, ri->clientid, NULL, NULL);
	       
	       queue_foreign_msg_add(ri->c, msg, msgtype, sender, ri->uid, 
				     ri->clientid ? octstr_get_cstr(ri->clientid) : NULL, 
				     NULL, 
				     xdomain, NULL, ri->ver, time(NULL) + DEFAULT_EXPIRY);
	       rs = csp_msg_new(Result, NULL,
				FV(code,101),
				FV(descr, 
				   csp_String_from_cstr("Queued", 
						   Imps_Description)));
	       csp_msg_free(sender);
	  } else 
	       rs = csp_msg_new(Result, NULL,
				FV(code,516),
				FV(descr, 
				   csp_String_from_cstr("Relay for foreign groups not allowed", 
							Imps_Description)));
     } else {
	  PGresult *r;
	  char cmd[512];

	  sprintf(cmd, "SELECT creator FROM groups WHERE id = %lld", *gid);
	  
	  r = PQexec(ri->c, cmd);
	  if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0)
	       *cgid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
	  else 
	       *cgid = -1;
	  PQclear(r);
	  rs = NULL;
     }
     return rs;
}

Status_t handle_delete_group(RequestInfo_t *ri, DeleteGroup_Request_t req)
{
     int64_t uid = ri->uid, gid, cgid;
     PGconn *c = ri->c;
     char xgid[DEFAULT_BUF_LEN];
     char xdomain[DEFAULT_BUF_LEN];
     char tmp1[DEFAULT_BUF_LEN];
     char cmd[512], *xs;
     PGresult *r;
     Result_t rs;
     char val[DEFAULT_BUF_LEN], *fld;

     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_DeleteGroup_Request, xdomain, xgid, &gid, &cgid)) != NULL)
	  goto done;

     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", uid);
     }

     PQ_ESCAPE_STR(c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT member_type FROM group_members WHERE %s = '%.128s' "
	     "AND groupid = %lld and clientid = '%.128s'",
	     fld, val, gid, tmp1);
     r = PQexec(c, cmd);

     if (PQresultStatus(r) != PGRES_TUPLES_OK) {
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,500), 
			   FV(descr, csp_String_from_cstr("Error", 
							  Imps_Description))); 	  
	  PQclear(r);
	  goto done;	  
     } else if (cgid != uid && 
		(PQntuples(r) < 1 ||
		 (xs = PQgetvalue(r, 0, 0)) == NULL ||
		 strcasecmp(xs, "Admin") != 0)) {
	  rs = csp_msg_new(Result, NULL, 
			   FV(code,816), 
			   FV(descr, csp_String_from_cstr("Not allowed", 
							  Imps_Description))); 	  
	  PQclear(r);
	  goto done;	  
     }
     PQclear(r);
     
     delete_group(c, gid, req->gid);     
     rs = csp_msg_new(Result, NULL, 
		      FV(code,200), 
		      FV(descr, csp_String_from_cstr("Complete", 
						     Imps_Description))); 	  
 done:
     
     return csp_msg_new(Status,NULL,  FV(res,rs));	  
}


LeaveGroup_Response_t handle_leave_group(RequestInfo_t *ri, LeaveGroup_Request_t req)
{
     int64_t gid, cgid;

     char xgid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     Result_t rs;
     

     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_LeaveGroup_Request, xdomain, xgid, &gid, &cgid)) == NULL)  {
	  int res = leave_group(ri->c, ri->is_ssp ? -1 : ri->uid,
				ri->is_ssp ? octstr_get_cstr(ri->userid) : NULL, 
				ri->clientid, gid, req->gid, ri->ver, 200, 0);
	  rs = csp_msg_new(Result, NULL,
			   FV(code,res),
			   FV(descr, 
			      csp_String_from_cstr((res == 200) ?  "Complete" : "error", 
						   Imps_Description)));	  
     }
     
     return csp_msg_new(LeaveGroup_Response, NULL, FV(res, rs), FV(gid, csp_msg_copy(req->gid)));
}

GetGroupMembers_Response_t handle_get_group_members(RequestInfo_t *ri, GetGroupMembers_Request_t req)
{
     int i, n, found;
     char cmd[512], *typ = NULL;
     PGresult *r;
     int64_t cgid;
     
     int64_t gid;
     char tmp1[DEFAULT_BUF_LEN];
     char xgid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     Result_t rs = NULL;
     GetGroupMembers_Response_t resp = NULL;
     Admin_t adm;
     Mod_t mod;
     UserList_t ul;
     char *fld, val[DEFAULT_BUF_LEN];

     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_GetGroupMembers_Request, xdomain, xgid, &gid, &cgid)) != NULL)
	  goto done;

     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", ri->uid);
     }

     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT member_type "
	     "FROM group_members WHERE groupid = %lld AND %s = '%.128s'  AND clientid = '%.128s'",
	     gid, fld, val, tmp1);
     r = PQexec(ri->c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  strncpy(tmp1, PQgetvalue(r, 0, 0), sizeof tmp1);
	  typ = tmp1;
	  found = 1;
     } else {
	  typ = NULL;
	  found = 0;
     }

     PQclear(r);
     if (typ == NULL ||
	 (!ri->is_ssp && cgid != ri->uid) ||
	 (strcasecmp(typ, "Mod") != 0 && 
	  strcasecmp(typ, "Admin") != 0)) {
	  int code = (!found) ? 808 : 816;
	  char *reason = (code == 808) ? "No such group" : "Denied";
	  
	       rs = csp_msg_new(Result, NULL,
				FV(code,code),
				FV(descr, 
				   csp_String_from_cstr(reason, 
							Imps_Description)));
	       goto done;
     }
     
     ul = csp_msg_new(UserList, NULL,
		      FV(ulist, gwlist_create()));
     adm = csp_msg_new(Admin, NULL,
		       FV(ulist, csp_msg_copy(ul)));
     mod = csp_msg_new(Mod, NULL,
		       FV(ulist, csp_msg_copy(ul)));
     
     resp = csp_msg_new(GetGroupMembers_Response, NULL,
			FV(admin, adm),
			FV(mod, mod),
			FV(ulist, ul));
     sprintf(cmd, "SELECT member_type, full_userid, screen_name,clientid FROM group_members_view "
	     " WHERE group_id = %lld and ismember = true ",
	     gid);
     r = PQexec(ri->c, cmd);
     
     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
     
     for (i = 0; i<n; i++) {
	  char *mtype = PQgetvalue(r, i, 0);
	  char *uname = PQgetvalue(r, i, 1);
	  
	  char *cname = PQgetvalue(r, i, 3);	  

	  User_t ux = make_user_struct(NULL, uname, cname);
	  UserList_t xul;
	  

	  
	  if (mtype && strcasecmp(mtype, "Admin") == 0)
	       xul = resp->admin->ulist;
	  else if (mtype && strcasecmp(mtype, "Mod") == 0)
	       xul = resp->mod->ulist;
	  else 
	       xul = resp->ulist;
	  
	  gwlist_append(xul->ulist, ux);	  
	  
     }
     
done:
     if (rs) 
	  return (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  
     /* else */
     csp_msg_free(rs);
     return resp;     
}

/* returns lists of Mapping_t */
static void get_joined_lists(PGconn *c, int ver, 
			     int64_t gid, GroupID_t grp, 
			     List *admin_list, List *mod_list, List *user_list)
{
     char cmd[512];
     int i, n;
     PGresult *r;
     sprintf(cmd, "SELECT member_type, screen_name, full_userid, "
	     " (SELECT value FROM group_member_properties WHERE jid = gmid AND item = 'ShowID') "
	     " FROM group_members_view "
	     " WHERE group_id = %lld", gid);

     r = PQexec(c, cmd);
     n =  (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
     for (i = 0; i<n; i++) {
	  char *sname =  PQgetvalue(r, i, 1);
	  SName_t s = csp_String_from_cstr(sname && sname[0] ? sname : "N/A", Imps_SName);

	  if (ver <= CSP_VERSION(1,1)) {
	       ScreenName_t xsname = csp_msg_new(ScreenName, NULL,
						 FV(sname, s),
						 FV(gid, csp_msg_copy(grp)));
	       gwlist_append(user_list, xsname);
	  } else {
	       char *mtype  = PQgetvalue(r, i, 0);
	       char *uname = PQgetvalue(r, i, 2);
	       char *x = PQgetvalue(r, i, 3);
	       int show_id = (x && toupper(x[0]) == 'T');

	       UserID_t u = show_id ? csp_String_from_cstr(uname, Imps_UserID) : NULL;
	       Mapping_t m = csp_msg_new(Mapping, NULL, 
					 FV(sname, s),
					 FV(userid, u));
	       List *l;
	       if (mtype && strcasecmp(mtype, "Admin") == 0)
		    l = admin_list;
	       else if (mtype && strcasecmp(mtype, "Mod") == 0)
		    l = mod_list;
	       else 
		    l = user_list;
	       
	       gwlist_append(l, m);	  
	  }
     }
     PQclear(r);     
}

/* only exists in ver > 1.1 */

GetJoinedUsers_Response_t handle_get_joined_users(RequestInfo_t *ri, GetJoinedUsers_Request_t req)
{
     int found;
     char cmd[512], *typ = NULL;
     PGresult *r  = NULL;
     int64_t cgid;     
     int64_t gid;
     char tmp1[DEFAULT_BUF_LEN];
     char xgid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     Result_t rs = NULL;

     void *ures = NULL;
     int ures_type = -1;
     List *user_list, *admin_list, *mod_list;
     
     char *fld, val[DEFAULT_BUF_LEN];

     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_GetJoinedUsers_Request, xdomain, xgid, &gid, &cgid)) != NULL)
	  goto done;

     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", ri->uid);
     }
     
     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT member_type "
	     "FROM group_members WHERE groupid = %lld AND %s = '%.128s'  AND clientid = '%.128s'",
	     gid, fld, val, tmp1);
     r = PQexec(ri->c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  typ = PQgetvalue(r, 0, 0);
	  found = 1;
     } else {
	  typ = NULL;
	  found = 0;
     }

     if (typ == NULL) {
	  int code = (!found) ? 808 : 816;
	  char *reason = (code == 808) ? "No such group" : "Denied";
	  
	  rs = csp_msg_new(Result, NULL,
			   FV(code,code),
			   FV(descr, 
			      csp_String_from_cstr(reason, 
						   Imps_Description)));
	  goto done;
     }
     
     if (strcasecmp(typ, "Admin") == 0 ||
	 strcasecmp(typ, "Mod") == 0) {
	  AdminMapping_t x = csp_msg_new(AdminMapping, NULL, 
					 FV(mlist, gwlist_create()));
	  ModMapping_t y = csp_msg_new(ModMapping, NULL, 
				       FV(mlist, gwlist_create()));
	  UserMapping_t z = csp_msg_new(UserMapping, NULL, 
					FV(mlist, gwlist_create()));
	  
	  AdminMapList_t al = csp_msg_new(AdminMapList, NULL, 
					  FV(amap, x), 
					  FV(mmap, y),
					  FV(umap, z));
	  
	  user_list = z->mlist;
	  mod_list = y->mlist;
	  admin_list = x->mlist;
	  
	  ures = al;
	  ures_type = Imps_AdminMapList;
     } else {
	  UserMapping_t x = csp_msg_new(UserMapping, NULL, 
					FV(mlist, gwlist_create()));
	  
	  UserMapList_t ul = csp_msg_new(UserMapList, NULL, FV(umap, x));

	  user_list = mod_list = admin_list = x->mlist;
	  ures = ul;
	  ures_type = Imps_UserMapList;
     }
     
     get_joined_lists(ri->c, ri->ver, gid, req->gid, admin_list, mod_list, user_list);
     
 done:
     if (r)
	  PQclear(r);
     if (rs)
	  return (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  
     
     /* else */
     csp_msg_free(rs);
     return csp_msg_new(GetJoinedUsers_Response, NULL, UFV(u, ures_type, ures));
}

JoinGroup_Response_t handle_join_group(RequestInfo_t *ri, JoinGroup_Request_t req)
{
     int64_t gid, cgid;
     Joined_t j = NULL;
     UserList_t jul = NULL;
     WelcomeNote_t w = NULL;
     
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     Result_t rs = NULL;

     ScreenName_t sname = NULL;
     
     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_JoinGroup_Request, xdomain, xid, &gid, &cgid)) != NULL)
	  goto done;
     
     rs = join_group(ri, gid, cgid, req->sname, req->oprop, 
		     req->snotify, "User",ri->userid, req->gid, 0, &w);
     
     if (rs && rs->code != 200)
	  goto done;
     if (req->jreq) {
	  List *l = gwlist_create();

	  get_joined_lists(ri->c, ri->ver, gid, req->gid, l, l, l);
	  
	  if (ri->ver > CSP_VERSION(1,1)) {
	       UserMapping_t um = csp_msg_new(UserMapping, NULL, 
					      FV(mlist, l));
	       UserMapList_t uml = csp_msg_new(UserMapList, NULL,
					       FV(umap, um));
	       j = csp_msg_new(Joined, NULL, 
			       FV(umlist, uml));
	  } else 
	       jul = csp_msg_new(UserList, NULL,
				 FV(slist, l));
     } else {
	  j = NULL;
	  jul = NULL;
     }
     
     if (ri->ver >= CSP_VERSION(1,3)) 
	  sname = req->sname ? csp_msg_copy(req->sname) : 
	       csp_msg_new(ScreenName, NULL,
			   FV(sname, csp_String_from_bstr(ri->userid, Imps_SName)),
			   FV(gid, csp_msg_copy(req->gid)));
     else 
	  sname = NULL;          
     
     csp_msg_free(rs); /* rs not used. */
     rs = NULL; 
 done:
     
     if (rs) {
	  csp_msg_free(w);
	  return (void *)csp_msg_new(Status,NULL,  FV(res,rs));	  
     } else    
	  return csp_msg_new(JoinGroup_Response, NULL,
			     FV(joined, j),
			     FV(sname, sname),
			     FV(ulist, jul),
			     FV(wnote, w));
}

Status_t handle_add_members(RequestInfo_t *ri, AddGroupMembers_Request_t req)
{
     int i, n, found;
     char cmd[512], *typ = NULL;
     PGresult *r;
     int64_t cgid;     
     int64_t gid;
     
     char xgid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char tmp1[DEFAULT_BUF_LEN];
     Result_t rs = NULL;     
     List *l, *drl = gwlist_create();
     char *fld, val[DEFAULT_BUF_LEN];

     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_AddGroupMembers_Request, xdomain, xgid, &gid, &cgid)) != NULL)
	  goto done;

     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", ri->uid);
     }

     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT member_type "
	     "FROM group_members WHERE groupid = %lld AND %s = '%.128s'  AND clientid = '%.128s'",
	     gid, fld, val, tmp1);
     r = PQexec(ri->c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  strncpy(tmp1, PQgetvalue(r, 0, 0), sizeof tmp1);
	  typ = tmp1;
	  found = 1;
     } else {
	  typ = NULL;
	  found = 0;
     }     
     PQclear(r);
     
     if (typ == NULL ||
	 (!ri->is_ssp && cgid != ri->uid) ||
	 (strcasecmp(typ, "Mod") != 0 && 
	  strcasecmp(typ, "Admin") != 0)) {
	  int code = (!found) ? 800 : 816;
	  char *reason = (code == 800) ? "No such group" : "Denied";
	  
	  rs = csp_msg_new(Result, NULL,
			   FV(code,code),
			   FV(descr, 
			      csp_String_from_cstr(reason, 
							Imps_Description)));
	  goto done;
     }
     
     if (req->ulist.typ == Imps_UserIDList)
	  l = req->ulist.val ? ((UserIDList_t)req->ulist.val)->ulist : NULL;
     else 
	  l = req->ulist.val ? ((UserList_t)req->ulist.val)->ulist : NULL;
     
     for (i = 0, n = gwlist_len(l); i<n; i++) {
	  void *u = gwlist_get(l, i);
	  UserID_t ux = (CSP_MSG_TYPE(u) == Imps_UserID) ? u : ((User_t)u)->user;
	  char *uname = ux ? ux->str : (void *)"";
	  int islocal;
	  char xuid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
	  int64_t uid;
	  char *fld;


	  extract_id_and_domain(uname, xuid, xdomain);
	  uid = get_userid(ri->c, xuid, xdomain, &islocal);
	  
	  if (uid < 0 && islocal) {
	       Octstr *err = octstr_format("No such user: %s", uname);
	       DetailedResult_t r = csp_msg_new(DetailedResult, NULL,
						FV(code,531),
						FV(descr, 
						   csp_String_from_bstr(err, 
									Imps_Description)));
	       gwlist_append(drl, r);
	       octstr_destroy(err);
	       continue;
	  }
	  if (islocal) {
	       fld = "local_userid";
	       sprintf(tmp1, "%lld", uid);
	  } else {	       
	       PQ_ESCAPE_STR_LOWER(ri->c, uname, tmp1);
	       fld = "foreign_userid";	        /* need to lower-case XXX */
	  }
	  sprintf(cmd, "UPDATE group_members SET ismember = true WHERE "
		  "%s = '%.128s' AND groupid = %lld RETURNING id", fld, tmp1, gid);
	  r = PQexec(ri->c, cmd);

	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) { /* not found, insert. */
	       PGresult *r2;
	       sprintf(cmd, "INSERT into group_members (groupid, ismember, %s) VALUES "
		       "(%lld, true, '%.128s') ",
		       fld, gid, tmp1);
	       r2 = PQexec(ri->c, cmd);
	       PQclear(r2);
	  }
	  PQclear(r);	  
     }

     rs = csp_msg_new(Result, NULL,
		      FV(code, (gwlist_len(drl) == 0) ? 200 : 201),
		      FV(drlist, drl));     
     drl = NULL;
 done:

     gwlist_destroy(drl, _csp_msg_free);
     return csp_msg_new(Status, NULL, FV(res, rs));
}



Status_t handle_del_members(RequestInfo_t *ri, RemoveGroupMembers_Request_t req)
{
     int i, n, found;
     char cmd[512], *typ = NULL;
     PGresult *r;
     int64_t cgid;     
     int64_t gid;
     char tmp1[DEFAULT_BUF_LEN];
     char xgid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     Result_t rs = NULL;     
     List *l, *drl = gwlist_create();
     char *fld, val[DEFAULT_BUF_LEN];

     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_RemoveGroupMembers_Request, xdomain, xgid, &gid, &cgid)) != NULL)
	  goto done;
     
     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", ri->uid);
     }

     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT member_type "
	     "FROM group_members WHERE groupid = %lld AND %s = '%.128s'  AND clientid = '%.128s'",
	     gid, fld, val, tmp1);
     r = PQexec(ri->c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  strncpy(tmp1, PQgetvalue(r, 0, 0), sizeof tmp1);
	  typ = tmp1;
	  found = 1;
     } else {
	  typ = NULL;
	  found = 0;
     }     
     PQclear(r);

     if (typ == NULL ||
	 (!ri->is_ssp && cgid != ri->uid) ||
	 (strcasecmp(typ, "Mod") != 0 && 
	  strcasecmp(typ, "Admin") != 0)) {
	  int code = (!found) ? 800 : 816;
	  char *reason = (code == 800) ? "No such group" : "Denied";
	  
	  rs = csp_msg_new(Result, NULL,
			   FV(code,code),
			   FV(descr, 
			      csp_String_from_cstr(reason, 
							Imps_Description)));
	  goto done;
     }
     
     if (req->ulist.typ == Imps_UserIDList)
	  l = req->ulist.val ? ((UserIDList_t)req->ulist.val)->ulist : NULL;
     else 
	  l = req->ulist.val ? ((UserList_t)req->ulist.val)->ulist : NULL;
     
     for (i = 0, n = gwlist_len(l); i<n; i++) {
	  void *u = gwlist_get(l, i);
	  UserID_t ux = (CSP_MSG_TYPE(u) == Imps_UserID) ? u : ((User_t)u)->user;
	  char *uname = ux ? ux->str : (void *)"";
	  int islocal;
	  char xuid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];

	  int64_t uid;
	  char *fld;
	  extract_id_and_domain(uname, xuid, xdomain);
	  uid = get_userid(ri->c, xuid, xdomain, &islocal);
	  
	  if (uid < 0 && islocal) {
	       Octstr *err = octstr_format("No such user: %s", uname);
	       DetailedResult_t r = csp_msg_new(DetailedResult, NULL,
						FV(code,531),
						FV(descr, 
						   csp_String_from_bstr(err, 
									Imps_Description)));
	       gwlist_append(drl, r);
	       octstr_destroy(err);
	       continue;
	  }
	  if (islocal) {
	       fld = "local_userid";
	       sprintf(tmp1, "%lld", uid);
	  } else {	       
	       PQ_ESCAPE_STR_LOWER(ri->c, uname, tmp1);
	       fld = "foreign_userid";	       
	  }
	  sprintf(cmd, "UPDATE group_members SET ismember = false WHERE "
		  "%s = '%.128s' and ismember=true AND groupid = %lld RETURNING id", fld, tmp1, gid);
	  r = PQexec(ri->c, cmd);

	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) { /* not found, report error. */
	       Octstr *err = octstr_format("No such user: %s", uname);
	       DetailedResult_t r = csp_msg_new(DetailedResult, NULL,
						FV(code,531),
						FV(descr, 
						   csp_String_from_bstr(err, 
									Imps_Description)));
	       gwlist_append(drl, r);
	       octstr_destroy(err);	  
	  } else {
	       PGresult *r2;
	       int64_t jid = strtoull(PQgetvalue(r, 0,0), NULL, 10);
	       sprintf(cmd, "DELETE FROM  group_members gm WHERE groupid=%lld AND id = %lld"
		       "  AND "
		       " (SELECT value FROM group_member_properties gp WHERE gp.jid = gm.id AND item = "
		       "'AutoJoin') = 'T'",
		       gid, jid);
	       r2 = PQexec(ri->c, cmd);
	       PQclear(r2);
	  }
	  PQclear(r);	  
     }

     rs = csp_msg_new(Result, NULL,
		      FV(code, (gwlist_len(drl) == 0) ? 200 : 201),
		      FV(drlist, drl));     
     drl = NULL;
 done:

     gwlist_destroy(drl, _csp_msg_free);
     return csp_msg_new(Status, NULL, FV(res, rs));
}


static void update_user_access(PGconn *c, const char *mtype, List *l, int64_t gid, List *drl, 
			       char update_mask[])
{
     int i, n;
     char cmd[512];
     
     for (i = 0, n = gwlist_len(l); i<n; i++) {
	  User_t u = gwlist_get(l, i);
	  UserID_t ux = u ?  (void *)u->user : NULL;
	  char *uname = ux ? ux->str : (void *)"";
	  int islocal;
	  char xuid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
	  char tmp1[DEFAULT_BUF_LEN];
	  int64_t uid;
	  char *fld;
	  PGresult *r;

	  extract_id_and_domain(uname, xuid, xdomain);
	  uid = get_userid(c, xuid, xdomain, &islocal);
	  
	  if (uid < 0 && islocal) {
	       Octstr *err = octstr_format("No such user: %s", uname);
	       DetailedResult_t r = csp_msg_new(DetailedResult, NULL,
						FV(code,531),
						FV(descr, 
						   csp_String_from_bstr(err, 
									Imps_Description)));
	       gwlist_append(drl, r);
	       octstr_destroy(err);
	       continue;
	  }
	  if (islocal) {
	       fld = "local_userid";
	       sprintf(tmp1, "%lld", uid);
	  } else {	       
	       PQ_ESCAPE_STR_LOWER(c, uname, tmp1);
	       fld = "foreign_userid";		    
	  }
	  sprintf(cmd, "UPDATE group_members SET ismember = true, member_type = '%s' WHERE "
		  "%s = '%.128s' AND %s AND groupid = %lld RETURNING id", mtype, fld, tmp1,
		  update_mask[0] ? update_mask : " TRUE", gid);
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) { /* not found, insert. */
	       PGresult *r2;
	       sprintf(cmd, "INSERT into group_members (groupid, ismember, member_type, %s) VALUES "
		       "(%lld, true, '%s', '%.128s') ",
		       fld, gid, mtype, tmp1);
	       r2 = PQexec(c, cmd);
	       PQclear(r2);
	  }
	  PQclear(r);	  
     }     
}

Status_t handle_member_access(RequestInfo_t *ri, MemberAccess_Request_t req)
{
     
     int found;
     char cmd[512], filt[64], *typ = NULL;
     PGresult *r;
     int64_t cgid;     
     int64_t gid;
     
     char xgid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char tmp1[DEFAULT_BUF_LEN];
     Result_t rs = NULL;     
     List *drl = gwlist_create();
     char *fld, val[DEFAULT_BUF_LEN];


     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_MemberAccess_Request, xdomain, xgid, &gid, &cgid)) != NULL)
	  goto done;
     
     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", ri->uid);
     }

     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT member_type "
	     "FROM group_members WHERE groupid = %lld AND %s = '%.128s' AND clientid = '%.128s'",
	     gid, fld, val, tmp1);
     r = PQexec(ri->c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  strncpy(tmp1, PQgetvalue(r, 0, 0), sizeof tmp1);
	  typ = tmp1;
	  found = 1;
     } else {
	  typ = NULL;
	  found = 0;
     }     
     PQclear(r);

     if (typ == NULL ||
	 (!ri->is_ssp && cgid != ri->uid) ||
	 (strcasecmp(typ, "Mod") != 0 && 
	  strcasecmp(typ, "Admin") != 0)) {
	  int code = (!found) ? 810 : 816;
	  char *reason = (code == 810) ? "Not joined" : "Denied";
	  
	  rs = csp_msg_new(Result, NULL,
			   FV(code,code),
			   FV(descr, 
			      csp_String_from_cstr(reason, 
							Imps_Description)));
	  goto done;
     }
     
     /* Only admin can add admins or moderators. */
     if (cgid == ri->uid ||
	 strcasecmp(typ, "Admin") == 0) { /* add admins. */
	  filt[0] = 0;
	  if (req->admin && 
	      req->admin->ulist)
	       update_user_access(ri->c, "Admin", req->admin->ulist->ulist, gid, drl, filt);
	  if (req->mod && 
	      req->mod->ulist)
	       update_user_access(ri->c, "Mod", req->mod->ulist->ulist, gid, drl, filt);	      	  
     } else 
	  sprintf(filt, " member_type = 'User' ");
     
     if (req->ulist)
	  update_user_access(ri->c, "User", req->ulist->ulist, gid, drl, filt);	      
     
     rs = csp_msg_new(Result, NULL,
		      FV(code, (gwlist_len(drl) == 0) ? 200 : 201),
		      FV(drlist, drl));     
     drl = NULL;
 done:
     
     gwlist_destroy(drl, _csp_msg_free);
     return csp_msg_new(Status, NULL, FV(res, rs));    
}

GetGroupProps_Response_t handle_get_props(RequestInfo_t *ri, GetGroupProps_Request_t req)
{
     int found;
     char cmd[512], *typ = NULL;
     PGresult *r;
     int64_t cgid;     
     int64_t gid, jid;
     List *oplist = NULL;
     List *gplist = NULL;
     char xgid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char tmp1[DEFAULT_BUF_LEN];
     Result_t rs = NULL;     
     WelcomeNote_t w = NULL;
     char *fld, val[DEFAULT_BUF_LEN];

     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_GetGroupProps_Request, xdomain, xgid, &gid, &cgid)) != NULL)
	  goto done;
     
     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", ri->uid);
     }

     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT member_type, id "
	     "FROM group_members WHERE groupid = %lld AND %s = '%.128s' AND clientid = '%.128s'",
	     gid, fld, val, tmp1);
     r = PQexec(ri->c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  typ = PQgetvalue(r, 0, 0);
	  found = 1;
	  jid = strtoull(PQgetvalue(r, 0, 1), NULL, 10);
     } else {
	  typ = NULL;
	  found = 0;
	  jid = -1;
     }     

     /* Get the user properties */
     oplist = get_properties(ri->c, "group_member_properties", "jid", jid);
     if (cgid == ri->uid ||	 
	 (typ &&  strcasecmp(typ, "Admin") == 0)) 
	  gplist = get_properties(ri->c, "group_properties", "groupid", gid);
     else 
	  gplist = NULL;
     
     PQclear(r);
     
     w = get_welcome_note(ri->c, gid, ri->binary);
 done:
     if (rs) {
	  csp_msg_free(w);
	  return (void *)csp_msg_new(Status, NULL, FV(res, rs));    
     }  else 
	  return  csp_msg_new(GetGroupProps_Response, NULL,
			      FV(gprop, 
				 csp_msg_new(GroupProperties, NULL, 
					     FV(plist, gplist),
					     FV(wnote, w))),
			      FV(oprop, 
				 csp_msg_new(OwnProperties, NULL,
					     FV(plist, oplist))));     
}


Status_t handle_set_props(RequestInfo_t *ri, SetGroupProps_Request_t req)
{
     int found;
     char cmd[512], *typ = NULL;
     PGresult *r;
     int64_t cgid;     
     int64_t gid, jid;
     char xgid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char tmp1[DEFAULT_BUF_LEN];
     Result_t rs = NULL;     
     List *drl = gwlist_create();
     char *fld, val[DEFAULT_BUF_LEN];
     
     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_SetGroupProps_Request, xdomain, xgid, &gid, &cgid)) != NULL)
	  goto done;

     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", ri->uid);
     }
     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT member_type, id "
	     "FROM group_members WHERE groupid = %lld AND %s = '%.128s' AND clientid = '%.128s'",
	     gid, fld, val, tmp1);
     r = PQexec(ri->c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  typ = PQgetvalue(r, 0, 0);
	  found = 1;
	  jid = strtoull(PQgetvalue(r, 0, 1), NULL, 10);
     } else {
	  typ = NULL;
	  found = 0;
	  jid = -1;
     }     


     /* Set the user properties */
     if (req->oprop)
	  set_properties(ri->c, "group_member_properties", "jid", jid, req->oprop->plist);
     if (req->gprop) {
	  if (cgid == ri->uid ||	 
	      (typ &&  strcasecmp(typ, "Admin") == 0)) {
	       set_properties(ri->c, "group_properties", "groupid", gid, req->gprop->plist);
	       if (req->gprop->wnote)
		    set_welcome_note(ri->c, gid, req->gprop->wnote);
	  }  else { /* no rights. */
	       DetailedResult_t r = csp_msg_new(DetailedResult, NULL,
						FV(code,816),
						FV(descr, 
						   csp_String_from_cstr("Group set Properties denied", 
									Imps_Description)));
	       gwlist_append(drl, r);	       
	  }
     }

     PQclear(r);     
     rs = csp_msg_new(Result, NULL, 
		      FV(code, gwlist_len(drl) == 0 ? 200 : 201),
		      FV(drlist, drl));
     drl = NULL;
 done:
     gwlist_destroy(drl, _csp_msg_free);
     return csp_msg_new(Status, NULL, FV(res, rs));    
}

static void reject_user(RequestInfo_t *ri, char *user, int64_t gid, int64_t cgid, List *errorlist, GroupID_t grp)
{
     char xid[DEFAULT_BUF_LEN], tmp1[DEFAULT_BUF_LEN];
     char cmd[512];
     int64_t uid;
     int islocal;
     char *fld;
     PGconn *c = ri->c;
     PGresult *r;
     
     extract_id_and_domain(user, xid, tmp1);
     uid = get_userid(c, xid, tmp1, &islocal);

     if (uid < 0 && islocal) {
	  Octstr *err = octstr_format("unknown user: %s", user);
	  DetailedResult_t d = csp_msg_new(DetailedResult, NULL,
					   FV(code, 531),
					   FV(descr, 
					      csp_String_from_bstr(err, Imps_Description)));
	  gwlist_append(errorlist, d);
	  octstr_destroy(err);
	  return;
     } else if (uid == cgid) /* can not reject owner. */
	  return;
     
     if (uid >= 0) {
	  fld = "local_userid";
	  sprintf(tmp1, "%lld", uid);
     } else {
	  fld = "foreign_userid";
	  sprintf(tmp1, "'%.128s'", user);
     }
     
     sprintf(cmd, "SELECT id FROM group_reject_list WHERE groupid = %lld AND %s = %s",
	     gid, fld, tmp1);
     r = PQexec(c, cmd);
     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) {
	  PGresult *r2;
	  sprintf(cmd, "INSERT INTO group_reject_list (groupid, %s) VALUES (%lld, %s)", 
		  fld, gid, tmp1);
	  r2 = PQexec(c, cmd);
	  PQclear(r2);

	  leave_group(c, uid, (uid>=0) ? NULL : user, NULL, 
		      gid, grp, ri->ver, 809, 1); /* force user to leave group. */
     }
     PQclear(r);          
}

static void unreject_user(PGconn *c, char *user, int64_t gid)
{
     char xid[DEFAULT_BUF_LEN], tmp1[DEFAULT_BUF_LEN];
     char cmd[512];
     int64_t uid;
     int islocal;
     char *fld;
     PGresult *r;
     
     extract_id_and_domain(user, xid, tmp1);
     uid = get_userid(c, xid, tmp1, &islocal);

     
     if (uid >= 0) {
	  fld = "local_userid";
	  sprintf(tmp1, "%lld", uid);
     } else {
	  fld = "foreign_userid";
	  sprintf(tmp1, "'%.128s'", user);
     }
     
     sprintf(cmd, "DELETE FROM group_reject_list WHERE groupid = %lld AND %s = %s",
	     gid, fld, tmp1);
     r = PQexec(c, cmd); /* no error check required as per spec. */
     PQclear(r); 
}

RejectList_Response_t handle_reject(RequestInfo_t *ri, RejectList_Request_t req)
{
     int i, n, found;
     char cmd[512], *typ = NULL;
     PGresult *r;
     int64_t cgid;     
     int64_t gid;
     char xgid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char tmp1[DEFAULT_BUF_LEN];
     Result_t rs = NULL;     
     List *l, *xul = NULL, *drl = gwlist_create();
     UserID_t u;
     UserList_t ul = NULL;
     char *fld, val[DEFAULT_BUF_LEN];
     
     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_RejectList_Request, xdomain, xgid, &gid, &cgid)) != NULL)
	  goto done;
     
     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", ri->uid);
     }

     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT member_type "
	     "FROM group_members WHERE groupid = %lld AND %s = '%.128s' AND clientid = '%.128s'",
	     gid, fld, val, tmp1);
     r = PQexec(ri->c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  strncpy(tmp1, PQgetvalue(r, 0, 0), sizeof tmp1);
	  typ = tmp1;
	  found = 1;
     } else {
	  typ = NULL;
	  found = 0;
     }     
     PQclear(r);
 
     if (typ == NULL || 	 
	 (!ri->is_ssp && cgid != ri->uid) ||
	 (strcasecmp(typ, "Mod") != 0 && 
	  strcasecmp(typ, "Admin") != 0)) {
	  int code = (!found) ? 800 : 816;
	  char *reason = (code == 800) ? "Not joined" : "Denied";
	  
	  rs = csp_msg_new(Result, NULL,
			   FV(code,code),
			   FV(descr, 
			      csp_String_from_cstr(reason, 
						   Imps_Description)));
	  goto done;
     }

     /* Go through Addlist first. */
     l = req->alist ? req->alist->users : NULL;
     for (i = 0, n = gwlist_len(l); i<n; i++)
	  if ((u = gwlist_get(l, i)) != NULL)
	       reject_user(ri, (char *)u->str, gid, cgid, drl, req->gid); 
     
     /* Go through RemoveList */
     l = req->rlist ? req->rlist->users : NULL;     
     for (i = 0, n = gwlist_len(l); i<n; i++)
	  if ((u = gwlist_get(l, i)) != NULL)
	       unreject_user(ri->c, (char *)u->str, gid);
     
     if (gwlist_len(drl)  > 0) {	  
	  rs = csp_msg_new(Result, NULL,
			   FV(code,201),
			   FV(drlist, drl));
	  drl = NULL;
	  goto done;

     }
     /* Get all the users. */

     xul = gwlist_create();
     sprintf(cmd, "SELECT full_userid FROM group_reject_list_view WHERE group_id = %lld", 
	     gid);
     r = PQexec(ri->c, cmd);
     n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;

     for (i = 0; i<n; i++)
	  gwlist_append(xul, 
			make_user_struct(NULL, PQgetvalue(r, i, 0), NULL));
     
     PQclear(r);
     
     if (gwlist_len(xul) == 0) { /* empty. */
	  gwlist_destroy(xul, NULL);
	  ul = NULL;
     } else 
	  ul = csp_msg_new(UserList, NULL, FV(ulist, xul));
     
 done:
     gwlist_destroy(drl, _csp_msg_free);
     if (rs) 
	  return (void *)csp_msg_new(Status, NULL, FV(res, rs));    
     else 
	  return csp_msg_new(RejectList_Response, NULL, FV(ulist, ul));
}



SubscribeGroupNotice_Response_t handle_subscribe_notice(RequestInfo_t *ri, SubscribeGroupNotice_Request_t req)
{

     int found, snotify = 0;
     char cmd[512];
     PGresult *r;
     int64_t jid;     
     int64_t gid, cgid;
     char xgid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN], stype;
     char tmp1[DEFAULT_BUF_LEN];
     Result_t rs = NULL;     
     char *fld, val[DEFAULT_BUF_LEN];

     if ((rs = get_grp_info(ri, req->gid ? req->gid->str : (void *)"", req, 
			    Imps_SubscribeGroupNotice_Request, xdomain, xgid, &gid, &cgid)) != NULL)
	  goto done;
     
     if (ri->is_ssp) {
	  fld = "foreign_userid";
	  PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->userid), val);
     } else {
	  fld = "local_userid";
	  sprintf(val, "%lld", ri->uid);
     }
     
     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT member_type, id, subscribe_notify "
	     "FROM group_members WHERE groupid = %lld AND %s = '%.128s' AND clientid = '%.128s'",
	     gid, fld, val, tmp1);
     r = PQexec(ri->c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  char *x;
	  found = 1;
	  jid = strtoull(PQgetvalue(r, 0, 1), NULL, 10);
	  x = PQgetvalue(r, 0, 2);

	  snotify = (x && tolower(x[0]) == 't');
     } else {
	  found = 0;
	  jid = -1;
	  snotify = 0;
     }     
     PQclear(r);
 
     if (found == 0) {
	  int code = 808;
	  char *reason =  "Not joined";
	  
	  rs = csp_msg_new(Result, NULL,
			   FV(code,code),
			   FV(descr, 
			      csp_String_from_cstr(reason, 
						   Imps_Description)));
	  goto done;
     }
     
     stype = req->stype ? toupper(req->stype->str[0]) : 'G';
     
     if (stype == 'U' || stype == 'S') {
	  sprintf(cmd, "UPDATE group_members SET subscribe_notify = %s WHERE id = %lld",
		  (stype == 'U') ? "false" : "true", jid);
	  r = PQexec(ri->c, cmd);
	  PQclear(r);	  
	  /* answer with a status message. */
	  rs = csp_msg_new(Result, NULL,
			   FV(code,200),
			   FV(descr, 
			      csp_String_from_cstr("Complete", 
						   Imps_Description)));
     }
     
 done:
     if (rs) 
	  return (void *)csp_msg_new(Status, NULL, FV(res, rs));    
     else 
	  return csp_msg_new(SubscribeGroupNotice_Response, NULL,
			     FV(value, csp_String_from_cstr(snotify ? "T" : "F", Imps_Value)));
}
