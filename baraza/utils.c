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
/* IMPS -- miscellanous helper routines. */

#include "utils.h"
#include <stdarg.h>
#include "wbxml.h"
#include "cspmessages.h"
#include "cspcommon.h"
#include "csppresence.h"
#include "cspim.h"
#include "cspgroup.h"
#include "mqueue.h"
#include "conf.h"
#include "baraza.h"

List *gwlist_create_ex_real(const char *file, const char *func, int line,...)
{
     va_list ap;
     List *l  = gwlist_create();
     void *v;
     
     va_start(ap, line);

     while ((v = va_arg(ap, void *)) != NULL)
	  gwlist_append(l, v);
     return l;
}

xmlNodePtr find_node_ex(xmlNodePtr start, char *name, int level, int maxlevel)
{
     xmlNodePtr node, x, list;

     
     if (level >= maxlevel) return NULL;
     
     /* First search at top level. */
     for (list=start; list; list=list->next)
          if (list->type == XML_COMMENT_NODE)
               continue;
          else if (xmlStrcasecmp(list->name, (const xmlChar *)name) == 0) 
               return list;
     
     /* Then recurse...*/
     for (list = start; list; list=list->next)     
          for (node = list->xmlChildrenNode; node; node = node->next)
               if (xmlStrcasecmp(node->name, (const xmlChar *)name) == 0) 
                    return node;
               else if (node->type != XML_COMMENT_NODE && 
                        (x = find_node_ex(node, name, level+1,maxlevel)) != NULL) 
                    return x;     
     return NULL;
}


xmlNodePtr find_nodebytype_ex(xmlNodePtr start, int type, int level, int maxlevel)
{
     xmlNodePtr node, x, list;

     
     if (level >= maxlevel) return NULL;
     
     /* First search at top level. */
     for (list=start; list; list=list->next)
          if (list->type == type)
	       return list;
     
     /* Then recurse...*/
     for (list = start; list; list=list->next)     
          for (node = list->xmlChildrenNode; node; node = node->next)
               if (node->type == type) 
                    return node;
               else if (node->type != XML_COMMENT_NODE && 
                        (x = find_nodebytype_ex(node, type, level+1,maxlevel)) != NULL) 
                    return x;     
     return NULL;
}


xmlDtdPtr find_dtd_node_ex(xmlNodePtr start, int level, int maxlevel)
{
     xmlNodePtr node, list;
     xmlDtdPtr x;
     
     if (level >= maxlevel) return NULL;
     
     /* First search at top level. */
     for (list=start; list; list=list->next)
          if (list->type == XML_DTD_NODE)
	       return (void *)list;
     
     /* Then recurse...*/
     for (list = start; list; list=list->next)     
          for (node = list->xmlChildrenNode; node; node = node->next)
               if (node->type != XML_COMMENT_NODE && 
		   (x = find_dtd_node_ex(node, level+1,maxlevel)) != NULL) 
                    return x;     
     return NULL;
}


void open_logs(char *access_log, char *debug_log, int loglevel)
{
     alog_open(access_log, 1, 1);

     log_open(debug_log, loglevel, GW_NON_EXCL);
}

int bit_count(unsigned long x)
{
     int n = 0;

     while (x) {
	  if (x&0x01)
	       n++;
	  x >>= 1;
     }
     return n;
}

void extract_id_and_domain(char *id, char xid[], char xdomain[])
{
     char *p;
     /* extract the id and domain. */
     if (strstr(id, "wv:") == id) /* prefix */
	  id += 3;
     if ((p = strchr(id, '@')) != NULL) {
	  int n = (p-id);
	  int lim = n < DEFAULT_BUF_LEN ? n : DEFAULT_BUF_LEN-1;
	  
	  strncpy(xdomain, p+1, DEFAULT_BUF_LEN);
	  strncpy(xid, id, lim);
	  xid[lim] = 0; 
	  xdomain[DEFAULT_BUF_LEN-1] = 0;
     } else {
	  xdomain[0] = 0;
	  strncpy(xid, id, DEFAULT_BUF_LEN);
	  xid[DEFAULT_BUF_LEN-1] = 0;
     }
}

Octstr *csp_msg_to_str(void *msg, int type)
{
#if 1
     WBXMLGen_t *z = wbxml_pack_state(DEFAULT_WBXML_VERSION, octstr_imm(DEFAULT_WBXML_PUBLICID),
				      DEFAULT_WBXML_CHARSET, DEFAULT_CSP_VERSION);
     Octstr *out = csp_pack_msg(msg, type, 1, z);      /* Pack as binary. */
     Octstr *x = wbxml_make_preamble(z);
     
     wbxml_pack_state_free(z);

     octstr_append(x, out);
     octstr_destroy(out);
     return x;
#else
     
     return csp_pack_msg(msg, type, 0, NULL);      /* Pack as text. */
#endif
}


void *csp_msg_from_str(Octstr *in, int type)
{
     int bin, ch; 
     void *w, *start;
     void *res = NULL;
     
     /* Try and guess the type of data */
     if (!in) return NULL;

     ch = octstr_get_char(in, 0);

     bin = (_x_isprint(ch) == 0);
     if (bin) {
	  w = parse_wbxml(in);
	  start = w ? ((WBXML_t)w)->body : NULL;
     } else {
	  w =  xmlParseMemory(octstr_get_cstr(in), octstr_len(in));
	  start = w ? ((xmlDocPtr)w)->xmlChildrenNode : NULL;
     }
     if (!w || !start)
	  res =  NULL;
     else if (csp_parse_msg(start, type, bin, &res) != 0)
	  res = NULL;
     
     if (w) 
	  (bin) ? free_wbxml(w) : xmlFreeDoc(w);
     
     return res;
}

Octstr *make_clientid(ClientID_t clnt, ApplicationID_t appid)
{

     Octstr *clid = octstr_create("");
     if (clnt) {
	  if (clnt->url) 
	       octstr_format_append(clid, "u:%s", 
				    clnt->url->str);
	  if (clnt->msisdn) 
	       octstr_format_append(clid, "%sn:%s", 
				    octstr_len(clid) > 0 ? " " : "", clnt->msisdn->str);
	  if (clnt->_content) 
	       octstr_format_append(clid, "%sc:%S",
				    octstr_len(clid) > 0 ? " " : "", clnt->_content);	  
     } else if (appid) /* one or the other. */
	  octstr_format_append(clid, 
			       "%sa:%s",
			       octstr_len(clid) > 0 ? " " : "", appid->str);	  
     return clid;

}

int compare_clientid(Octstr *clientid_x, ClientID_t clientid_y)
{
     int ret;

     if (clientid_x == NULL && clientid_y == NULL)
	  ret = 0;
     else {
	  Octstr *s = make_clientid(clientid_y, NULL);
	  ret = clientid_x && (octstr_compare(clientid_x, s) == 0);
	  octstr_destroy(s);
     }
     return ret;
}

int parse_clientid(Octstr *s, ClientID_t *clnt, ApplicationID_t *appid)
{
     int ch, i, pos = 0;
     Octstr *x;
    

     *clnt = NULL;
     *appid = NULL;
     if (s == NULL)
	  return 0;
     if ( ((ch = octstr_get_char(s, pos)) == 'u' || ch == 'n' || ch == 'c') && 
	  octstr_get_char(s, pos+1) == ':') { /* we have a client object. */
	  ClientID_t c = *clnt = csp_msg_new(ClientID, NULL, NULL);

	  pos = 2;
	  if (ch == 'u') {
	       i = octstr_search_char(s, ' ', pos);
	       if (i < 0) i = octstr_len(s);
	       x = octstr_copy(s, pos, i);
	       CSP_MSG_SET_FIELD(c, url, csp_String_from_bstr(x, Imps_URL));
	       
	       pos = i + 1;
	       ch = octstr_get_char(s, pos);
	       octstr_destroy(x);
	  }

	  if (ch == 'n') {
	       i = octstr_search_char(s, ' ', pos);
	       if (i < 0) i = octstr_len(s);
	       x = octstr_copy(s, pos, i);
	  
	       CSP_MSG_SET_FIELD(c, msisdn, csp_String_from_bstr(x, Imps_MSISDN));
	       
	       pos = i + 1;
	       ch = octstr_get_char(s, pos);
	       octstr_destroy(x);
	  }

	  if (ch == 'c') {
	       i = octstr_search_char(s, ' ', pos);
	       if (i < 0) i = octstr_len(s);
	  
	       c->_content = octstr_copy(s, pos, i);

	       pos = i + 1;
	       ch = octstr_get_char(s, pos);
	  }	  	 	  
     }

     if ((ch = octstr_get_char(s, pos)) == 'a' && 
	 octstr_get_char(s, pos+1) == ':') {
	  x = octstr_copy(s, pos+2, octstr_len(s)); /* to the end. */

	  *appid = csp_String_from_bstr(x, Imps_ApplicationID);
	  
	  octstr_destroy(x);
     }
     return 0;
}

Octstr *make_sender_str(Sender_t sender)
{
     Octstr *x = octstr_create("");

     
     if (sender == NULL) 
	  return x;
     else if (sender->u.typ == Imps_User) {
	  User_t u = sender->u.val;
	  char *name = u->user ? u->user->str : (void *)"";
	  ClientID_t _c = NULL; 
	  ApplicationID_t _a = NULL;
	  
	  Octstr *cl;
	  
	  octstr_format_append(x, "User=%s", name);

	  if (u->fname)
	       octstr_format_append(x, "; FriendlyName=%s", u->fname->str);
	  
	  if (u->u.typ == Imps_ApplicationID)
	       _a = u->u.val;
	  else 
	       _c = u->u.val;
	  
	  cl = make_clientid(_c, _a);
	  octstr_format_append(x, "; Client=%S", cl);

	  octstr_destroy(cl);
     } else {
	  Group_t g = sender->u.val;	  
	  GroupID_t grp = (g->u.typ == Imps_GroupID) ? g->u.val : ((ScreenName_t)g->u.val)->gid;
	  SName_t sname = (g->u.typ == Imps_ScreenName) ? ((ScreenName_t)g->u.val)->sname : NULL;

	  gw_assert(grp);
	  octstr_format_append(x, "Group=%s", grp->str);
	  if (sname)
	       octstr_format_append(x, "; ScreenName=%s", sname->str);	  
     }

     return x;
}


#define GET_PARAM(_buf, _p) do { \
	  int _i = 0; \
	  while (*_p && *_p != ';') \
	       _buf[_i++] = *_p++; \
	  _buf[_i] = 0; \
	  if (*_p == ';') /* clear for next one. */ \
	       _p++; \
	  while (*_p && isspace(*_p)) \
	       _p++; \
 } while (0)
	  

Sender_t parse_sender_str(char *in)
{
     char *p, buf[256];
     void *val;
     
     if (in == NULL || in[0] == 0) 
	  return NULL;
     
     if ((p = strstr(in, "User=")) == in) { /* A user. */
	  User_t u = csp_msg_new(User, NULL, NULL);
	  
	  p += strlen("User=");	  
	  GET_PARAM(buf,p);
	  CSP_MSG_SET_FIELD(u, user, csp_String_from_cstr(buf, Imps_UserID));	  
	  if (strstr(p, "FriendlyName=") == p) {
	       p += strlen("FriendlyName=");
	       GET_PARAM(buf,p);
	       CSP_MSG_SET_FIELD(u, fname, csp_String_from_cstr(buf, Imps_FriendlyName));       
	  }
	  
	  /* skip over the client part. */
	  if (strstr(p, "Client=") == p) {
	       ClientID_t _c = NULL; 
	       ApplicationID_t _a = NULL;
	       Octstr *x;
	       int type; 
	       void *val;
	       
	       p += strlen("Client=");

	       x = octstr_create(p);
	       parse_clientid(x, &_c, &_a);
	       octstr_destroy(x);
	       
	       type = _c ? Imps_ClientID : Imps_ApplicationID;
	       val = _c ? _c : (void *)_a;	       
	       csp_msg_set_union_field_value(u, csp_get_field_num(u, "u"), type, val);
	  }
	  val = u;
     } else if ((p = strstr(in, "Group=")) == in) { /* A group with a screen name. */
	  Group_t g;	
	  GroupID_t grp;

	  p += strlen("Group=");
	  GET_PARAM(buf,p);
	  grp = csp_String_from_cstr(buf, Imps_GroupID);
	  
	  if (strstr(p, "ScreenName=") == p) {	 
	       ScreenName_t sname;
	       GET_PARAM(buf,p);
	       
	       sname = csp_msg_new(ScreenName, NULL,
				   FV(sname, csp_String_from_cstr(buf, Imps_SName)),
				   FV(gid, grp));
	       g = csp_msg_new(Group, NULL, 
			       UFV(u, Imps_ScreenName, sname));
	  } else 
	       g = csp_msg_new(Group, NULL, 
			       UFV(u, Imps_GroupID, grp));
	  val = g;
     } else 
	  return NULL; /* Badly formatted! */

     return csp_msg_new(Sender, NULL, 
			UFV(u, CSP_MSG_TYPE(val), val));
}


ScreenName_t parse_screen_name(char *in)
{
     char sname[DEFAULT_BUF_LEN], gid[DEFAULT_BUF_LEN];
     if (in == NULL)
	  return NULL;
     
     sname[0] = 0;
     gid[0] = 0;
     if (sscanf(in, "g:%64s s:%64[^\n]",  gid, sname) >= 1)
	  return csp_msg_new(ScreenName, NULL, 
			     FV(sname, csp_String_from_cstr(sname, Imps_SName)),
			     FV(gid, csp_String_from_cstr(gid, Imps_GroupID)));
     else 
	  return NULL;
}

void _csp_msg_free(void *msg)
{     
     csp_msg_free(msg);
}


static char *obj_tables[] = {"users", "groups", "contactlists"};
static char *obj_id_fields[] = {"userid", "groupid", "cid"};

int64_t get_object_id(PGconn *c, enum DBObjectTypes_t type, 
		      char *id, char *domain, char *extra_cond, 
		      int *islocal_domain)
{

     char cmd[512];
     PGresult *r;
     int64_t xid;
     
     if (type < 0 || type > DBObj_ContactList)
	  return -1;
     
     sprintf(cmd, "SELECT id from %s WHERE lower(%s)=lower('%.128s') AND lower(domain) = lower('%.128s') AND %s", 
	     obj_tables[type], obj_id_fields[type],
	     id, domain,
	     extra_cond ? extra_cond : "TRUE");
     
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK &&  PQntuples(r) > 0) {
	  xid = strtoull(PQgetvalue(r, 0, 0), NULL, 10);
	  *islocal_domain = 1;
     } else { /* determine if the domain is local after all. */
	  *islocal_domain = get_islocal_domain(c, domain);
	  xid = -1;
     }
     PQclear(r);
     
     return xid;

}

int is_bot(PGconn *c, u_int64_t uid, char url[], char name[])
{
     char cmd[512];
     PGresult *r;
     int res;
          
     sprintf(cmd, "SELECT bot_url, nickname from users WHERE id=%lld AND bot_url IS NOT NULL", uid);
     
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  res = 1;
	  if (url)
	       strncpy(url, PQgetvalue(r, 0, 0), DEFAULT_BUF_LEN);
	  if (name)
	       strncpy(name, PQgetvalue(r, 0, 1), DEFAULT_BUF_LEN);
     } else 
	  res = 0;     
     
     PQclear(r);     
     return res;
}

int get_object_name_and_domain(PGconn *c, enum DBObjectTypes_t type, int64_t id, 
			       char *extra_cond,
			       char xid[], char xdomain[])
{
     char cmd[512];
     PGresult *r;
     int res;
     
     if (type < 0 || type > DBObj_ContactList)
	  return -1;
     
     sprintf(cmd, "SELECT %s,domain from %s WHERE id=%lld AND %s", 
	     obj_id_fields[type],
	     obj_tables[type], 
	     id, 
	     extra_cond ? extra_cond : "TRUE");
     
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) == PGRES_TUPLES_OK &&  PQntuples(r) > 0) {
	  strncpy(xid, PQgetvalue(r, 0, 0), DEFAULT_BUF_LEN);
	  strncpy(xdomain, PQgetvalue(r, 0, 1), DEFAULT_BUF_LEN);
	  res = 0;
     } else 
	  res = -1;
     PQclear(r);
     
     return res;
}
int get_islocal_domain(PGconn *c, char *domain)
{
     int x;
     char cmd[512];
     PGresult *r;
     
     sprintf(cmd, "SELECT id from localdomains WHERE lower(domain) = lower('%.128s')", domain);
     
     r = PQexec(c, cmd);
     
     x = (PQresultStatus(r) == PGRES_TUPLES_OK) && (PQntuples(r) > 0);
     PQclear(r);

     return x;
}

void set_has_cir(PGconn *c, int64_t sid, int has_cir)
{
     PGresult *r;
     char buf[DEFAULT_BUF_LEN];

     sprintf(buf, "UPDATE sessions SET cir = %s WHERE id = %lld", has_cir ? "true" : "false", sid);
     r = PQexec(c, buf);
     PQclear(r);
}

/* return 0 or -1 if no such session. */
static int get_session_id_real(PGconn *c, char *fld, char *val, RequestInfo_t *req)
{
     PGresult *r;
     char tmp1[DEFAULT_BUF_LEN], tmp2[2*DEFAULT_BUF_LEN], tmp3[2*DEFAULT_BUF_LEN], cmd[1024], *x;
     int major = 1, minor = 1;
     
     if (c == NULL || PQstatus(c) != CONNECTION_OK)
	  return -1;

     if (req->conf == NULL)
	  req->conf = config; /* Get a copy of the conf. */

     /* verify the session. */
     PQ_ESCAPE_STR(c, val, tmp1);

     if (octstr_len(req->client_ip) > 0) {
	  char tmp[DEFAULT_BUF_LEN];
	  PQ_ESCAPE_STR(c, octstr_get_cstr(req->client_ip), tmp);
	  
	  sprintf(tmp2, ", request_ip = '%.128s'", tmp);
     } else 
	  tmp2[0] = 0;

     if (octstr_len(req->msisdn) > 0) {
	  char tmp[DEFAULT_BUF_LEN];
	  PQ_ESCAPE_STR(c, octstr_get_cstr(req->msisdn), tmp);
	  
	  sprintf(tmp3, ", msisdn = '%.128s'", tmp);
     } else 
	  tmp3[0] = 0;
     
     sprintf(cmd, "UPDATE sessions SET lastt = current_timestamp %s %s WHERE  %s = '%.128s' "
	     "RETURNING  id, userid, clientid,default_notify, pull_len, push_len, deliver_method, "
	     " (SELECT full_userid FROM users_view WHERE  users_view.id = sessions.userid), "
	     " cookie,csp_version,ttl,cir , msisdn, request_ip, sessionid",
	     tmp2, tmp3,     fld, tmp1);
     r = PQexec(c, cmd);
     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1) {
	  error(0, "invalid/expired  session [%s=%.64s]!", fld, val);
	  PQclear(r);
	  return -1;
     }
     
     req->sessid = strtoull( PQgetvalue(r, 0, 0), NULL, 10);
     req->uid = strtoull(PQgetvalue(r, 0, 1), NULL, 10);
     req->clientid = octstr_create(PQgetvalue(r, 0, 2));
     req->sinfo.react = (x = PQgetvalue(r, 0, 3)) && (tolower(x[0]) == 't');
     req->sinfo.pull_len = strtoul(PQgetvalue(r, 0, 4), NULL, 10);
     req->sinfo.push_len = strtoul(PQgetvalue(r, 0, 5), NULL, 10);
     req->sinfo.deliver_method = (x = PQgetvalue(r, 0, 6)) &&  (tolower(x[0]) == 'n') ? NotifyGet_DMethod : Push_DMethod;
     req->userid = octstr_create(PQgetvalue(r, 0, 7));
     req->cookie = octstr_create(PQgetvalue(r, 0, 8));
     x = PQgetvalue(r, 0, 9);
     
     sscanf(x, "%d.%d", &major, &minor);
     if (req->ver <= 0)
	  req->ver = CSP_VERSION(major, minor);
     req->ttl = strtoul(PQgetvalue(r, 0, 10), NULL, 10); 
     req->cir = ((x = PQgetvalue(r, 0, 11)) != NULL && tolower(x[0]) == 't');

     if (req->msisdn == NULL)
	  req->msisdn = ((x = PQgetvalue(r, 0, 12)) != NULL && x[0]) ? octstr_create(x) : NULL;
     if (req->client_ip == NULL)
	  req->client_ip = ((x = PQgetvalue(r, 0, 13)) != NULL && x[0]) ? octstr_create(x) : NULL;

     if (req->xsessid[0] == 0) 
	  strncpy(req->xsessid, PQgetvalue(r, 0, 14), sizeof req->xsessid); 
     
     PQclear(r);

     return 0;
}

int get_session_id(PGconn *c, char *sessid, RequestInfo_t *req)
{
     return get_session_id_real(c, "sessionid", sessid, req);     
}


int get_session_info(PGconn *c, int64_t sid, RequestInfo_t *req)
{
     char xid[64];

     sprintf(xid, "%lld", sid);
     return get_session_id_real(c, "id", xid, req);     
}


void free_req_info(RequestInfo_t *ri, int clear_struct)
{
     octstr_destroy(ri->userid);
     octstr_destroy(ri->transid);     
     octstr_destroy(ri->clientid);
     octstr_destroy(ri->cookie);
     octstr_destroy(ri->msisdn);
     octstr_destroy(ri->client_ip);
 
     if (clear_struct)
	  gw_free(ri);
}

void update_session_notify(PGconn *c, int64_t sessid, int default_notify)
{
     PGresult *r;
     char cmd[512];
             
     sprintf(cmd, "UPDATE sessions SET default_notify=%s  WHERE id = %lld", 
	     default_notify ? "true" : "false",
	     sessid);
     r = PQexec(c, cmd);

     PQclear(r);     
}

/* returns true if this user has pending messages. If the request structure is given (i.e. >= 0, then 
 * updates the TTL as needed. 
 */
int has_pending_msgs_ex(PGconn *c, int64_t uid, Octstr *clientid, unsigned long min_ttl,
			unsigned long max_ttl, int64_t sessid, int has_cir)
{
     
     PGresult *r;
     char tmp1[DEFAULT_BUF_LEN], cmd[512];
     int res;
     
     PQ_ESCAPE_STR(c, octstr_get_cstr(clientid), tmp1);
     sprintf(cmd, "SELECT id from csp_message_recipients_view WHERE userid = %lld AND "
	     " (clientid IS NULL OR clientid = '' OR clientid = '%.128s') AND "
	     " msg_status = 'N' and edate > current_timestamp LIMIT 1",
	     uid, tmp1);
     r = PQexec(c, cmd);

     res = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0);
     PQclear(r);

     if (sessid >= 0 && !has_cir) {
	  if (res == 0) /* no messages, increase the TTL. */
	       sprintf(cmd, "UPDATE sessions SET ttl = ttl + %ld WHERE id = %lld AND ttl < %ld", 
		       (long)min_ttl, sessid, (long)max_ttl);
	  else /* has messages, bring the TTL back down to zero. */
	    sprintf(cmd, "UPDATE sessions SET ttl = %ld WHERE id = %lld", (long)min_ttl, sessid);
	  r = PQexec(c, cmd);
	  PQclear(r);
     }
     return res;
}

int make_temp_ids_table(PGconn *c, char tblname[])
{
     static u_int64_t ct;
     char cmd[512];
     PGresult *r;
     int ret;
     
     sprintf(tblname, "temp_ids%lld", ct++);

     sprintf(cmd, "CREATE TEMPORARY TABLE %s (id bigint NOT NULL) ON COMMIT DROP", tblname);

     r = PQexec(c, cmd);

     if (PQresultStatus(r) != PGRES_COMMAND_OK) {
	  error(0, "failed to create temp table: %s", PQerrorMessage(c));
	  ret = -1;
     } else 
	  ret = 0;
     PQclear(r);
     
     return ret;
}
void check_csp_grant_block_in_use(PGconn *c, int64_t uid, 
				  int *ginuse, int *binuse)
{
     PGresult *r;
     char cmd[512];
     /* First check if block/grant list in use. */
     sprintf(cmd, "SELECT grant_list_in_use, block_list_in_use FROM users WHERE id = %lld", uid);
     r = PQexec(c, cmd);
     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) {
	  char *x = PQgetvalue(r, 0, 0);
	  char *y = PQgetvalue(r, 0, 1);
	  
	  *ginuse = _str2bool(x);
	  *binuse = _str2bool(y);
     } else {
	  *ginuse = 0;
	  *binuse = 0;
     }
     PQclear(r);     
}

int check_csp_grant(PGconn *c, Sender_t sender, int64_t sender_uid, int64_t receiver_id)
{
     char cmd[1024], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN], cond[256];
     PGresult *r;
     int ginuse = 0, binuse = 0;
     int i, n = 0, ret;
     int has_block, has_grant;
     
     if (!sender) /* if no sender, then we simply deny? */
	  return 0;

     check_csp_grant_block_in_use(c, receiver_id, &ginuse, &binuse); /* get block flags. */
     
     if (sender->u.typ == Imps_Group) {
	  Group_t g = sender->u.val;	  
	  ScreenName_t s = (g->u.typ == Imps_ScreenName) ? g->u.val : NULL;
	  GroupID_t gid = s ? s->gid : g->u.val;
	  char cond1[256];

	  PQ_ESCAPE_STR(c, gid ? (char *)gid->str : "", tmp2);	       	  
	  if (s) {
	       PQ_ESCAPE_STR(c, s->sname ? (char *)s->sname->str : "", tmp1);	       
	       sprintf(cond1, "(screen_name='%.128s' AND group_id = '%.128s') OR ", tmp1, tmp2);
	  } else 
	       cond1[0] = 0;
	  sprintf(cond, "%s (group_id = '%.128s' AND screen_name IS NULL)", cond1, tmp2);	  
     } else 
	  sprintf(cond, "local_userid = %lld", sender_uid);

     /*Get the block and grants list. */
     sprintf(cmd, "SELECT DISTINCT allow FROM access_lists WHERE owner=%lld AND (%s) LIMIT 1", receiver_id, cond);
     
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) != PGRES_TUPLES_OK)
	  warning(0, "grant check failed: %s", PQerrorMessage(c));
     else if ((n = PQntuples(r)) == 0) {
	  ret = 1; /* allowed: no grant or block lists. */
	  goto done;
     } 

     /* Now pass through results, and see if we have a grant or a block: Block supersedes grant. */
     
     has_block = has_grant = 0;
     for (i = 0; i<n; i++) {
	  char *t = PQgetvalue(r, i, 0);
	  
	  if (!_str2bool(t))  /* blocked! */
	       has_block |= 1;
	  else 
	       has_grant |= 1;
     }
     
     if (binuse /* straight implementation of the flow chart. */
	 && has_block) {
	  ret = 0;
	  goto done;
     }

     if (ginuse && !has_grant) {
	  ret = 0;
	  goto done;
     }
     
     ret = 1; /* allowed if not blocked. */
 done:
     PQclear(r);     
     return ret;
}

int check_ssp_grant(PGconn *c, Sender_t sender, int64_t receiver_id)
{
     char cmd[1024], tmp1[DEFAULT_BUF_LEN], tmp2[DEFAULT_BUF_LEN], cond[256];
     PGresult *r;
     
     int i, n = 0, ret;
     
     if (!sender)
	  return 0;

     if (sender->u.typ == Imps_Group) {
	  Group_t g = sender->u.val;	  
	  ScreenName_t s = (g->u.typ == Imps_ScreenName) ? g->u.val : NULL;
	  GroupID_t gid = s ? s->gid : g->u.val;
	  char cond1[256];

	  PQ_ESCAPE_STR(c, gid ? (char *)gid->str : "", tmp2);	       	  
	  if (s) {
	       PQ_ESCAPE_STR(c, s->sname ? (char *)s->sname->str : "", tmp1);	       
	       sprintf(cond1, "(screen_name='%.128s' AND group_id = '%.128s') OR ", tmp1, tmp2);
	  } else 
	       cond1[0] = 0;
	  sprintf(cond, "%s (group_id = '%.128s' AND screen_name IS NULL)", cond1, tmp2);	  
     } else {
	  User_t u = sender->u.val;
	  UserID_t uid = u ? u->user : NULL;
	  PQ_ESCAPE_STR(c, uid ? (char *)uid->str : "", tmp2);	       	  
	  
	  sprintf(cond, "foreign_userid = '%.128s'", tmp2);
     }

     /*Get the block and grants list. */
     sprintf(cmd, "SELECT DISTINCT allow FROM access_lists WHERE owner=%lld AND (%s) LIMIT 1", receiver_id, cond);
     
     r = PQexec(c, cmd);
     
     if (PQresultStatus(r) != PGRES_TUPLES_OK)
	  warning(0, "grant check failed: %s", PQerrorMessage(c));
     else if ((n = PQntuples(r)) == 0) {
	  ret = 1; /* allowed: no grant or block lists. */
	  goto done;
     } 

     /* Now pass through results, and see if we have a grant or a block: Block supersedes grant. */
     
     for (i = 0; i<n; i++) {
	  char *t = PQgetvalue(r, i, 0);
	  
	  if (t && tolower(t[0]) == 'f') { /* blocked! */
	       ret = 0;
	       goto done;
	  }
     }
     ret = 1; /* allowed if not blocked. */
 done:
     PQclear(r);     
     return ret;
}

Recipient_t make_local_rcpt_struct(PGconn *c, int64_t uid, Octstr *clientid)
{
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char buf[DEFAULT_BUF_LEN*2];
     User_t s;
     ClientID_t clnt = NULL;
     ApplicationID_t appid = NULL;
     
     get_userid_and_domain(c, uid, xid, xdomain);
     
     sprintf(buf, "wv:%.128s%s%.128s", 
	     xid, xdomain[0] ? "@" : "", xdomain);
     if (clientid)
	  parse_clientid(clientid, &clnt, &appid);
     
     s = csp_msg_new(User, NULL, FV(user, csp_String_from_cstr(buf, Imps_UserID))); 
     if (clnt)
	  CSP_MSG_SET_UFIELD(s, u, Imps_ClientID, clnt);
     else if (appid)
	  CSP_MSG_SET_UFIELD(s, u, Imps_ApplicationID, appid);
     
     return csp_msg_new(Recipient, NULL, FV(ulist, gwlist_create_ex(s)));
}

Octstr *get_bytea_data(PGresult *r, int row, int col)
{
     size_t dlen = PQgetlength(r, row, col);
     char *s = PQgetvalue(r, row, col);
     char *x;
     Octstr *out;
     
     if (s && (_x_isprint(s[0]) || s[0] == '\\')) 
	  x = (void *)PQunescapeBytea((void *)s, &dlen);
     else 
	  x = s;
     out = octstr_create_from_data(x, dlen);
     
     if (x != s)
	  PQfreemem(x);
     return out;
}


void *make_user_struct(char *gsname, char *u, char *clid)
{
     void *val = NULL;
     ScreenName_t xs;
     if (gsname && gsname[0] && 
	 (xs = parse_screen_name(gsname)) != NULL) { /* a screen name as recipient -- parse it. */
	  int typ;
	  void *xval;
	  if (xs->sname == NULL || xs->sname->str[0] == 0) { /* empty screen name: means was all group. */
	       xval = csp_msg_copy(xs->gid);
	       typ = Imps_GroupID;
	       
	       csp_msg_free(xs);
	  } else {
	       typ = Imps_ScreenName;
	       xval = xs;
	  }
	  val = csp_msg_new(Group, NULL,
			    UFV(u, typ, xval));	       
     }  else {
	  ClientID_t clnt = NULL;
	  ApplicationID_t app = NULL;
	  Octstr *x = octstr_create(clid ? clid : "");
	  UserID_t xu = csp_String_from_cstr(u, Imps_UserID);
	  
	  parse_clientid(x, &clnt, &app); /* doesn't matter if they are NULL, we'll skip them */
	  val = csp_msg_new(User, NULL,
			    FV(user, xu),
			    UFV(u, clnt ? Imps_ClientID : Imps_ApplicationID,
				clnt ? (void *)clnt : (void *)app));
	  octstr_destroy(x);
	  if (clnt)
	       csp_msg_free(app);
     }
     
     return val;
}

Sender_t make_sender_struct2(Octstr *userid,  Octstr *clientid, char *sname, char *grpname)
{

     if (userid) {
	  UserID_t ux;
	  User_t u;
	  ApplicationID_t appid = NULL;
	  ClientID_t clnt = NULL;

	  /* build the sender element: we need it. */
	  parse_clientid(clientid, &clnt, &appid);
	  
	  ux = csp_String_from_bstr(userid, Imps_UserID);	  
	  u = csp_msg_new(User, NULL,
			  FV(user, ux),
			  UFV(u, clnt ? (int)Imps_ClientID : (int)Imps_ApplicationID, 
			      clnt ? (void *)clnt : (void *)appid));
	  if (clnt)
	       csp_msg_free(appid);
	  else 
	       csp_msg_free(clnt);
	  return csp_msg_new(Sender, NULL,
			     UFV(u,Imps_User,u));	  
     } else {
	  void *val;
	  GroupID_t gid = csp_String_from_cstr(grpname, Imps_GroupID);
	  Group_t g;
	  if (sname && sname[0]) 
	       val  = csp_msg_new(ScreenName, 
				  NULL,
				  FV(sname, csp_String_from_cstr(sname, Imps_SName)),
				  FV(gid, gid));
	  else 
	       val = gid;
	  g = csp_msg_new(Group, NULL,
			  UFV(u, CSP_MSG_TYPE(val), val));
	  return csp_msg_new(Sender, NULL,
			     UFV(u,Imps_Group,g));	  
     }    
}

Sender_t make_sender_struct(PGconn *c, int64_t uid, Octstr *clientid, char *sname, char *grpname)
{
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     Octstr *userid;
     void *s;
     
     if (uid >= 0)  {
	  get_userid_and_domain(c, uid, xid, xdomain);
	  userid = octstr_format("wv:%.128s%s%.128s", 
				 xid, xdomain[0] ? "@" : "", xdomain);
     } else 
	  userid = NULL;

     s = make_sender_struct2(userid, clientid, sname, grpname);

     octstr_destroy(userid);
     return s;
}

static int str_isprint(char *s, int len)
{
     int i;

     for (i = 0; i < len; i++)
	  if (!_x_isprint(s[i]))
	      return 0;
     return 1;     
}

/* returns 1 if message was modified. */
int  do_conditional_msg_encoding(String_t *data, int binary, ContentEncoding_t *enc)
{

     char *s = (char *)(*data)->str;
     int len = (*data)->len;
     int typ = CSP_MSG_TYPE(*data);

     /* Remember: Spec only defines Base64 as the allowed content encoding.
      */


     if (binary) { /* receiver uses binary */
	  if (*enc == NULL ||  /* no encoding. go away. */
	      strcasecmp(csp_String_to_cstr(*enc), "base64") != 0) {
	       if (*enc == NULL)
		    *enc = csp_String_from_cstr("None", Imps_ContentEncoding); 
	       return 0;
	  }  else { /* unencode it. */
	       Octstr *x = octstr_create_from_data(s, len);
	       
	       octstr_base64_to_binary(x);
	       *data = csp_String_from_bstr(x, typ);
	       octstr_destroy(x);

	       csp_msg_free(*enc);
	       *enc = csp_String_from_cstr("None", Imps_ContentEncoding);  /* no more encoding. */
	  }	  
     } else { /* not binary. */
	  Octstr *x;
	  int plain_text;

	  if (*enc && strcasecmp(csp_String_to_cstr(*enc), "base64") == 0)
	       return 0; /* nothing to do. */

	  csp_msg_free(*enc);

	  plain_text = str_isprint(s, len);
	  x = octstr_create_from_data(s, len);
	  if (plain_text) {
	       octstr_convert_to_html_entities(x); /* Kill all non-compliant XML characters. */
	       *enc = csp_String_from_cstr("None", Imps_ContentEncoding);
	  } else {
	       octstr_binary_to_base64(x);
	       *enc = csp_String_from_cstr("BASE64", Imps_ContentEncoding);
	  }
	  *data = csp_String_from_bstr(x, typ);	       	       
	  octstr_destroy(x);
     }
              
     return 1;
}

void make_msg_data(MessageInfo_t minfo, String_t *data, int binary)
{
     long len;
     void *old_enc = minfo->enc;
     do_conditional_msg_encoding(data, binary, &minfo->enc);

     if (old_enc && minfo->enc == NULL)
	  CSP_MSG_CLEAR_FIELD(minfo, enc);	  
     else if (old_enc != minfo->enc && !csp_msg_field_isset(minfo,enc)) /* it was not set, so it should now be set, if not yet set. */
	  csp_msg_set_fieldset(minfo, "enc");
     
     len = data ? csp_String_len(*data) : 0;
     /* Set the message size, because some clients demand it. */
     if (!csp_msg_field_isset(minfo, size))
	  CSP_MSG_SET_FIELD(minfo, size, len);
}

/* according to CSP sec. 5.3 */
int isvalid_nameid(char *name)
{
     
     while (*name) {
	  if (*name == '/' ||
	      *name == '@' ||
	      isspace(*name) || 
	      *name == '+')
	       return 0;
	  name++;
     }
     return 1;
}

Octstr *make_salt(RequestInfo_t *ri)
{
     Octstr *x = octstr_format("%s-%S-%S", ri->xsessid, ri->clientid, ri->cookie);
     Octstr *y = md5digest(x);
     
     octstr_destroy(x);
     return y;
}

Octstr *get_setting(PGconn *c, char *setting)
{
     char cmd[512];
     Octstr *v;
     PGresult *r;
     
     gw_assert(setting);

     sprintf(cmd, "SELECT value FROM settings WHERE item = '%s'", setting);

     r = PQexec(c, cmd);

     if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0) 
	  v = octstr_create(PQgetvalue(r, 0, 0));
     else 
	  v = NULL;
     PQclear(r);
     return v;
}

int check_salt(RequestInfo_t *ri, char *salt)
{
     Octstr *x = make_salt(ri);
     int res = octstr_str_case_compare(x, salt);
     
     octstr_destroy(x);
     
     return res;
}

int _x_isprint(int ch)
{
     return (isprint(ch) || isspace(ch));     
}


void mylist_combine(List *l, List *n)
{

     if (!n)
          return;
     if (l)
          while (gwlist_len(n) > 0)
               gwlist_append(l, gwlist_extract_first(n));
     gwlist_destroy(n,NULL); /* it is empty, so destructor can be NULL. */
}

int fetch_url(Octstr *url, int method, Octstr *body, List *rh, char *body_ctype, Octstr *cfile)
{
     List  *rph = NULL;
     HTTPCaller *c = http_caller_create();
     Octstr *furl = NULL, *rbody = NULL;
     int status;
     
     
     gw_assert(rh);
     http_header_add(rh, "User-Agent", SYSTEM_NAME);
     if (body_ctype) 
	  http_header_add(rh, "Content-Type", body_ctype);
     
     http_start_request(c, method, url, rh, body, 1, NULL, cfile);
     if (http_receive_result_real(c, &status, &furl, &rph, &rbody, 1) == NULL)
	  status = -1;
     
     octstr_destroy(rbody);
     octstr_destroy(furl);
     http_caller_destroy(c);
     http_destroy_headers(rph);
     
     return status;
}

Octstr *get_sender_domain(Sender_t sender)
{
     Octstr *domain;
     if (sender == NULL)
	  return NULL;
     
     if (sender->u.typ == Imps_User) {
	  User_t u = sender->u.val;
	  Octstr *ux = (u && u->user) ? csp_String_to_bstr(u->user) : octstr_imm("");
	  int x = octstr_search_char(ux, '@', 0);

	  if (x >= 0)
	       domain = octstr_copy(ux, x + 1, octstr_len(ux));
	  else 
	       domain = octstr_imm("");	  
	  octstr_destroy(ux);
     } else { /* group. */
	  Group_t g = sender->u.val;
	  GroupID_t grp = (g->u.typ == Imps_GroupID) ? g->u.val : 
	       (g->u.val ? ((ScreenName_t)g->u.val)->gid : NULL);
	  Octstr *gx = (grp) ? csp_String_to_bstr(grp) : octstr_imm("");
	  int x = octstr_search_char(gx, '@', 0);

	  if (x >= 0)
	       domain = octstr_copy(gx, x + 1, octstr_len(gx));
	  else 
	       domain = octstr_imm("");	  
	  octstr_destroy(gx);

     }
     return domain;
}

HTTPRequest_t *make_http_request_info(List *rh, Octstr *uri, 
				      Octstr *body, 
				      HTTPClient *client,
				      Octstr *ip, 
				      List *cgivars)
{
     HTTPRequest_t *r = gw_malloc(sizeof r[0]);
     
     r->ip = ip;
     r->body = body;
     r->c = client;
     r->rh = rh;
     r->cgivars = cgivars;
     r->uri = uri;
     r->ua = http_header_value(rh, octstr_imm("User-Agent"));
     
     return r;
}

void free_http_request_info(HTTPRequest_t *r)
{
     
     gw_assert(r);

     octstr_destroy(r->ip);
     octstr_destroy(r->uri);
     octstr_destroy(r->body);
     http_destroy_headers(r->rh);
     http_destroy_cgiargs(r->cgivars);
     octstr_destroy(r->ua);
     gw_free(r);
}

void send_http_ack(HTTPClient *c, int code)
{
     List *rh = http_create_empty_headers();
     http_header_add(rh, "Connection", "keep-alive");
     http_send_reply(c, code,rh, octstr_imm(""));
     http_destroy_headers(rh);
}

Octstr *_xmlNodeContent(xmlNodePtr node)
{
     char *s = (void *)xmlNodeGetContent(node);
     Octstr *x = s ? octstr_create(s) : octstr_create("");
     
     xmlFree(s);
     octstr_strip_blanks(x); /* because of xml node content semantics! */
     return x;
}

UserMapList_t convert_ulist_to_mapping(UserList_t ulist)
{
     UserMapping_t um = csp_msg_new(UserMapping, NULL, FV(mlist,gwlist_create()));
     UserMapList_t uml = csp_msg_new(UserMapList, NULL, FV(umap, um));
     int i, n;
     User_t u;
     ScreenName_t s;
     
     gw_assert(ulist);
     
     for (i = 0, n = gwlist_len(ulist->ulist); i <n; i++) 
	  if ((u = gwlist_get(ulist->ulist, i))  != NULL) 	       
	       gwlist_append(um->mlist, 
			     csp_msg_new(Mapping, NULL, 
					 FV(userid, csp_msg_copy(u->user))));

     for (i = 0, n = gwlist_len(ulist->slist); i <n; i++) 
	  if ((s = gwlist_get(ulist->slist, i))  != NULL) 	       
	       gwlist_append(um->mlist, 
			     csp_msg_new(Mapping, NULL, 
					 FV(sname, csp_msg_copy(s->sname))));     
     return uml;
}


UserList_t convert_mapping_to_ulist(UserMapList_t umlist)
{
     UserList_t ul = csp_msg_new(UserList, NULL,
				 FV(slist, gwlist_create()),
				 FV(ulist, gwlist_create()));
     List *l = umlist && umlist->umap ? umlist->umap->mlist : NULL; 
     int i, n;
     Mapping_t m;

     for (i = 0, n = gwlist_len(l); i <n; i++) 
	  if ((m = gwlist_get(l, i))  != NULL) {
	       if (csp_msg_field_isset(m, sname)) 
		    gwlist_append(ul->slist, 
				  csp_msg_new(ScreenName, NULL,
					      FV(sname, csp_msg_copy(m->sname))));
	       if (csp_msg_field_isset(m, userid)) 
		    gwlist_append(ul->ulist, 
				  csp_msg_new(User, NULL,
					      FV(userid, csp_msg_copy(m->userid))));
	  }
     return ul;
}

int verify_ssp_sender(User_t sender, Octstr *b_domain)
{
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     
     if (sender == NULL)
	  return 200; /* sender will be found by other means. */
     
     extract_id_and_domain(csp_String_to_cstr(sender->user), xid, xdomain);
     
     if (octstr_str_case_compare(b_domain, xdomain) == 0)
	  return 200;
     else 
	  return 901;
}

/* returns type of first pending message, and also the msg (in msg). Returns NULL if no messages. */
void *get_pending_msg(RequestInfo_t *ri)
{

     PGresult *r, *r2;
     char tmp1[DEFAULT_BUF_LEN], cmd[512], cmd2[512];
     Octstr *data = NULL;
     int mtype, num_fetches;
     char *uname, *rpath, *sname, *rid, *qid, *xmtype;
     void *msg = NULL;

     
     PQ_ESCAPE_STR(ri->c, octstr_get_cstr(ri->clientid), tmp1);
     sprintf(cmd, "SELECT msg_type, msg_data,internal_rcpt_struct_path, full_userid, screen_name, rid, id,num_fetches "
	     " FROM csp_message_recipients_view WHERE userid = %lld AND "
	     " (clientid IS NULL OR clientid = '' OR clientid = '%.128s') AND msg_status IN ('N','F') and edate > current_timestamp "
	     " AND next_fetch <= current_timestamp "
	     "  ORDER BY rid ASC,msg_status ASC LIMIT 1",
	     ri->uid, tmp1); /* we don't lock here, but below we try to detect if message gets fetched again. */
     r = PQexec(ri->c, cmd);

     if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) < 1)
	  goto done;

     xmtype = PQgetvalue(r, 0, 0);
     mtype = csp_name_to_type(xmtype);
     data = get_bytea_data(r, 0, 1);
     rpath = PQgetvalue(r, 0, 2);     
     uname = PQgetvalue(r, 0, 3);
     sname = PQgetvalue(r, 0, 4);
     rid = PQgetvalue(r, 0, 5);
     qid = PQgetvalue(r, 0, 6);
     num_fetches = atoi(PQgetvalue(r, 0, 7));

     if ((msg = csp_msg_from_str(data, mtype)) == NULL) { /* failed to parse. Or something. */
	  PGresult *r;
	  error(0, "Failed to parse msg in csp queue id [%s] of type [%s] for recipient [%s]"
		" Further delivery attempts disabled", qid, xmtype, uname && uname[0] ? uname : sname);
	  
     	  sprintf(cmd, "UPDATE  csp_message_recipients  SET msg_status = 'R'  WHERE id = %s ", rid);  
	  r = PQexec(ri->c, cmd);
	  PQclear(r);
	  goto done;
     }
          
     if  (rpath && rpath[0]) { /* find the Recipient Struct, fix it up. */
	  char *pname, *plast;
	  void *r;
	  int fnum;
	  for (r = msg, pname = strtok_r(rpath, ",;", &plast);
	       pname && r; 
	       pname = strtok_r(NULL, ",;", &plast)) 	       
	       if ((fnum = csp_get_field_num(r, pname)) < 0) 
		    r = NULL;
	       else 
		    r = csp_msg_get_field_value(r, fnum);
	  
	  if (r && CSP_MSG_TYPE(r) == Imps_Recipient) 
	       fixup_rcpt_field(r, sname, uname, octstr_get_cstr(ri->clientid));
	  else 
	       warning(0, "Rcpt path for csp_queue recipient entry [%s] has wrong path: %s",
		       rid, PQgetvalue(r, 0, 2));
     }
     

     if (mtype == Imps_NewMessage) { /* handle Push vs. Get/Notify */
	  NewMessage_t nm = msg;
	  if (ri->sinfo.deliver_method == NotifyGet_DMethod || 
	      octstr_len(data) > ri->sinfo.push_len) {
	       
	       MessageNotification_t m = csp_msg_new(MessageNotification, 
						     NULL, 
						     FV(minfo, nm->minfo)); /* steal the field. */
	       nm->minfo = NULL; /* stolen, so zero out, then delete */
	       csp_msg_free(nm);
	       
	       msg = m;
	       mtype = Imps_MessageNotification;
	  } else
	       make_msg_data(nm->minfo, &nm->data, ri->binary);	       

	  /* mark the message as fetched, check if it is still not yet fetched */
	  sprintf(cmd, "UPDATE csp_message_recipients SET msg_status = 'F',num_fetches = num_fetches + 1,"
		  " next_fetch = current_timestamp + '%ld secs'::interval "
		  " WHERE id = %s AND next_fetch < current_timestamp "
		  " RETURNING id",  (long)2*ri->conf->min_ttl, rid);
	  cmd2[0] = 0; 
     } else  {       
     	  sprintf(cmd, "DELETE FROM csp_message_recipients  WHERE id = %s RETURNING id ",
		  rid);  /* consider the message delivered, remove it.. */
	  sprintf(cmd2, " DELETE FROM csp_message_queue WHERE id = %s AND NOT "
		  " EXISTS (SELECT id FROM csp_message_recipients WHERE messageid=%s) ",
		  qid, qid);
     }
     
     if (mtype == Imps_PresenceNotification_Request) {
	  PresenceNotification_Request_t pn = msg;
	  
	  int i, n;
	  
	  /* Massage presence attributes to fit the csp version. */
	  for (i = 0, n = gwlist_len(pn->plist); i<n; i++) {
	       Presence_t p = gwlist_get(pn->plist, i);
	       int j, m;
	       
	       if (!p) continue;
	       for (j = 0, m = gwlist_len(p->pslist); j<m; j++) 
		    fixup_pres_for_cspversion(gwlist_get(p->pslist, j), ri->ver);
	  }
	  
	  
     } else if (mtype == Imps_GroupChangeNotice &&  /* fixup joined struct */
		csp_msg_field_isset(msg, joined)) {
	  GroupChangeNotice_t gc = msg;
	  Joined_t j = gc->joined;
	  
	  if (ri->ver < CSP_VERSION(1,2) ) { /* uses userlist. */
	       UserList_t x;
	       if (j && csp_msg_field_isset(j, umlist))  {
		    x = convert_mapping_to_ulist(j->umlist);
		    if (csp_msg_field_isset(j, ulist))
			 CSP_MSG_CLEAR_SFIELD(j, ulist);
		    CSP_MSG_SET_FIELD(j, ulist, x);
	       }
	  } else if (ri->ver >= CSP_VERSION(1,2)) {
	       UserMapList_t x;

	       if (j && csp_msg_field_isset(j, ulist)) {
		    x = convert_ulist_to_mapping(j->ulist);
		    if (csp_msg_field_isset(j, umlist))
			 CSP_MSG_CLEAR_SFIELD(j, umlist);
		    CSP_MSG_SET_FIELD(j, umlist, x);	       
	       } 
	  }	  
     }
     
     
     r2 = PQexec(ri->c, cmd);
     if (PQresultStatus(r2) !=  PGRES_TUPLES_OK || PQntuples(r2) < 1) { 
        /* message was delivered in the meantime to a parallel session.*/
	  info(0, "Parallel fetch of message for %s [rid=%d, type=%s]", 
	       octstr_get_cstr(ri->userid), (int)rid, csp_obj_name(mtype));
	  csp_msg_free(msg);
	  msg = NULL;
     }
     PQclear(r2);

     if (cmd2[0]) {
	  r2 = PQexec(ri->c, cmd2);
	  PQclear(r2);
     }
     
done:
     PQclear(r);     
     octstr_destroy(data);
     return msg;
}

static void strip_quotes(Octstr *s)
{
     int l = s ? octstr_len(s) : 0;

     if (l == 0)
	  return;
     if (octstr_get_char(s, 0) == '"') {
	  octstr_delete(s, 0, 1);
	  l--;
     }
     if (octstr_get_char(s, l-1) == '"')
	  octstr_delete(s, l-1, 1);     
}

List  *get_value_parameters(Octstr *params)
{
     int i,n, k = 0;
     List *h = http_create_empty_headers();
     Octstr *xparams = octstr_duplicate(params);

     octstr_format_append(xparams, ";"); /* So parsing is easier. (aka cheap hack) */

     for (i = 0, n = octstr_len(xparams); i < n; i++) {
	  int c = octstr_get_char(xparams, i);

	  if (c == ';') {
	       int j  = octstr_search_char(xparams, '=', k);
	       Octstr *name, *value;
	       if (j > 0 && j < i) {
		    name = octstr_copy(xparams, k, j - k);
		    value = octstr_copy(xparams, j+1,i-j-1);
		    octstr_strip_blanks(name);
		    octstr_strip_blanks(value);
		    strip_quotes(value);
		    if (octstr_len(name) > 0)
			 http_header_add(h, 
					 octstr_get_cstr(name), 
					 octstr_get_cstr(value));
		    octstr_destroy(name); 
		    octstr_destroy(value);
	       }
	       k = i + 1;
	  } else if (c == '"') 
	       i += http_header_quoted_string_len(xparams, i) - 1;	  
     }
     octstr_destroy(xparams);
     return h;
}

int split_header_value(Octstr *value, Octstr **base_value, Octstr **params)
{

     int i, n;
     for (i = 0, n = octstr_len(value); i < n; i++) {
	  int c = octstr_get_char(value, i);

	  if (c == ';')
	       break;
	  else if (c == '"') 
	       i += http_header_quoted_string_len(value, i) - 1;	  
     }

     *base_value = octstr_duplicate(value);     
     if (i < n) {
	  *params = octstr_copy(value, i+1, octstr_len(value));
	  octstr_delete(*base_value, i, octstr_len(*base_value));
     } else 
	  *params = octstr_create("");
     return 0;

}

/* borrowed from mbuni. */

/* Mapping file extensions to content types. */
static struct {
     char *ctype,  *file_ext;
} exts[] = {
     {"text/plain", "txt"},
     {"image/jpeg",  "jpg"},
     {"image/jpeg",  "jpeg"},
     {"image/png",  "png"},
     {"image/tiff",  "tiff"},
     {"image/gif",  "gif"},
     {"image/bmp",  "bmp"},
     {"image/vnd.wap.wbmp",  "wbmp"},
     {"image/x-bmp",  "bmp"},
     {"image/x-wmf",  "bmp"},
     {"image/vnd.wap.wpng",  "png"},
     {"image/x-up-wpng",  "png"},
     {"audio/mpeg",  "mp3"},
     {"audio/wav",  "wav"},
     {"audio/basic",  "au"},
     {"audio/amr",  "amr"},
     {"audio/x-amr",  "amr"},
     {"audio/amr-wb",  "amr"},
     {"audio/midi",  "mid"},
     {"audio/sp-midi",  "mid"},  
     {"application/smil", "smil"},
     {"application/vnd.wap.mms-message", "mms"},
     {"application/java-archive", "jar"},
     {"video/3gpp", "3gp2"},
     {"video/3gpp", "3gp"},
     {"video/3gpp2", "3g2"},
     {NULL, NULL}
};

Octstr *filename2content_type(char *fname)
{
     char *p = strrchr(fname, '.');
     int i;
     
     if (p) 
	  for (i = 0; exts[i].file_ext; i++)
	       if (strcasecmp(p+1, exts[i].file_ext) == 0)
		    return octstr_imm(exts[i].ctype);
     
     return octstr_imm("application/octet-stream");          
}


int get_content_type(List *hdrs, Octstr **type, Octstr **params)
{
     
     Octstr *v;
     
     v = http_header_find_first(hdrs, "Content-Type");	  
     *params =NULL;

     if (!v) {
	  *type = octstr_create("application/octet-stream");
	  *params = octstr_create("");
	  return -1;          
     }

     split_header_value(v, type, params);

     octstr_destroy(v);
     return 0;
}

static int is_mime_special_char(int ch)
{
     const char *x = "=;<>[]?()@:\\/,";
     char *p;
     for (p = (char *)x; *p; p++)
	  if (ch == *p)
	       return 1;
     return 0;
}
static int needs_quotes(Octstr *s)
{
     int i, n;
     if (!s) 
	  return 0;
     
     for (i = 0, n = octstr_len(s); i<n; i++) {
	  int ch = octstr_get_char(s,i);
	  if (isspace(ch) || is_mime_special_char(ch))
	       return 1;
     }
     return 0;
}

Octstr *make_value_parameters(List *params)
{
     Octstr *s = octstr_create(""), *name, *value;
     int i, n;

     for (i = 0, n = params ? gwlist_len(params) : 0; i<n; i++) {
	  int space;
	  http_header_get(params, i, &name, &value);
	  space = needs_quotes(value);
	  octstr_format_append(s, "%s%S=%s%S%s", 
			       (i==0) ? "" : "; ", 
			       name, 
			       (space) ? "\"" : "",
			       value,
			       (space) ? "\"" : "");
	  octstr_destroy(name);
	  octstr_destroy(value);
     }
     return s;
}


static int fetch_url_with_auth(HTTPCaller *c, int method, Octstr *url, List *request_headers, 
			       Octstr *body, Octstr *auth_hdr, List **reply_headers, Octstr **reply_body);

int url_fetch_content(int method, Octstr *url, List *request_headers, 
			      Octstr *body, List **reply_headers, Octstr **reply_body)
{

     int status = 0;
     Octstr *furl = NULL;

     if (octstr_search(url, octstr_imm("data:"), 0) == 0) {
	  int i = octstr_search_char(url, ',',0);
	  Octstr *ctype = (i >= 0) ? octstr_copy(url, 5, i-5) : octstr_create("text/plain; charset=us-ascii");
	  Octstr *data = (i >= 0) ? octstr_copy(url, i+1, octstr_len(url)) : octstr_duplicate(url);

	  Octstr *n = NULL, *h = NULL;
	  
	  if (octstr_len(ctype) == 0)
	       octstr_append_cstr(ctype, "text/plain; charset=us-ascii");

	  split_header_value(ctype, &n, &h);
	  
	  if (h) {
	       List *ph = get_value_parameters(h);
	       Octstr *v = NULL;

	       if (ph && (v = http_header_value(ph, octstr_imm("base64"))) != NULL) { /* has base64 item */
		    Octstr *p = NULL;

		    octstr_base64_to_binary(data);
		    http_header_remove_all(ph, "base64");
		    
		    octstr_destroy(ctype);
		    
		    if (gwlist_len(ph) > 0) {
			 p = make_value_parameters(ph);
			 ctype = octstr_format("%S; %S",
					       n,p);
			 octstr_destroy(p);
		    } else 
			 ctype = octstr_format("%S", n);
	       }
	       
	       if (ph)
		    http_destroy_headers(ph);

	       octstr_destroy(v);
	       octstr_destroy(h);
	  }
	  
	  octstr_destroy(n);

	  *reply_body = data;
	  *reply_headers = http_create_empty_headers();
	  http_header_add(*reply_headers, "Content-Type", octstr_get_cstr(ctype));

	  octstr_destroy(ctype);
	  status = HTTP_OK;
     } else  if (octstr_search(url, octstr_imm("file://"), 0) == 0) {
	  char *file = octstr_get_cstr(url) + 6;
          Octstr *ctype = filename2content_type(file);
	  Octstr *data = octstr_read_file(file);

	  *reply_body = data;
	  *reply_headers = http_create_empty_headers();
	  http_header_add(*reply_headers, "Content-Type", octstr_get_cstr(ctype));

          status = data ? HTTP_OK : HTTP_NOT_FOUND;	  
	  octstr_destroy(ctype);	  
     } else {
	  HTTPCaller *c = http_caller_create();
	  http_start_request(c, method, url, request_headers, body, 1, NULL, NULL);	  
	  if (http_receive_result_real(c, &status, &furl, reply_headers, reply_body,1) == NULL)
	       status = -1;
	  if (status == HTTP_UNAUTHORIZED) { 
	       Octstr *v = http_header_value(*reply_headers, octstr_imm("WWW-Authenticate"));
	       
	       status = fetch_url_with_auth(c, method, url, request_headers, body, v, 
					    reply_headers, reply_body);

	       octstr_destroy(v);
	  }
	  http_caller_destroy(c);
     }

     octstr_destroy(furl);

     return status;
}

 Octstr *get_stripped_param_value(Octstr *value, Octstr *param)
{
     Octstr *x = http_get_header_parameter(value, param);

     if (x != NULL && 
	 octstr_get_char(x, 0) == '"' &&
	 octstr_get_char(x, octstr_len(x) - 1) == '"') {
	  octstr_delete(x, 0, 1);
	  octstr_delete(x, octstr_len(x) - 1, 1);
     }
     return x;    
}


static Octstr *make_url(HTTPURLParse *h);

/* Fetch a url with authentication as necessary. */
static int fetch_url_with_auth(HTTPCaller *c, int method, Octstr *url, List *request_headers, 
			       Octstr *body, Octstr *auth_hdr,  List **reply_headers, Octstr **reply_body)
{
     Octstr *xauth_value = auth_hdr ? octstr_duplicate(auth_hdr) : octstr_create("");
     Octstr *domain = NULL, *nonce = NULL, *opaque = NULL, *algo = NULL, *auth_type = NULL, *x;
     Octstr *realm = NULL, *xurl = NULL;
     Octstr *cnonce = NULL;
     char *nonce_count = "00000001";
     Octstr *A1 = NULL, *A2 = NULL, *rd = NULL;
     List *qop = NULL, *l = NULL;
     int i, status = HTTP_UNAUTHORIZED, has_auth = 0, has_auth_int = 0;
     HTTPURLParse *h = parse_url(url);
     char *m_qop = NULL;
     time_t t  = time(NULL);
     
     /* Check that there is a username and password in the URL! */

     if (h == NULL || h->user == NULL || octstr_len(h->user) == 0) 
	  goto done;
          
     /* First we get the auth type: */
     
     if ((i = octstr_search_char(xauth_value, ' ', 0)) < 0) {
	  warning(0, "Mal-formed WWW-Authenticate header (%s) received while fetching %s!",
		  octstr_get_cstr(xauth_value), url ? octstr_get_cstr(url) : "");
	  status = -1;
	  goto done;
     }
     auth_type = octstr_copy(xauth_value, 0, i);
     octstr_delete(xauth_value, 0, i+1);

     if (octstr_str_case_compare(auth_type, "Basic") == 0) {
	  status = HTTP_UNAUTHORIZED; /* suported by default by GWLIB so if we get here, means bad passwd. */
	  goto done;
     } /* else digest. */

     /* Put back some fake data so what we have can be parsed easily. */
     if ((l =  http_header_split_auth_value(xauth_value)) != NULL) {
	  Octstr *x = gwlist_get(l, 0);
	  octstr_insert(x, octstr_imm("_none; "), 0); /* make it easier to parse. */
	  octstr_destroy(xauth_value);
	  xauth_value = octstr_duplicate(x);
	  
	  gwlist_destroy(l, (gwlist_item_destructor_t *)octstr_destroy);
     } else 
	  warning(0, "Mal-formed Digest header (%s) while fetching (%s)!", 
		  octstr_get_cstr(xauth_value), url ? octstr_get_cstr(url) : "");
     
     realm = get_stripped_param_value(xauth_value, octstr_imm("realm"));
     domain = get_stripped_param_value(xauth_value, octstr_imm("domain"));
     nonce = get_stripped_param_value(xauth_value, octstr_imm("nonce"));
     opaque = get_stripped_param_value(xauth_value, octstr_imm("opaque"));     
     algo = get_stripped_param_value(xauth_value, octstr_imm("algorithm"));

     if ((x = get_stripped_param_value(xauth_value, octstr_imm("qop"))) != NULL) {
	  int i;
	  qop = octstr_split(x, octstr_imm(","));
	  octstr_destroy(x);
	  for (i = 0; i<gwlist_len(qop); i++) { /* find qop options. */
	       Octstr *s = gwlist_get(qop, i);
	       if (!s) continue;
	       if (octstr_str_case_compare(s, "auth") == 0)
		    has_auth = 1;
	       else if (octstr_str_case_compare(s, "auth-int") == 0)
		    has_auth_int = 1;
	  }
     }
     
     if (qop || 
	 (algo != NULL && octstr_str_case_compare(algo, "MD5-sess") == 0)) {
	  cnonce = octstr_create_from_data((void *)&t, sizeof t);
	  octstr_binary_to_hex(cnonce,0);
     }

     /* Make A1 */
     x = octstr_format("%S:%S:%S",
		       h->user, realm, h->pass ? h->pass : octstr_imm(""));
     A1 = md5(x);
     octstr_destroy(x);

     if (algo != NULL && octstr_str_case_compare(algo, "MD5-sess") == 0) {
	  x = octstr_format("%S:%S:%S", 
			    A1, nonce, cnonce);
	  octstr_destroy(A1);
	  A1 = md5(x);
	  octstr_destroy(x);	  
     }
     octstr_binary_to_hex(A1,0);

     /* Make A2. */
     x = octstr_format("%s:%S",
		       http_method2name(method), 
		       h->path);
     if (qop != NULL && has_auth_int && !has_auth) { /* if qop, and qop=auth-int */
	  Octstr *y; 
	  m_qop = "auth-int";
	  
	  y = md5(body);
	  octstr_binary_to_hex(y,0);

	  octstr_append_char(x, ':');
	  octstr_append(x, y);

	  octstr_destroy(y);
     } else if (qop)
	  m_qop = "auth";

     A2 = md5(x);
     octstr_destroy(x);
     octstr_binary_to_hex(A2,0);
     
     /* Finally make the digest response */
     if (qop) 
	  x = octstr_format("%S:%S:%s:%S:%s:%S",
			    A1, nonce, nonce_count, cnonce,
			    m_qop, A2);
     else 
	  x = octstr_format("%S:%S:%S", A1, nonce, A2);

     rd = md5(x);
     octstr_destroy(x);
     octstr_binary_to_hex(rd, 0);
     
     
     /* make the header value */
     x = octstr_format("Digest username=\"%S\", realm=\"%S\", response=\"%S\", nonce=\"%S\", uri=\"%S\"",
		       h->user, realm, rd, nonce, h->path);

     if (opaque) 
	  octstr_format_append(x, ", opaque=\"%S\"", opaque);
     
     if (cnonce) 
	  octstr_format_append(x, ", cnonce=\"%S\", nc=%s", cnonce, nonce_count);
     if (m_qop)
	  octstr_format_append(x,", qop=%s", m_qop);
     if (algo)
	  octstr_format_append(x,", algorithm=%S", algo);

     http_header_remove_all(request_headers, "Authorization");
     http_header_add(request_headers, "Authorization", octstr_get_cstr(x));
     octstr_destroy(x);

     /* Remove username, password, then remake URL */
     octstr_destroy(h->user);
     h->user = NULL;
	 
     octstr_destroy(h->pass);
     h->pass = NULL;

     xurl = make_url(h);
     x = NULL;
     http_start_request(c, method, xurl, request_headers, body, 1, NULL, NULL);	  
     if (http_receive_result_real(c, &status, &x, reply_headers, reply_body,1) == NULL)
	  status = -1;
     if (x)
	  octstr_destroy(x);
 done:
     octstr_destroy(xauth_value);     
     octstr_destroy(realm);     
     octstr_destroy(domain);
     octstr_destroy(nonce);
     octstr_destroy(opaque);
     octstr_destroy(algo);
     octstr_destroy(xurl);
     octstr_destroy(cnonce);
     gwlist_destroy(qop, (gwlist_item_destructor_t *)octstr_destroy);     
     if (h)
	  http_urlparse_destroy(h);
     
     return status;
}


static Octstr *make_url(HTTPURLParse *h)
{
     Octstr *url = octstr_duplicate(h->scheme);
     
     if (h->user) {
	  octstr_format_append(url, "%S", h->user);
	  
	  if (h->pass)
	       octstr_format_append(url, ":%S", h->pass);	       
	  octstr_format_append(url, "@");
     }
     octstr_format_append(url, "%S:%d%S", h->host, h->port, h->path);
     
     if (h->query)
	  octstr_format_append(url, "?%S", h->query);

     if (h->fragment)
	  octstr_format_append(url, "#%S", h->fragment);
     return url;
}

#if 0
void _gw_free(void *x)
{
     gw_free(x);
}
#endif
/* table of functions. */

#define CSP_FUNC(msgtype, handler) [Imps_##msgtype] = (request_func_t)(handler)

const request_func_t req_funcs[] = {
     CSP_FUNC(Login_Request, handle_login),
     
     CSP_FUNC(Logout_Request, handle_logout),	       
     CSP_FUNC(Service_Request, handle_serviceRequest),
     
     CSP_FUNC(ClientCapability_Request, handle_cap_request),
     
     CSP_FUNC(Search_Request, handle_search),
	       
     CSP_FUNC(StopSearch_Request, handle_stopsearch),
	       
     
     CSP_FUNC(CancelInvite_Request, handle_cancel_invite_request),
     
     
     CSP_FUNC(Invite_Request, handle_invite_request),
     CSP_FUNC(InviteUser_Response,handle_invite_user_response),
	       
     CSP_FUNC(VerifyID_Request, handle_verifyID),

     CSP_FUNC(KeepAlive_Request, handle_keepalive),
	       
     CSP_FUNC(GetList_Request, handle_get_list),
	       
     CSP_FUNC(CreateList_Request, handle_create_list),
	       
     CSP_FUNC(DeleteList_Request, handle_delete_list),
     
     CSP_FUNC(ListManage_Request, handle_manage_list),
	       
	       
     CSP_FUNC(CreateAttributeList_Request, handle_create_attribs),
     
     
     CSP_FUNC(DeleteAttributeList_Request, handle_delete_attribs),
	       
	       
     CSP_FUNC(GetAttributeList_Request, handle_get_attribs),
     
     CSP_FUNC(SubscribePresence_Request, handle_pres_subscribe),
	       
	       
     CSP_FUNC(UnsubscribePresence_Request, handle_pres_unsubscribe),
     
     
     CSP_FUNC(PresenceAuth_User, handle_pres_auth_user),
     
     
     CSP_FUNC(GetPresence_Request, handle_get_presence),
     
     
     CSP_FUNC(UpdatePresence_Request, handle_update_presence),
	       
     CSP_FUNC(GetWatcherList_Request, handle_get_watcher),
	       
	       
     CSP_FUNC(SendMessage_Request, handle_send_im),
	       
     CSP_FUNC(SetDeliveryMethod_Request, handle_setd_method),
	       
     CSP_FUNC(ForwardMessage_Request, handle_fwd_msg),
	       
     CSP_FUNC(MessageDelivered, handle_msg_delivered),
	       
     CSP_FUNC(GetMessage_Request, handle_get_msg),
     
     CSP_FUNC(RejectMessage_Request, handle_reject_msg),
     
     CSP_FUNC(GetMessageList_Request, handle_get_message_list),
     
     CSP_FUNC(GetBlockedList_Request, handle_get_block_list),
	       
     CSP_FUNC(BlockEntity_Request, handle_block_entity_req),	

     CSP_FUNC(CreateGroup_Request, handle_create_group),
     CSP_FUNC(DeleteGroup_Request, handle_delete_group),
     CSP_FUNC(LeaveGroup_Request, handle_leave_group),
     CSP_FUNC(GetGroupMembers_Request, handle_get_group_members),
     CSP_FUNC(GetJoinedUsers_Request, handle_get_joined_users),
     CSP_FUNC(JoinGroup_Request, handle_join_group),
     CSP_FUNC(AddGroupMembers_Request, handle_add_members),
     CSP_FUNC(RemoveGroupMembers_Request, handle_del_members),
     CSP_FUNC(MemberAccess_Request, handle_member_access),
     CSP_FUNC(GetGroupProps_Request, handle_get_props),
     CSP_FUNC(SetGroupProps_Request, handle_set_props),
     CSP_FUNC(RejectList_Request, handle_reject),
     CSP_FUNC(SubscribeGroupNotice_Request, handle_subscribe_notice),

     CSP_FUNC(Polling_Request, handle_poll_req),
     CSP_FUNC(GetSPInfo_Request, handle_get_spinfo),

     CSP_FUNC(Status, handle_noop), /* XXX ignore all status messages (really??) */

     CSP_FUNC(LastOne, handle_noop) /* we need this one to ensure array is properly sized. */
};


const unsigned long req_funcs_len = NELEMS(req_funcs);
