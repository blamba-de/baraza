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
#include <gwlib/gwlib.h>
#include "pgconnpool.h"

#define DEFAULT_CONNECTIONS 5
#define DEFAULT_DB "template1"
#define MIN_PG_VERSION 80200 /* v8.2 */

static List *free_conns;
static Dict *on_commit_funcs; /* used for keeping on_commit functions: indexed by conn value, contains
			       * list of con_commit stuff. 
			       */

struct OnCommit_t {
     void (*func)(void *data);
     void *data;
};
static void free_on_commit_list(List *);
static int check_db_structure(PGconn *c);
static int handle_db_init(char *dbhost, char *dbport, char *dbname, char *dbuser, char *dbpass, 
			  char *mydomain);
int pg_cp_init(long num_conns, char *dbhost, char *dbuser, char *dbpass, char *dbname, int dbport, 
	       char *mydomain)
{
     char xport[32], *port_str;
     long i, n = num_conns;
     int x;
     PGconn *c;
     
     gw_assert(dbname);

     if (n <= 0)
          n = DEFAULT_CONNECTIONS;
     
     if (dbport > 0) {
	  sprintf(xport, "%d", dbport);
	  port_str = xport;
     } else 
	  port_str = NULL;
     
     /* Let's make a test connection to the DB. If it fails, we try to init the db. */
     if ((c = PQsetdbLogin(dbhost, port_str, NULL, NULL, dbname, dbuser, dbpass)) == NULL || 
	 PQstatus(c) != CONNECTION_OK || 
	 check_db_structure(c) < 0) {
       int x = handle_db_init(dbhost, port_str, dbname, dbuser, dbpass, mydomain);
	  PQfinish(c);
	  if (x < 0)
	       return -1;
     }  else if ((x = PQserverVersion(c)) < MIN_PG_VERSION) {
	  error(1, "Current database version [%d.%d.%d] is not supported. Minimum should be v%d.%d.%d", 
		(x/10000), (x/100) % 100, x % 100,
		(MIN_PG_VERSION/10000), (MIN_PG_VERSION/100) % 100, MIN_PG_VERSION % 100);
	  PQfinish(c);
	  return -1;
     } else
	  PQfinish(c);
     
     free_conns = gwlist_create();
     gwlist_add_producer(free_conns);     
     for (i = 0; i<n;i++) {
          c = PQsetdbLogin(dbhost, port_str, NULL, NULL, dbname, dbuser, dbpass);
          if (c && PQstatus(c) == CONNECTION_OK) 
               gwlist_produce(free_conns, c);   
          else  {
               error(0, "pg_cp_init: failed to connect to db: %s", 
                     PQerrorMessage(c));            
               PQfinish(c);
          }     
     }
     
     on_commit_funcs = dict_create(101, (void *)free_on_commit_list);
     return gwlist_len(free_conns) > 0 ? 0 : -1;
}

int pg_cp_cleanup(void)
{
     gw_assert(free_conns);
     
     gwlist_remove_producer(free_conns);
     gwlist_destroy(free_conns, (void *)PQfinish);
     free_conns = NULL;
     
     return 0;
}

PGconn *pg_cp_get_conn(void)
{
     PGconn *c;
     PGresult *r;
     gw_assert(free_conns);
     
     c = gwlist_consume(free_conns);     

     r = PQexec(c, "BEGIN"); /* start a transaction. */
     PQclear(r);
     return c;
}

void pg_cp_on_commit(PGconn *c, void (*func)(void *), void *data)
{
     Octstr *xkey = octstr_format("%ld", (long)c);
     struct OnCommit_t *x = gw_malloc(sizeof x[0]);
     List *l = gwlist_create();
     
     gw_assert(on_commit_funcs);
     
     if (dict_put_once(on_commit_funcs, xkey, l) == 0) 
	  l = dict_get(on_commit_funcs, xkey);
     
     gw_assert(l);
     x->func = func;
     x->data = data;
     gwlist_append(l, x);
     octstr_destroy(xkey);
}

void pg_cp_return_conn(PGconn *c)
{
     List *l;
     PGresult *r;
     int commit;
     Octstr *xkey = octstr_format("%ld", (long)c);     

     gw_assert(free_conns);
     
     /* commit or destroy transaction. */
     if (PQtransactionStatus(c) == PQTRANS_INERROR) {
          r = PQexec(c, "ROLLBACK");
	  commit = 0;
     } else {
	  commit = 1;
          r = PQexec(c, "COMMIT");	  
     }
     PQclear(r);

     l = dict_get(on_commit_funcs, xkey);
     dict_remove(on_commit_funcs, xkey);     

     gwlist_produce(free_conns,c); /* let the connection go. */

     if (commit) { /* call the functions. */
	  struct OnCommit_t *x;
	  int i, n;
	  
	  for (i = 0, n = gwlist_len(l); i<n; i++)
	       if ((x = gwlist_get(l, i)) != NULL) 
		    x->func(x->data);	  
     }
     free_on_commit_list(l);
     octstr_destroy(xkey);
}

static void free_on_commit_list(List *l)
{
     void *x;

     if (l == NULL) 
	  return;
     while ((x = gwlist_extract_first(l)) != NULL)
	  gw_free(x);
     gwlist_destroy(l, NULL);
}

/* checks DB structure by looking for certain key tables. */
#define CHECK_TABLE(tbl) do {						\
	  int res;							\
	  PGresult *r;							\
	  r = PQexec(c, "SELECT id FROM " tbl " LIMIT 1");		\
	  res = (PQresultStatus(r) == PGRES_TUPLES_OK);			\
	  if (res != 1)	{						\
	       error(0, "Database not (fully) setup? Table: [" tbl "] is missing: %s", \
		     PQresultErrorMessage(r));				\
	       PQclear(r);						\
	       return -1;						\
	  }								\
	  PQclear(r);							\
     } while (0)

static int check_db_structure(PGconn *c)
{
     
     CHECK_TABLE("users");
     CHECK_TABLE("sessions");
     CHECK_TABLE("contactlists");
     CHECK_TABLE("csp_message_queue");
     CHECK_TABLE("ssp_message_queue");
     return 0;
}

static char *table_cmds[];
static int handle_db_init(char *dbhost, char *dbport, char *dbname, char *dbuser, char *dbpass, 
			  char *mydomain)
{
     char buf[512];
     PGconn *c;
     PGresult *r;
     int i, x, err;
     info(0, "Attempting to initialise the database [%s] on host [%s] with user [%s]", 
	  dbname, dbhost, dbuser);
     /* first try to create the database. */
     c = PQsetdbLogin(dbhost, dbport, NULL, NULL, DEFAULT_DB, dbuser, dbpass);
     
     if (PQstatus(c) != CONNECTION_OK) {
	  error(0, "Failed to even connect to the default PostgreSQL DB [%s], err [%s]. Quiting!",
		DEFAULT_DB, PQerrorMessage(c));
	  PQfinish(c);
	  return -1;
     } else if ((x = PQserverVersion(c)) < MIN_PG_VERSION) {
	  error(0, "Current database version [%d.%d.%d] is not supported. Minimum should be v%d.%d.%d", 
		(x/10000), (x/100) % 100, x % 100,
		(MIN_PG_VERSION/10000), (MIN_PG_VERSION/100) % 100, MIN_PG_VERSION % 100);
	  PQfinish(c);
	  return -1;
     }
     
     /* attempt to create the database. */
     sprintf(buf, "CREATE DATABASE %s", dbname);
     r = PQexec(c, buf);
     if (PQresultStatus(r) != PGRES_COMMAND_OK) 
	  warning(0, "pg_init: Trying to create database %s returned an error "
		  "[%s]. Proceeding with connection anyway", dbname, PQresultErrorMessage(r));
     PQclear(r);
     PQfinish(c);
     
     /* attempt to connect to it. */     
     c = PQsetdbLogin(dbhost, dbport, NULL, NULL, dbname, dbuser, dbpass);
     if (PQstatus(c) != CONNECTION_OK) {
	  error(0, "Failed to connect to DB [%s], err [%s]. Quiting!",
		dbname, PQerrorMessage(c));
	  PQfinish(c);
	  return -1;
     }
     
     info(1, "We have a connection to [%s].  will now attempt to initialise database structure. "
	  "Watch out for errors, but note that some errors can be safely ignored!", dbname); 
     /* we have a connection: Try to create the DB structure. */
     for (i = 0, err = 0; table_cmds[i]; i++) {
	  r = PQexec(c, table_cmds[i]);
	  if (PQresultStatus(r) != PGRES_COMMAND_OK) {
	       warning(0, "Initialising command %d failed: %s", i+1, PQresultErrorMessage(r));
	       err++;
	  }
	  PQclear(r);
     }
     /* attempt to add our domain to the localdomains table */
     if (mydomain) {
	  sprintf(buf, "INSERT into localdomains (domain) VALUES ('%.128s')", mydomain);
	  r = PQexec(c, buf);
	  PQclear(r);
     }
     PQfinish(c);
     if (err == i) {
	  error(0, "All initialiser commands failed. Please seek help to create the database!");
	  return -1;
     } else 
	  info(0, "Hopefully we are done initialising the database [%s] [%d error(s)], we'll try to connect to it", dbname, err);
     return 0;
}

static char *table_cmds[] = {
"CREATE LANGUAGE plpgsql; -- and ignore result\n"
,
"CREATE TABLE users (\n"
" id bigserial PRIMARY KEY,\n"
" userid text NOT NULL,\n"
" domain text NOT NULL DEFAULT '',\n"
" \n"
" firstname text NOT NULL DEFAULT '', \n"
" lastname  text NOT NULL DEFAULT '', \n"
" \n"
" nickname  text NOT NULL DEFAULT '', -- can also be the name of the Bot\n"
" email  text NOT NULL DEFAULT '',  \n"
" phone  text NOT NULL DEFAULT '',  \n"
" city  text NOT NULL DEFAULT '',  \n"
" country  text NOT NULL DEFAULT '',  \n"
" gender  text  CHECK (gender IN ('M','F','U')),  \n"
" \n"
" dob timestamp, -- date of birth.	 \n"
" online_status text NOT NULL DEFAULT 'Offline',\n"
" intention text,\n"
" hobbies text,\n"
" marital_status varchar(1) DEFAULT 'U' CHECK (marital_status IN ('C','D','E','M','S','U','W')),\n"
" other_info text, -- free_text field\n"
" \n"
" nonce text NOT NULL DEFAULT 'nonce', -- random nonce\n"
" rand_salt text NOT NULL DEFAULT random():: text || current_timestamp::text, -- salt for use below \n"
" crypt_md5_pass text NOT NULL DEFAULT '', -- md5(md5(password + nonce) + rand_salt)\n"
" lastt timestamp NOT NULL DEFAULT current_timestamp,\n"
"   \n"
"  default_attr_list int, -- default authorised presence attr list (as a bits, one for each attribute, in order of appearance in spec)\n"
" \n"
"  default_notify boolean NOT NULL DEFAULT TRUE, -- if default notification is sought. \n"
"  grant_list_in_use boolean NOT NULL DEFAULT FALSE,\n"
"  block_list_in_use boolean NOT NULL DEFAULT FALSE,\n"
"  -- more fields as needed\n"
"  auto_reg boolean NOT NULL DEFAULT FALSE,\n"
"  bot_url text, -- If this is set, then it is the URL of the agent who handles IMs to this user. \n"
"                -- this means that this is actually a Bot not a real user. \n"
" UNIQUE(userid,domain)\n"
");\n"
,
"CREATE VIEW users_view AS \n"
"SELECT 'wv:'|| (case when domain = '' then userid else userid || '@' || domain end) as full_userid, \n"
"* from users;\n"
,
"CREATE TABLE sessions (\n"
" id bigserial PRIMARY KEY,\n"
" userid bigint REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE,\n"
" clientid text NOT NULL DEFAULT '', -- includes app ID if any\n"
" sessionid text,\n"
"  \n"
" -- More fields -- capabilities\n"
"   csp_version varchar(16) NOT NULL DEFAULT '1.2',\n"
"   pull_len int NOT NULL DEFAULT 100000,\n"
"   push_len int NOT NULL DEFAULT 100000,\n"
"   text_len int NOT NULL DEFAULT 100000,\n"
"   \n"
"   anycontent boolean NOT NULL DEFAULT FALSE,\n"
"   client_type text NOT NULL DEFAULT '',\n"
"   lang text NOT NULL DEFAULT 'en',\n"
"   deliver_method varchar(1) NOT NULL DEFAULT 'P',\n"
"   multi_trans int NOT NULL DEFAULT 1,\n"
"   offline_ete_m_handling varchar(32) NOT NULL DEFAULT 'SENDSTORE',\n"
"   online_ete_m_handling varchar(32) NOT NULL DEFAULT 'SERVERLOGIC',\n"
"   \n"
"   parse_size int NOT NULL DEFAULT 10000,\n"
"   server_poll_min int NOT NULL DEFAULT 60,\n"
"   priority int NOT NULL DEFAULT 10, -- session priority\n"
"   ip  text NOT NULL DEFAULT '', -- client  IP address as gleaned from headers.\n"
"   msisdn text, -- the session msisdn (null if not known)\n"
"   request_ip text, -- request IP\n"
"   default_notify boolean NOT NULL DEFAULT FALSE, -- whether default notification was negotiated\n"
"   caps boolean NOT NULL DEFAULT FALSE, -- whether capabilities were negotiated\n"
"   cir_mask int NOT NULL DEFAULT 0,\n"
"   cdate timestamp NOT NULL DEFAULT current_timestamp,\n"
"   lastt timestamp NOT NULL DEFAULT current_timestamp,\n"
"   ttl  int NOT NULL DEFAULT 30*60, -- default TTL in seconds. \n"
"   cookie text NOT NULL DEFAULT '',\n"
"   presence bytea, -- presence element\n"
"   last_pres_update timestamp NOT NULL DEFAULT current_timestamp,\n"
"   cir boolean NOT NULL DEFAULT FALSE, -- Whether session has CIR.\n"
"   sudp_port int NOT NULL DEFAULT 56732,\n"
"   UNIQUE(sessionid)\n"
");\n"
" \n"
"-- groups table\n"
,
"CREATE TABLE groups (\n"
"  id bigserial PRIMARY KEY,\n"
"  groupid text NOT NULL, -- excludes domain part.\n"
"  domain text NOT NULL DEFAULT '',\n"
"  creator bigint REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE, -- NULL if system group\n"
"   \n"
"   cdate timestamp NOT NULL DEFAULT current_timestamp, -- date of creation\n"
"   welcome_note bytea,\n"
"   welcome_note_ctype text NOT NULL DEFAULT 'text/plain',	\n"
"  -- more fields to come\n"
"  \n"
"  \n"
" UNIQUE(groupid, domain)\n"
");\n"
,
"CREATE TABLE group_properties (\n"
"	id bigserial PRIMARY KEY,\n"
"	groupid bigint NOT NULL REFERENCES groups ON DELETE CASCADE ON UPDATE CASCADE,\n"
"        \n"
"	item text NOT NULL,\n"
"	value text NOT NULL,\n"
"	UNIQUE(groupid,item)\n"
");\n"
,
"CREATE VIEW groups_view AS \n"
"SELECT 'wv:'|| (case when domain = '' then groupid else groupid || '@' || domain end) as group_id, \n"
"*,\n"
"  (SELECT value FROM group_properties gp WHERE gp.groupid = g.id AND  item='Name') as group_name, \n"
"  (SELECT value FROM group_properties gp WHERE gp.groupid = g.id AND  item='Topic') as topic\n"
" from groups g;\n"
"-- List of members, joined,  autojoin users. \n"
,
"CREATE TABLE group_members (\n"
"   id bigserial PRIMARY KEY,\n"
"  groupid bigint NOT NULL REFERENCES groups ON UPDATE CASCADE ON DELETE RESTRICT,\n"
"  -- info (either one of userid or foreign_userid is set)\n"
"  local_userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,\n"
"  foreign_userid text CHECK (foreign_userid IS NOT NULL OR local_userid IS NOT NULL),\n"
" \n"
"   member_type varchar(6) NOT NULL DEFAULT 'User' CHECK (member_type IN ('User', 'Mod', 'Admin')),\n"
"  screen_name text, -- screen name of user in list.\n"
"  clientid text,\n"
"  \n"
"  isjoined boolean NOT NULL DEFAULT false,  -- true if user is currently joined (see auto-join above)\n"
"  ismember boolean NOT NULL DEFAULT false, -- true if a member\n"
"  subscribe_notify boolean NOT NULL DEFAULT false, -- if user subscribes to notification\n"
"  sessionid bigint REFERENCES sessions ON UPDATE CASCADE ON DELETE SET NULL,\n"
"   -- more fields to come\n"
"   \n"
"  UNIQUE(groupid, local_userid,clientid),\n"
"  UNIQUE(groupid,foreign_userid,clientid),\n"
"  UNIQUE(groupid,screen_name)\n"
");\n"
,
"CREATE SEQUENCE screen_name_sequence; -- for screen names\n"
,
"CREATE TABLE group_member_properties (\n"
"	id bigserial PRIMARY KEY,\n"
"	jid bigint NOT NULL REFERENCES group_members ON DELETE CASCADE ON UPDATE CASCADE,\n"
"        \n"
"	item text NOT NULL,\n"
"	value text NOT NULL,\n"
"	UNIQUE(jid,item)\n"
");\n"
,
"CREATE TABLE group_reject_list (\n"
"	id bigserial PRIMARY KEY,\n"
"	groupid bigint NOT NULL REFERENCES groups ON UPDATE CASCADE ON DELETE RESTRICT,\n"
"  -- member info (either one of userid or foreign_userid is set)\n"
"       local_userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,\n"
"       foreign_userid text CHECK (foreign_userid IS NOT NULL OR local_userid IS NOT NULL),\n"
"	\n"
"    UNIQUE(groupid, local_userid),\n"
"    UNIQUE(groupid,foreign_userid)\n"
"     	\n"
");\n"
,
"CREATE VIEW group_members_view AS \n"
"	SELECT g.*, gm.local_userid,gm.foreign_userid, \n"
"	(CASE WHEN local_userid IS NOT NULL THEN (select full_userid FROM users_view WHERE gm.local_userid = users_view.id) ELSE foreign_userid END) AS full_userid , \n"
"	gm.member_type, gm.screen_name,gm.clientid, gm.ismember, gm.id AS gmid,\n"
"	(SELECT value FROM group_member_properties WHERE jid = gm.id AND item='AutoJoin') as auto_join, \n"
"	gm.groupid AS group_id,gm.isjoined,gm.subscribe_notify FROM\n"
"   	groups g, group_members gm WHERE g.id = gm.groupid;\n"
,
"CREATE VIEW group_reject_list_view AS \n"
"  SELECT g.*, (CASE WHEN local_userid IS NOT NULL THEN \n"
"	(select full_userid FROM users_view WHERE gm.local_userid = users_view.id) ELSE foreign_userid END) AS full_userid, gm.groupid AS group_id, gm.id AS rid \n"
"	FROM group_reject_list gm, groups g WHERE gm.groupid = g.id; \n"
,
"CREATE TABLE group_session_limits (\n"
"  id bigserial PRIMARY KEY,\n"
"  \n"
"  sessid bigint REFERENCES sessions ON DELETE CASCADE ON UPDATE CASCADE,\n"
"  groupid TEXT NOT NULL,\n"
"  push_len int NOT NULL DEFAULT 100000,\n"
"  pull_len int NOT NULL DEFAULT 100000,\n"
"  deliver_method varchar(1) NOT NULL DEFAULT 'P',\n"
"  UNIQUE(sessid,groupid)\n"
");\n"
"  	\n"
,
"CREATE VIEW session_users AS \n"
"	SELECT sessions.*,users_view.full_userid,nickname FROM sessions,users_view WHERE sessions.userid = users_view.id;\n"
,
"CREATE TABLE session_content_types (\n"
"  id bigserial PRIMARY KEY,\n"
"  \n"
"  sessionid bigint REFERENCES sessions ON DELETE CASCADE ON UPDATE CASCADE,\n"
"  ctype text NOT NULL,\n"
"  max_len int NOT NULL DEFAULT 100000,\n"
"  cpolicy varchar(1) NOT NULL DEFAULT 'N',\n"
"  cpolicy_limit int NOT NULL DEFAULT 100000  \n"
");\n"
,
"CREATE TABLE session_charsets (\n"
"  id bigserial PRIMARY KEY,\n"
"  \n"
"  sessionid bigint REFERENCES sessions ON DELETE CASCADE ON UPDATE CASCADE,\n"
"  charset int NOT NULL\n"
");\n"
"-- list of presence subscribers for a user\n"
,
"CREATE TABLE presence_watchlists (\n"
" id bigserial PRIMARY KEY,\n"
" sessid bigint REFERENCES sessions ON DELETE CASCADE ON UPDATE CASCADE, -- link to the watcher session\n"
" userid bigint NOT NULL REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE, -- link to watched user\n"
" \n"
" foreign_userid text CHECK (foreign_userid IS NOT NULL OR sessid IS NOT NULL), -- set it if this is foreign watcher. \n"
" foreign_clientid text ,\n"
" \n"
" attribs_requested int NOT NULL DEFAULT 0, -- attributes requested\n"
" UNIQUE(userid,sessid),\n"
" UNIQUE(userid,foreign_userid,foreign_clientid)\n"
");\n"
,
"CREATE VIEW pr_watchlist_user_view AS \n"
" SELECT presence_watchlists.*, full_userid as local_userid,nickname\n"
"  FROM presence_watchlists LEFT JOIN session_users ON\n"
"  presence_watchlists.sessid = session_users.id;\n"
,
"CREATE VIEW pr_watchlist_userid_view AS \n"
"       SELECT p.*, s.userid AS local_userid, s.clientid FROM presence_watchlists p LEFT JOIN sessions s ON\n"
"       p.sessid = s.id;\n"
"-- table of users who have been authorised to see our presence. \n"
,
"CREATE TABLE presence_user_authorisations (\n"
"   id bigserial PRIMARY KEY,\n"
"   userid bigint NOT NULL REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE, -- link to user who has authorised\n"
" \n"
"   -- authorised user info (either one of userid or foreign_userid is set)\n"
"  local_userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,\n"
"  foreign_userid text CHECK (foreign_userid IS NOT NULL OR local_userid IS NOT NULL),\n"
"  attribs_authorised int NOT NULL DEFAULT 0, -- attributes authorised (bit field). Ensure it is zero when status is not GRANTED!\n"
"  user_notify boolean NOT NULL DEFAULT false, -- set to true until GRANTED or DENIED.\n"
"  react boolean NOT NULL DEFAULT false,\n"
"  status varchar(8) NOT NULL DEFAULT 'GRANTED' CHECK (status IN ('GRANTED', 'DENIED', 'PENDING')),\n"
"  UNIQUE(userid, local_userid),\n"
"  UNIQUE(userid, foreign_userid)\n"
"); \n"
,
"CREATE VIEW pr_users_view  AS  \n"
"	SELECT presence_user_authorisations.*, (CASE WHEN local_userid IS NOT NULL THEN \n"
"	(SELECT full_userid FROM users_view WHERE id = local_userid) ELSE NULL END) AS localuserid \n"
"	FROM presence_user_authorisations;\n"
"	\n"
,
"CREATE TABLE searches (\n"
"   id bigserial PRIMARY KEY,\n"
"   session bigint NOT NULL REFERENCES  sessions ON DELETE CASCADE ON UPDATE CASCADE,\n"
"   stype varchar(1) NOT NULL CHECK (stype IN ('G','U')), -- type of search -- Group or Users\n"
"   slimit int NOT NULL DEFAULT 5, -- limit on number of results to return each time.\n"
"   start_results_id bigint, -- an optimisation: start index of results in table below.\n"
"   result_count int NOT NULL DEFAULT 0\n"
");\n"
,
"CREATE TABLE search_results (\n"
"   id bigserial PRIMARY KEY,\n"
"   \n"
"   sid bigint REFERENCES searches ON DELETE CASCADE ON UPDATE CASCADE,\n"
"   v1 text,\n"
"   V2 text\n"
");\n"
,
"CREATE SEQUENCE message_sequence;\n"
"-- tables for queue management\n"
"-- locally destined messages: \n"
,
"CREATE TABLE csp_message_queue (\n"
"  id bigserial PRIMARY KEY,\n"
" \n"
"  tdate timestamp NOT NULL DEFAULT current_timestamp, -- date of entry\n"
" \n"
"  edate timestamp NOT NULL DEFAULT (current_timestamp + interval '1 week'), -- expiry date\n"
"  msgid text, -- the textual message id  -- can be null\n"
"  sender text NOT NULL, -- sender of IM (formatted in readable manner)\n"
"  msg_type text NOT NULL, -- taken from packet itself. \n"
"  msg_data bytea NOT NULL,   -- message data.\n"
"   delivery_report boolean NOT NULL DEFAULT FALSE,\n"
"   internal_rcpt_struct_path text, -- path to the Recepient struct within struct\n"
"   csp_ver int NOT NULL DEFAULT 17,\n"
"  UNIQUE(msgid) -- message id must be unique\n"
");\n"
,
"CREATE TABLE csp_message_recipients (\n"
"   id bigserial PRIMARY KEY, -- also used for generating transact ID when delivering message locally\n"
"   messageid bigint NOT NULL REFERENCES csp_message_queue ON UPDATE CASCADE ON DELETE CASCADE,\n"
"  \n"
"   userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,\n"
"   clientid text, -- if sent to specific client (and application)\n"
"   screen_name text, -- if the user was addressed using a screen name, this is it (s:sname,g:groupname)\n"
"    gsender text, -- sender of IM (formatted in readable manner) if a group\n"
"   msg_status varchar(1)  NOT NULL DEFAULT 'N', -- 'N' == new, 'R' == rejected, 'F' == fetched\n"
"   num_fetches int NOT NULL DEFAULT 0, -- number of times fetched.\n"
"   next_fetch timestamp NOT NULL DEFAULT '-infinity'\n"
");\n"
,
"CREATE VIEW csp_message_recipients_view AS \n"
"  SELECT q.*, r.id as rid, r.userid, r.screen_name, r.clientid, r.msg_status, r.num_fetches, r.next_fetch,\n"
"	(SELECT full_userid FROM users_view WHERE id = r.userid) AS full_userid FROM \n"
"  csp_message_queue q, csp_message_recipients r WHERE r.messageid = q.id;\n"
"-- externally destined messages\n"
,
"CREATE TABLE ssp_message_queue (\n"
"   id bigserial PRIMARY KEY, -- will also be used for transaction ID on outgoing SSP transactions, unless incoming_transid is set.\n"
"  tdate timestamp NOT NULL DEFAULT current_timestamp, -- date of entry\n"
" \n"
"  edate timestamp NOT NULL DEFAULT (current_timestamp + interval '24 hours'), -- expiry date\n"
"  \n"
"   -- message ID must not be unique and can be NULL\n"
"  msgid text, -- the textual message id  \n"
"  sender text NOT NULL, -- sender of IM (formatted in readable manner)\n"
"  domain text NOT NULL, -- domain to which to send message\n"
"  msg_type text NOT NULL, -- taken from packet itself. \n"
"  msg_data bytea NOT NULL,   -- message data. (recipients are within struct, presumably!)\n"
"  lastt timestamp NOT NULL default '-infinity', -- last send attempt,\n"
"  nextt timestamp NOT NULL default current_timestamp, -- when is next send attempt\n"
"  num_tries int NOT NULL DEFAULT 0, -- number of attempts to send.\n"
" \n"
"  sent boolean NOT NULL DEFAULT false, -- this is true if message was sent successfully (and we're waiting for response)\n"
" -- info about the real sender.\n"
"  userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,\n"
"  clientid text,\n"
"  csp_ver int NOT NULL DEFAULT 17 -- Default version set to 1.1\n"
");\n"
"-- to be used when recipients are not within the structure above\n"
,
"CREATE TABLE ssp_message_recipients (\n"
"	id bigserial PRIMARY KEY,\n"
"  	messageid BIGINT NOT NULL REFERENCES ssp_message_queue ON DELETE CASCADE ON UPDATE CASCADE,\n"
"	foreign_userid text NOT NULL,\n"
"	clientid text,\n"
"	gsender text -- sender of IM (formatted in readable manner) if a group\n"
");\n"
"-- ssp sessions \n"
,
"CREATE TABLE ssp_sessions (\n"
"       id bigserial PRIMARY KEY,\n"
"       ssp_domain text NOT NULL, -- the domain we're speaking for\n"
"       ssp_domain_url text,  -- the actual URL of ghandler in the domain (relay, etc)\n"
"       outgoing boolean NOT NULL DEFAULT false, -- is this an incoming or outgoing connection?\n"
"       a_secret text , -- our secret (if any, base64 coded)\n"
"       b_secret text, -- their secret\n"
"       sdate timestamp NOT NULL DEFAULT current_timestamp, -- time of first contact\n"
"       ldate timestamp NOT NULL DEFAULT '-infinity', -- when last active (only set once logon is complete.)\n"
"       edate timestamp NOT NULL DEFAULT (current_timestamp + interval '24 hours'), -- expiry date\n"
"       -- The session ID pair.\n"
"       a_sessionid text, -- requestor side session ID (NULL until we have setup the connection)\n"
"       b_sessionid text, -- response side's session ID (NULL until we have setup the connection)\n"
"       b_transid text,\n"
"       pw_check_ok boolean  NOT NULL DEFAULT false,\n"
"       mydomain text NOT NULL,\n"
"       UNIQUE(ssp_domain, a_sessionid)\n"
");\n"
"-- table for archive messages \n"
,
"CREATE TABLE message_archive (\n"
"  id bigserial PRIMARY KEY,\n"
"  userid text NOT NULL, -- the user to whom/from whom message sent/received\n"
"  msg_direction varchar(5)  NOT NULL CHECK (msg_direction IN ('RECVD', 'SENT')),\n"
" \n"
"  msg_type varchar(32) NOT NULL, -- type of message\n"
"  tdate timestamp NOT NULL DEFAULT current_timestamp,\n"
"  msg_data bytea NOT NULL\n"
" \n"
" );\n"
"-- table listing all local domains (i.e. ones for which we handle IM)\n"
,
"CREATE TABLE localdomains (\n"
"  id bigserial PRIMARY KEY,\n"
"  cdate timestamp NOT NULL DEFAULT current_timestamp,\n"
" \n"
"  domain text NOT NULL,\n"
" \n"
" -- comma-separated list of message types to archive from/to this domain\n"
"  archive_sent text NOT NULL DEFAULT '',\n"
"  archive_recvd text NOT NULL DEFAULT '',\n"
"  UNIQUE(domain)\n"
");\n"
"-- table listing the settings for the domain\n"
,
"CREATE TABLE settings (\n"
"  id serial,\n"
"  \n"
"  item varchar(32),\n"
"  value text,\n"
" \n"
"  UNIQUE(item)\n"
");\n"
,
"CREATE TABLE contactlists (\n"
"  id bigserial PRIMARY KEY,\n"
"  cid text NOT NULL, -- exclused domain part\n"
" \n"
"  domain text NOT NULL,\n"
"  userid bigint REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE, -- NULL if system list\n"
"  isdefault boolean NOT NULL DEFAULT false,\n"
"  descr text NOT NULL DEFAULT '',\n"
"  friendly_name text NOT NULL DEFAULT '',\n"
"  presence_attribs_authorised int, -- authorised presence attributes (if any)\n"
"  contact_list_notify boolean NOT NULL DEFAULT false,\n"
"  presence_attribs_auto_subscribe int, -- auto-subscribed presence attributes\n"
" UNIQUE(userid,cid,domain)\n"
");\n"
,
"CREATE VIEW contactlists_VIEW AS \n"
"	SELECT *, 'wv:'||(case when domain = '' then cid else cid || '@' || domain end) AS contactlistid FROM contactlists;\n"
,
"CREATE TABLE contactlist_members (\n"
" id bigserial PRIMARY KEY,\n"
" cid bigint NOT NULL REFERENCES contactlists ON UPDATE CASCADE ON DELETE CASCADE,\n"
"  -- member info (either one of userid or foreign_userid is set)\n"
"  local_userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,\n"
"  foreign_userid text CHECK (foreign_userid IS NOT NULL OR local_userid IS NOT NULL),\n"
" \n"
"  cname text NOT NULL, -- name of user in list.\n"
"   -- more fields to come\n"
"   \n"
"  UNIQUE(cid, local_userid),\n"
"  UNIQUE(cid,foreign_userid)\n"
");\n"
"create view contactlist_members_view AS \n"
"	SELECT *,(select 'wv:'||userid||'@'||domain FROM users WHERE users.id = local_userid LIMIT 1) as localuserid FROM contactlist_members;\n"
"-- access lists: GRANT/BLOCK\n"
,
"CREATE TABLE access_lists (\n"
"	id bigserial NOT NULL PRIMARY KEY,\n"
"	\n"
"-- owner of the access list\n"
"	owner bigint NOT NULL REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,\n"
"--  allow = true means on GRANT list, else on BLOCK list\n"
" 	allow boolean NOT NULL DEFAULT FALSE,\n"
"-- references to the users, screen names or groups that are granted or blocked\n"
"	local_userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,\n"
"	foreign_userid text,\n"
"	screen_name text,\n"
"	\n"
"	group_id text,\n"
"	application_id text\n"
");\n"
,
"CREATE VIEW access_lists_view AS \n"
"  SELECT *, (CASE WHEN local_userid IS NOT NULL THEN \n"
"	(select full_userid FROM users_view WHERE local_userid = id) ELSE foreign_userid END) AS full_userid \n"
"	FROM access_lists; \n"
"-- shared content table\n"
,
"CREATE TABLE shared_content (\n"
"   id bigserial PRIMARY KEY,\n"
"   \n"
"   cdate timestamp NOT NULL DEFAULT current_timestamp,\n"
"   edate timestamp NOT NULL DEFAULT (current_timestamp + interval '7 days'), -- expiry date\n"
"   content_type text NOT NULL,   \n"
"   content bytea NOT NULL,\n"
"   content_encoding text,\n"
"   content_key text, -- some key for identifying content\n"
"   content_keyword text -- a keyword, for more permanent content\n"
"); \n"
"-- create a user entry\n"
,
"CREATE  OR REPLACE FUNCTION new_user_md5(u text, d text, xnonce text, xpass text, areg boolean) RETURNS bigint AS $$\n"
"	DECLARE\n"
"		uid bigint;\n"
"		x text;\n"
"		cp text;\n"
"		y text;\n"
"	BEGIN\n"
"	x := xpass;\n"
"	SELECT (random()::text || current_timestamp::text) INTO y;\n"
"	SELECT md5(x||y) INTO cp;\n"
"	uid := -1;\n"
"	INSERT into users (userid,domain,nonce,crypt_md5_pass, rand_salt,auto_reg) VALUES \n"
"	(u,d, xnonce, cp, y, areg) RETURNING id INTO uid; \n"
"	RETURN uid;\n"
" 	END;\n"
"$$ LANGUAGE plpgsql;\n"
"-- create new user with nonce -- simply calls the other one.\n"
,
"CREATE  OR REPLACE FUNCTION new_user_with_nonce(u text, p text, d text, xnonce text, areg boolean) RETURNS bigint AS $$\n"
"	DECLARE\n"
"		x text;\n"
"	BEGIN\n"
"	x := xnonce || p;\n"
"	SELECT md5(x) INTO x;\n"
"	RETURN new_user_md5(u,d,xnonce,x,areg);\n"
" 	END;\n"
"$$ LANGUAGE plpgsql;\n"
,
"CREATE  OR REPLACE FUNCTION new_user(u text, p text, d text, areg boolean) RETURNS bigint AS $$\n"
"	DECLARE\n"
"		xnonce text;\n"
"	BEGIN\n"
"	-- Make the nonce\n"
"	SELECT md5(current_timestamp::text) INTO xnonce;\n"
"	RETURN new_user_with_nonce(u, p, d, xnonce, areg);\n"
" 	END;\n"
"$$ LANGUAGE plpgsql;\n"
"-- verify a password\n"
,
"CREATE OR REPLACE FUNCTION verify_plain_pass(u text, d text, p text) RETURNS boolean AS $$\n"
"	DECLARE\n"
"	  t boolean;\n"
"	BEGIN\n"
"		SELECT crypt_md5_pass = md5(md5(nonce||p)|| rand_salt) INTO t FROM users WHERE userid = u AND domain = d AND bot_url IS NULL; -- must NOT be a Bot\n"
"		IF NOT FOUND THEN\n"
"		  RETURN false;\n"
"		END IF;\n"
"		RETURN t;	\n"
"	END;\n"
"$$ LANGUAGE plpgsql;\n"
,
"CREATE OR REPLACE FUNCTION verify_md5_pass(u text, d text, p text) RETURNS boolean AS $$\n"
"	DECLARE\n"
"	  t boolean;\n"
"	BEGIN\n"
"		SELECT crypt_md5_pass = md5(p|| rand_salt) INTO t FROM users WHERE userid = u AND domain = d AND bot_url IS NULL;\n"
"		IF NOT FOUND THEN\n"
"		  RETURN false;\n"
"		END IF;\n"
"		RETURN t;	\n"
"	END;\n"
"$$ LANGUAGE plpgsql;\n"
"-- type for the functions below to return\n"
,
"CREATE TYPE user_auth_data as (\n"
"	  attribs int, \n"
"          auth_type varchar(16),\n"
"	  notify boolean,\n"
"	  status varchar(8));\n"
,
"CREATE OR REPLACE FUNCTION get_local_user_auth(watched bigint, watcher bigint) RETURNS SETOF user_auth_data AS $$\n"
"    DECLARE\n"
"	r user_auth_data%rowtype;\n"
"	attribs int;\n"
"	atype varchar(16);\n"
"        notify boolean;\n"
"	n int;\n"
"    BEGIN\n"
"	-- first try the user.\n"
"	SELECT attribs_authorised, 'User', user_notify,status INTO r FROM \n"
"	presence_user_authorisations  WHERE userid = watched AND local_userid = watcher;\n"
"	IF FOUND THEN\n"
"	  RETURN NEXT r;\n"
"	  RETURN;\n"
"  	END IF;	\n"
"	-- then try the contact lists\n"
"	\n"
"	SELECT bit_or(presence_attribs_authorised), bool_or(contact_list_notify), count(*) \n"
"	INTO attribs, notify, n FROM contactlists WHERE\n"
"	userid = watched AND presence_attribs_authorised IS NOT NULL AND \n"
"	EXISTS (SELECT id FROM contactlist_members WHERE \n"
"	cid = contactlists.id AND local_userid = watcher);\n"
"	IF FOUND AND n > 0 THEN\n"
"		r.attribs := attribs;\n"
"		r.notify := notify;\n"
"		r.auth_type := 'ContactList';\n"
"		r.status := 'GRANTED';\n"
"		RETURN NEXT r;\n"
"		RETURN;\n"
"	END IF;\n"
"	-- then try the default.	\n"
"	SELECT default_attr_list, 'Default', default_notify,'GRANTED' as status INTO r FROM \n"
"	users  WHERE id = watched AND default_attr_list IS NOT NULL;\n"
"	\n"
"	IF FOUND THEN	        \n"
"		RETURN NEXT r;\n"
"		RETURN;\n"
"	END IF;	\n"
"	-- otherwise return nothing.\n"
"	RETURN;\n"
"   END;\n"
"$$ LANGUAGE plpgsql;\n"
,
"CREATE OR REPLACE FUNCTION get_foreign_user_auth(watched bigint, watcher text) RETURNS SETOF user_auth_data AS $$\n"
"    DECLARE\n"
"	r user_auth_data%rowtype;\n"
"	attribs int;\n"
"	atype varchar(16);\n"
"        notify boolean;\n"
"	n int;\n"
"    BEGIN\n"
"	-- first try the user.\n"
"	SELECT attribs_authorised, 'User', user_notify,status INTO r FROM \n"
"	presence_user_authorisations  WHERE userid = watched AND foreign_userid = watcher;\n"
"	IF FOUND THEN\n"
"	  RETURN NEXT r;\n"
"	  RETURN;\n"
"  	END IF;	\n"
"	-- then try the contact lists\n"
"	\n"
"	SELECT bit_or(presence_attribs_authorised), bool_or(contact_list_notify), count(*) \n"
"	INTO attribs, notify, n FROM contactlists WHERE\n"
"	userid = watched AND presence_attribs_authorised IS NOT NULL AND \n"
"	EXISTS (SELECT foreign_userid FROM contactlist_members WHERE \n"
"	cid = contactlists.id AND foreign_userid = watcher);\n"
"	IF FOUND AND n > 0 THEN\n"
"		r.attribs := attribs;\n"
"		r.notify := notify;\n"
"		r.auth_type := 'ContactList';\n"
"		r.status := 'GRANTED';\n"
"		RETURN NEXT r;\n"
"		RETURN;\n"
"	END IF;\n"
"	-- then try the default.	\n"
"	SELECT default_attr_list, 'Default', default_notify,'GRANTED' as status INTO r FROM \n"
"	users  WHERE id = watched AND default_attr_list IS NOT NULL;\n"
"	\n"
"	IF FOUND THEN\n"
"		RETURN NEXT r;\n"
"		RETURN;\n"
"	END IF;	\n"
"	-- otherwise return nothing.\n"
"	RETURN;\n"
"   END;\n"
"$$ LANGUAGE plpgsql;\n"
,NULL

};
