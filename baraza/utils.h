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
#ifndef __IMPS_UTILS_INCLUDED__
#define __IMPS_UTILS_INCLUDED__
#include <unistd.h>
#define BIND_8_COMPAT
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <ctype.h>
#include <string.h>
#include <libpq-fe.h>

#include <gwlib/gwlib.h>
#include <gwlib/mime.h>
#include "cspmessages.h"
#include "baraza-config.h"

#define MAXLIST 10
#define MIN_ALLOC 15
/* Configs -- to move to a conf file XXX */
#define DEFAULT_MAX_CLEN 100*1024 /* default maximum content object size. */
#define DEFAULT_MAX_SEARCH_LIMIT 100
#define DEFAULT_EXPIRY 60*60*24
#define SHORT_EXPIRY   60 /* presence info should expire fast. */
#define DEFAULT_POLL_MIN MIN_TTL /* default poll minimum. */

#define DEFAULT_BUF_LEN 256

#define DEFAULT_WBXML_VERSION 0x03
#define DEFAULT_WBXML_PUBLICID ""
#define DEFAULT_WBXML_CHARSET 106
#define DEFAULT_CSP_VERSION CSP_VERSION(1,2)


#define SYSTEM_HOME_URL "http://www.baraza.im"
#define SYSTEM_NAME "Baraza IMPS -- " SYSTEM_HOME_URL
#define SYSTEM_DESCR "Baraza is a \"Wireless Village\" Mobile Instant Messaging and Presence Server"
#define SYSTEM_SHORT_HOME "baraza.im"

#define SC_URI "/sc"
#define CIR_URI "/cir"
#define SSP_CONTENT_TYPE "application/vnd.wv.ssp+xml"
#define CIR_CONTENT_TYPE "application/vnd.wv.csp.cir"
#define WAP_CIR_CONTENT_TYPE 0x46

#define WAP_PUSH_PORT "0B84"
#define WAP_PUSH_PORT_DEC 0x0B84
#define SUDP_PORT  56732
#define CIR_APP_ID 0x0A
#define HAS_WAPUDP 1
#define HAS_WAPSMS 2
#define HAS_STCP   4
#define HAS_SUDP   8
#define HAS_SHTTP  16

/* useful XML macros. */
#define NMATCH(node,str) ((node) && (node)->type == XML_ELEMENT_NODE &&	\
			  strcasecmp((void *)(node)->name, (str)) == 0)
#define NATTR(node,name) (void *)xmlGetProp(node, (void *)(name))

#define myroundup(e,n) ((((e)+(n)-1)/(n))*(n))

typedef struct RequestInfo_t {
     int64_t uid;    /* the user who's session it is. (CSP only.) */
     int64_t sessid; /* the sessid ID in the DB. (CSP only) */
     char    xsessid[128];  /* the original text session ID as given. */     

     Octstr  *req_ip; /* IP address from which request received. */
     Octstr  *client_ip;  /* client request IP */
     Octstr  *msisdn;     /* Client MSISDN */

     Octstr  *clientid;  /* clientID string (incl. applicationid) */
     Octstr  *transid;  /* client (or server) provided transid. */
     Octstr  *userid;   /* the userid who is initiating this */
     Octstr  *cookie;   /* the logon cookie. */
     long     ttl;          /* session Time-to-live. */
     u_int8_t cir;           /* whether we have CIR. */
     u_int8_t is_ssp;       /* 1 if this is from SSP side, else 0. */
     u_int8_t binary;     /* whether binary CSP packet was sent or not. */
     u_int8_t ver;        /* CSP version */
     struct {
	  unsigned long push_len;
	  unsigned long pull_len;
	  enum {NotifyGet_DMethod, Push_DMethod} deliver_method;	  
	  u_int8_t react;      /* whether reactive authorisation is requested in this session. */
     } sinfo;
     struct imps_conf_t *conf; /* link to the conf data. */
     PGconn *c;
} RequestInfo_t;

typedef void *(*request_func_t)(RequestInfo_t *req, void *obj);
extern const request_func_t req_funcs[]; /* functions for requests. */

#define CSP_SUCCESS(code) ((code)/100 == 2)
#define CSP_INFO(code) ((code)/100 == 1)

#define NELEMS(a) (sizeof(a)/sizeof((a)[0]))
List *gwlist_create_ex_real(const char *file, const char *func, int line,...);

#define gwlist_create_ex(...) gwlist_create_ex_real(__FILE__,__FUNCTION__,__LINE__, __VA_ARGS__, NULL)

#define find_node(node, name, maxlevel) find_node_ex((node), (name), 0, (maxlevel))
#define find_nodebytype(node, typ, maxlevel) find_nodebytype_ex((node), (typ), 0, (maxlevel))
#define find_dtd_node(node, maxlevel) find_dtd_node_ex((node), 0, (maxlevel))

xmlNodePtr find_node_ex(xmlNodePtr start, char *name, int level, int maxlevel);
xmlNodePtr find_nodebytype_ex(xmlNodePtr start, int type, int level, int maxlevel);
xmlDtdPtr find_dtd_node_ex(xmlNodePtr start, int level, int maxlevel);
void open_logs(char *access_log, char *debug_log, int loglevel);

/* count the number of one bits. */
extern int bit_count(unsigned long x);

void extract_id_and_domain(char *id, char xid[], char xdomain[]);

Octstr *make_clientid(ClientID_t clnt, ApplicationID_t appid);
int parse_clientid(Octstr *s, ClientID_t *clnt, ApplicationID_t *appid);
/* compares clientID. */
int compare_clientid(Octstr *clientid_x, ClientID_t clientid_y); 

/* linearize and de-linearize sender string. */
Octstr *make_sender_str(Sender_t sender);
Sender_t parse_sender_str(char *in);


/* format a screen name into a string, parse it: Group must come first since it can't have spaces */
#define format_screen_name_ex(groupid, sname) octstr_format("g:%.64s s:%.64s", (char *)(groupid), (sname)? (char *)(sname) : "")
#define format_screen_name(sname) format_screen_name_id_ex((sname)->gid->str, (sname)->sname->str)

ScreenName_t parse_screen_name(char *in);

Octstr *csp_msg_to_str(void *msg, int type); /* make a string from a message. */
void *csp_msg_from_str(Octstr *in, int type); /* make a message from a string, given the type. */
void _csp_msg_free(void *msg); /* free func -- for when we need a func pointer. */


/* make a sender from a uid and a group. */
Sender_t make_sender_struct(PGconn *c, int64_t uid, Octstr *clientid, char *sname, char *gid);

/* make sender struct without need for connection. */
Sender_t make_sender_struct2(Octstr *userid,  Octstr *clientid, char *sname, char *grpname);

/* Pick up the request info and fill in the structure. */
int get_session_id(PGconn *c, char *sessid, RequestInfo_t *req);

/* Get session info given an ID. */
int get_session_info(PGconn *c, int64_t sid, RequestInfo_t *req);

void set_has_cir(PGconn *c, int64_t sid, int has_cir);
/* returns true if this session has pending messages. */
int has_pending_msgs_ex(PGconn *c, int64_t uid, Octstr *clientid,
			unsigned long min_ttl, 
			unsigned long max_ttl, int64_t sessid, int has_cir);

#define has_pending_msgs(c, u, cid, min_ttl,max_ttl) has_pending_msgs_ex((c), (u), (cid), (min_ttl), (max_ttl), -1, 0)

void update_session_notify(PGconn *c, int64_t sessid, int default_notify);
enum DBObjectTypes_t {DBObj_User, DBObj_Group, DBObj_ContactList};
int get_islocal_domain(PGconn *c, char *domain);
int64_t get_object_id(PGconn *c, enum DBObjectTypes_t type, 
		      char *id, char *domain, char *extra_cond, 
		      int *islocal_domain);
int get_object_name_and_domain(PGconn *c, enum DBObjectTypes_t type, int64_t id, 
			       char *extra_cond,
			       char xid[], char xdomain[]);
#define get_userid(c, _user, _domain, _islocal) get_object_id(c, DBObj_User, _user, _domain, NULL,_islocal)
#define get_contactlist(c, _clid, _domain, _uid_crit, _islocal) get_object_id(c, DBObj_ContactList, _clid, _domain, _uid_crit,_islocal)
#define get_groupid(c, _g, _domain, _islocal) get_object_id(c, DBObj_Group, _g, _domain, NULL,_islocal)

#define get_userid_and_domain(c,_id,xuserid,xdomain) get_object_name_and_domain(c,DBObj_User,_id,NULL,xuserid,xdomain)

/* Returns true if this user is a Bot. */
int is_bot(PGconn *c, u_int64_t uid, char url[], char name[]);

#define PQ_ESCAPE_STR(c,_str,_buf) do {char *_s = (_str); int _n = strlen(_s); PQescapeString((_buf),(_s),_n<sizeof _buf ? _n : sizeof _buf); } while (0)

#define PQ_ESCAPE_BSTR(c,_str,len,_buf) do {char *_s = (_str); int _n = (len); PQescapeString((_buf),(_s),_n<sizeof _buf ? _n : sizeof _buf); } while (0)


/* Same as above, but also lower case the string. */

#define PQ_ESCAPE_STR_LOWER(c,_str,_buf) do {				\
    char *_xs = (_str), *_xp = _xs;					\
    while (*_xp) {*_xp = tolower(*_xp); _xp++;}				\
    PQ_ESCAPE_STR((c), _xs, (_buf));					\
  } while (0)

#define PQ_ESCAPE_BSTR_LOWER(c,_str,len,_buf) do {			\
    char *_xs = (_str), *_xp = _xs;					\
    int _n = (len);							\
    while ((_xp - _xs) < _n && *_xp) {*_xp = tolower(*_xp); _xp++;}	\
    PQ_ESCAPE_BSTR((c), _xs, _n, (_buf));				\
  } while (0)

/* makes a temporary table for storing (u_int64_t) IDs. Has only one field called 'id'
 * table gets dropped at end of transaction
 */
int make_temp_ids_table(PGconn *c, char tblname[]);

/* Returns 1 if the Sender is allowed to send to the recipient */
int check_csp_grant(PGconn *c, Sender_t sender, int64_t sender_uid, int64_t receiver_id);
int check_ssp_grant(PGconn *c, Sender_t sender, int64_t receiver_id);

/* check that the sender is of the right domain. Returns 200 on success. */
int verify_ssp_sender(User_t sender, Octstr *b_domain);

void check_csp_grant_block_in_use(PGconn *c, int64_t uid, 
				  int *ginuse, int *binuse);

/* Make a recipient structure from a local userid */
Recipient_t make_local_rcpt_struct(PGconn *c, int64_t uid, Octstr *clientid);

#define _str2bool(x) ((x) && tolower((x)[0]) == 't')

Octstr *get_bytea_data(PGresult *r, int row, int col);

void *make_user_struct(char *screen_name, char *userid, char *clientid);

/* Check that a name is valid */
int isvalid_nameid(char *name);

/* base64 encode message data as needed, return it or NULL if no change. */
void make_msg_data(MessageInfo_t minfo, String_t *data, int binary);

/* Conditionally massage data: If the caller is using a plain text CSP format, 
 * and the message needs encoding (is not representable), base64 encode it, return 1
 * otherwise if the user is using a binary CSP format, and message is base64 encoded, 
 * un-encode it and return 1. 
 * returns 0 if no change was made to the message.
 */
int  do_conditional_msg_encoding(String_t *data, int binary, ContentEncoding_t *enc);


void free_req_info(RequestInfo_t *ri, int clear_struct);

/* for randomizing the CIR URL string */
Octstr *make_salt(RequestInfo_t *ri);
int check_salt(RequestInfo_t *ri, char *salt);

/* get named setting from the settings table. */
Octstr *get_setting(PGconn *c, char *setting);

/* Check for printable characters */
int _x_isprint(int ch);

/* add list 'n' to list 'l', destroy 'n' */
void mylist_combine(List *l, List *n);

/* fetch a URL, return the result code. */
int fetch_url(Octstr *url, int method, Octstr *body, List *request_headers, char *body_ctype, Octstr *certfile);

/* extract domain from sender struct */
Octstr *get_sender_domain(Sender_t sender);

/* General HTTP object for encapsulating request. Used variously. */
typedef struct HTTPRequest_t {
     Octstr *uri;
     Octstr *ip;
     HTTPClient *c;
     Octstr *body;
     List *rh;
     List *cgivars;
} HTTPRequest_t;

HTTPRequest_t *make_http_request_info(List *rh, Octstr *uri, 
				      Octstr *body, 
				      HTTPClient *client,
				      Octstr *ip,
				      List *cgivars);
void free_http_request_info(HTTPRequest_t *r);

/* Respond to an HTTP request with a simple Ack (200, 404, etc.; empty body) */
void send_http_ack(HTTPClient *c, int code); 


/* Get contents of node, strip as necessary. */
Octstr *_xmlNodeContent(xmlNodePtr node);

UserMapList_t convert_ulist_to_mapping(UserList_t ulist);
UserList_t convert_mapping_to_ulist(UserMapList_t umlist);
// void _gw_free(void *x);

/* returns type of first pending message, and also the msg (in msg). Returns NULL if no messages. */
void *get_pending_msg(RequestInfo_t *ri);

/* fetch content, possibly with authentication. */
int url_fetch_content(int method, Octstr *url, List *request_headers, 
		      Octstr *body, List **reply_headers, Octstr **reply_body);


int get_content_type(List *hdrs, Octstr **type, Octstr **params);


#define DEBUG_LOG_MSG(str, ip, url, descr) do {Octstr *_x = octstr_duplicate(str); \
                                   octstr_binary_to_hex(_x,1); \
                                   debug("cspd." descr, 0, "IP=[%s], URL=[%s], body=[%s]",octstr_get_cstr(ip), (url) ? octstr_get_cstr(url) : "N/A", \
                                   octstr_get_cstr(_x)); octstr_destroy(_x); } while (0)

#endif
