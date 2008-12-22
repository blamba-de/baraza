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

#ifndef __IMPS_MESSAGE_QUEUES_INCLUDED__
#define __IMPS_MESSAGE_QUEUES_INCLUDED__
/* message queue handlers. */

#include "cspmessages.h"
#include <sys/types.h>
#include "utils.h"
#include <libpq-fe.h>


/* Heavy lifting: Takes a Recipient, and:
 * - rips out the local recipients and returns them as a list of IDs
 * - returns a Dict containing Recipient_t thingies grouped by domain (Dict is indexed by domain)
 * - returns a list of DetailedResult_t structs for any errors found.
 * if 'sender' is non-negative, then we verify group membership and contact list ownership against the user
 */

struct QLocalUser_t {
     u_int64_t uid; /* userid */  
     char sname[DEFAULT_BUF_LEN];    /* screen name (as screen_name & group name) if any */
     char clientid[DEFAULT_BUF_LEN];  /* client ID (and appid) if any. */
};

/* convenience macro */
#define ALLOC_BSIZE 16
#define ADD_QLOCAL_USER(xuid, ulist, clid, xscreen_name) do {\
                  int _i, _found = 0; \
                    for (_i = 0; _i < nelems; _i++) \
                       if (ulist[_i].uid == (xuid)) { /* exists, go away. */ \
                            _found = 1; \
                            break; \
                       } \
                    if (_found) break; \
  		  if (nelems >= nalloc) { \
			 nalloc += ALLOC_BSIZE; \
			 ulist = gw_realloc(ulist, nalloc*sizeof ulist[0]); \
		    } \
		    ulist[nelems].uid = (xuid); \
		    strncpy(ulist[nelems].clientid, (clid), sizeof ulist[0].clientid); \
		    strncpy(ulist[nelems].sname, (xscreen_name), sizeof ulist[0].sname); \
		    nelems++; \
            } while (0)

struct QSender_t {
     enum {QNo_User, QLocal_User, QForeign_User} type;
     char clientid[DEFAULT_BUF_LEN];
     union {int64_t uid; char *fid;} u;
};

#define FILL_QSENDER(qsender, is_ssp, uid_val, userid_str, clientid_str) do { \
    if (!(is_ssp)) {							\
      (qsender).type = QLocal_User;					\
      (qsender).u.uid = (uid_val);					\
      strncpy((qsender).clientid, octstr_get_cstr(clientid_str), sizeof (qsender).clientid); \
    } else {								\
      (qsender).type = QForeign_User;					\
      (qsender).u.fid = octstr_get_cstr(userid_str);			\
      (qsender).clientid[0] = 0;					\
    }									\
} while (0)

Octstr *make_msg_id(PGconn *c);

Dict *queue_split_rcpt(PGconn *c, struct QSender_t sender, Recipient_t rcpt, int is_group_invite, 
		       struct QLocalUser_t **localids, 
		       int *localid_count, List **errorlist, Sender_t *fixed_sender, int is_ssp);

/* dest_userids is a list of UserID_t or User_t */
int64_t queue_foreign_msg_add(PGconn *c, void *msg, Sender_t sender, 
			      int64_t sender_uid, 
			      char *clientid,
			      Octstr *msgid, 
			      char *domain, List *dest_userids, 
			      int csp_ver,
			      time_t expiryt);
int64_t queue_local_msg_add(PGconn *c, void *msg, Sender_t sender, 
			    struct QLocalUser_t localids[], 
			    int num, 
			    int dlr,
			    Octstr *msgid, 
			    char *rcpt_struct_path,
			    time_t expiryt);

/* removes (i.e. shifts out) all local recipients who are blocked by the recipient. 
 * returns the new count of number of recipients. 
 */
int remove_disallowed_local_recipients(PGconn *c, Sender_t sender, 
				       int64_t sender_uid, 
				       struct QLocalUser_t localids[], int count, 
				       List *errlist);

/* utility function to split and send all in one go. */
Octstr *queue_msg(PGconn *c, Sender_t sender, int64_t sender_uid, Octstr *foreign_sender, 
		  char *clientid, Recipient_t to, 
		  void *msg, Recipient_t *rcpt_ptr,
		  int is_group_invite, int dlr, 
		  char *rcpt_struct_path, time_t expiryt, int is_ssp, int csp_ver,
		  List **errlist);

void queue_get_ssp_sender_info(PGconn *c, int64_t tid, int64_t *uid, Octstr **clientid, int *csp_ver, 
			       void **msg);
#endif
