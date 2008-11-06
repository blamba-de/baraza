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
#ifndef __SSP_INCLUDED__
#define __SSP_INCLUDED__
#include "utils.h"
#include "conf.h"

#define SSP_ERROR_FATAL     -1
#define SSP_ERROR_TRANSIENT -2
#define SSP_OK               200
#define SSP_PARTIAL_SUCCESS  201
typedef struct SSPRecipient_t {
     int64_t id;   /* id in the db of this recipient for reference. */
     int sent;     /* set to true if message has been sent out to this recipient (provisionally). */
     void *to;     /* a User_t or UserID_t struct. */
} SSPRecipient_t;

typedef struct s2sHandler_t {
     const char *name;
     int (*init)(struct imps_conf_t *conf); /* init function. */
     /* List is of type SSPRecipient_t */
     int (*msg_send)(PGconn *c, EmptyObject_t msg, List *rcptlist,  Sender_t sender, 
		     char *domain, int64_t tid); /* Returns: SSP_OK on send, SSP_PARTIAL on partial send, 
						  * SSP_ERROR_TRANSIENT on recovery error (i.e. try again)
						  * SSP_ERROR_FATAL when it doesn't know what to do. 
						  */
     void (*shutdown)(void);
} s2sHandler_t;
#define MAX_S2S_HANDLERS 10

/* Tell the SSP Daemon there is a new message that needs to go out. 
 * argument is the ID of the message in the DB
 */
void notify_sspd(Octstr *newmsg_tid);

List *ssp_requests; /* SSP request lists. */
#endif
