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
/* Main SSP daemon. */
#include "utils.h"
#include "ssp.h"
#include "ssphandler.h"
#include "xmpphandler.h"
#include "pgconnpool.h"
#include "baraza.h"
#include "scserver.h"

#define MIN_QRUN_INTERVAL 15 /* since we have a notification procedure once message hits SSP queue, no need to run DB queue too often. */
#define SENDER_BACKOFF 10 


/* List of handlers, in order of preference. */
static struct {
     int inited;
     s2sHandler_t *handler;
} handlers[MAX_S2S_HANDLERS];

static void s2s_queue_runner(List *outgoing)
{
     Octstr *tid;
     
     while ((tid = gwlist_consume(outgoing)) != NULL) {
	  PGconn *c = pg_cp_get_conn();
	  int i, n, ret;
	  char cmd[512], *x, *xmtype;	  
	  PGresult *r = NULL;
	  int mtype;
	  long num_tries;
	  Octstr *msgdata = NULL;
	  void *msg = NULL;
	  Octstr  *domain = NULL;
	  List *rcptlist = NULL;
	  int64_t xtid;
	  Sender_t sender = NULL;
	  
	  if (c == NULL)
	       panic(0, "%s: failed to get database connection from pool", __FUNCTION__);
	  
	  xtid = strtoull(octstr_get_cstr(tid), NULL, 10);
          /* we need the NOWAIT so we can skip it if locked. */
	  sprintf(cmd, "SELECT msg_type, msg_data, sender, domain,num_tries "
		 " FROM ssp_message_queue WHERE id = %lld AND sent = false "
		  " AND nextt <= current_timestamp AND edate >= current_timestamp " /* it might have been processed. */
		  "FOR UPDATE "
		 " NOWAIT", xtid); 
	  r = PQexec(c, cmd);
	  
	  if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) <= 0) 
	       goto loop;
	  
	  xmtype = PQgetvalue(r, 0, 0);
	  mtype = csp_name_to_type(xmtype);
	  msgdata = get_bytea_data(r, 0, 1);
	  
	  sender = parse_sender_str(PQgetvalue(r, 0, 2));
	  domain = (x = PQgetvalue(r, 0, 3)) ? octstr_create(x) : NULL;
	  num_tries = strtoul(PQgetvalue(r, 0, 4), NULL, 10);

	  if ((msg = csp_msg_from_str(msgdata, mtype)) == NULL) {
	       PGresult *r;
	       error(0, "Failed to parse msg in ssp queue id [%s] of type [%s] for domain [%s]"
		     " Further delivery attempts disabled", octstr_get_cstr(tid), 
		     xmtype, octstr_get_cstr(domain));
	       
	       sprintf(cmd, "UPDATE  ssp_message_queue  SET nextt = 'infinity'::timestamp  WHERE id = %lld ", 
		       xtid);  
	       r = PQexec(c, cmd);
	       PQclear(r);	       
	       goto loop;
	  }
	  PQclear(r);

	  /* Get recipients. */
	  sprintf(cmd, "SELECT id, foreign_userid, clientid FROM "
		  " ssp_message_recipients WHERE messageid = %lld FOR UPDATE",
		  xtid);
	  r = PQexec(c, cmd);
	  
	  n = (PQresultStatus(r) == PGRES_TUPLES_OK) ? PQntuples(r) : 0;
	  rcptlist = gwlist_create();
	  for (i = 0; i<n; i++) {
	       char *u = PQgetvalue(r, i, 1);
	       char *clnt = PQgetvalue(r, i, 2);
	       struct SSPRecipient_t *sr = gw_malloc(sizeof *sr);
	       
	       sr->to = make_user_struct(NULL, u, clnt);
	       sr->sent = 0;
	       sr->id = strtoull(PQgetvalue(r, i, 0), NULL, 10);
	       
	       gwlist_append(rcptlist, sr);	       
	  }
	  /* we have a message, attempt to send through the first one that will accept. If sent, mark as sent.
	   * if not, just defer.
	   */

	  for (i = 0, cmd[0]=0; i < NELEMS(handlers) && handlers[i].handler; i++)
	       if (handlers[i].inited && 
		   (ret = handlers[i].handler->msg_send(c, msg, 
							rcptlist,sender,
							domain ? octstr_get_cstr(domain) : 
							NULL,
							xtid)) != SSP_ERROR_FATAL) {
		    SSPRecipient_t *sr;
		    int j, m = 0, k = 0;
		    /* delete all the ones which have been sent. */
		    if (ret == SSP_OK || ret == SSP_PARTIAL_SUCCESS)
			 for (j = 0, m = gwlist_len(rcptlist); j<m; j++) 
			      if ((sr = gwlist_get(rcptlist, j)) != NULL && 
				  sr->sent != 0) {			 			 
				   PGresult *r;
				   sprintf(cmd, "DELETE FROM ssp_message_recipients WHERE id = %lld", sr->id);
				   r = PQexec(c, cmd);
				   PQclear(r);
				   k++;
			      }
		    if (k == m && (ret == SSP_OK || ret == SSP_PARTIAL_SUCCESS))  /* message has been sent. mark as such. */
			 sprintf(cmd, "UPDATE ssp_message_queue SET lastt = current_timestamp, sent = true WHERE id = %lld", 
				 xtid);
		    /* else defer delivery. */
		    break;
	       }

	  if (!cmd[0]) {  /* No handlers, or all returned transient: just retry again until expiry. */
	       sprintf(cmd, "UPDATE ssp_message_queue SET num_tries = num_tries + 1, "
		       " nextt = current_timestamp + '%ld secs'::interval, lastt = current_timestamp "
		       " WHERE id = %lld", 
		       (num_tries + 1)*SENDER_BACKOFF, xtid);
	       info(0, "S2S: Delivery to domain [%s] failed. Will retry", domain ? octstr_get_cstr(domain) : "n/a");
	  }
	  PQclear(r);
	  r = PQexec(c, cmd); /* update and go away. */
	  
     loop:
	  if (r)
	       PQclear(r);
	  if (c) 
	       pg_cp_return_conn(c);
	  octstr_destroy(domain);
	  octstr_destroy(msgdata);
	  if (rcptlist) {
	       struct SSPRecipient_t *sr;
	       while ((sr = gwlist_extract_first(rcptlist)) != NULL) {
		    csp_msg_free(sr->to);
		    gw_free(sr);
	       }	       
	       gwlist_destroy(rcptlist, NULL);
	  }
	  csp_msg_free(sender);
	  csp_msg_free(msg);
	  octstr_destroy(tid);
     }
     
}

static int sstop = 0;
static List *outgoing; /* outgoing messages. */
static long sth;
static int num_threads;
static void sspd_queue_runner(void *unused)
{
     int i;
     /* Now start running the queue, never finish. */
     outgoing = gwlist_create();
     gwlist_add_producer(outgoing);
     
     for (i = 0; i < num_threads; i++)
	  gwthread_create((void *)s2s_queue_runner, outgoing);
     
     do {
	  int i, n;
	  PGconn *c = pg_cp_get_conn();
	  PGresult *r;
	  
	  if (c == NULL)
	       break;
	  r = PQexec(c, "SELECT id,domain,msg_type FROM ssp_message_queue WHERE nextt <= current_timestamp "
		      " AND edate >= current_timestamp AND sent = false");
	  if (PQresultStatus(r) == PGRES_TUPLES_OK && (n = PQntuples(r)) > 0)
	       for (i = 0; i<n; i++) {
		    char *x = PQgetvalue(r, i, 0);
		    char *d = PQgetvalue(r, i, 1);
		    char *m = PQgetvalue(r, i, 2);
		    if (d == NULL || get_islocal_domain(c, d) == 1) {
			 char buf[256];
			 PGresult *r;
			 error(0, "SSPD: Unexpected recipient domain [%s] in queue entry [%s], msg type [%s]: "
			       "This domain is local. Message discarded!", 
			       d, x, m);
			 sprintf(buf, "DELETE from ssp_message_queue WHERE id = %s", x);
			 r = PQexec(c, buf);
			 PQclear(r);
		    } else 
			 gwlist_produce(outgoing, octstr_create(x));
	       }
	  
	  PQclear(r);
	  pg_cp_return_conn(c);
	  gwthread_sleep(config->qrun_interval);
     } while (!sstop);
     /* done. */

     gwlist_remove_producer(outgoing);

     gwthread_join_every((void *)s2s_queue_runner);
     gwlist_destroy(outgoing, NULL);

     for (i = 0; i < NELEMS(handlers) && handlers[i].handler; i++)
	  if (handlers[i].inited) {
	       handlers[i].handler->shutdown();
	       handlers[i].inited = 0; 
       }
}

void start_sspd(void)
{
     int i, have_one = 0;

     
     /* Set the handler order: */

     handlers[0].handler = imps_ssp_handler;
     handlers[1].handler = xmpp_ssp_handler;


     /* XXX here we may load others from, say, DSOs */

     for (i = 0; i < NELEMS(handlers) && handlers[i].handler; i++)
	  if (handlers[i].handler->init(config) == 0)
	       handlers[i].inited = have_one = 1;
     
     if (!have_one)
	  panic(0, "No S2S handlers, quiting!");
     if (config->qrun_interval < MIN_QRUN_INTERVAL)
	  config->qrun_interval = MIN_QRUN_INTERVAL;
     num_threads = config->num_threads;
     /* run loop. */
     sth = gwthread_create(sspd_queue_runner, NULL);
          
}

void stop_sspd(void)
{     
     sstop = 1; /* make it stop. */
     gwthread_wakeup(sth);
     gwthread_join(sth);
}

void notify_sspd(Octstr *newmsg_tid)
{
     if (outgoing)
	  gwlist_produce(outgoing, newmsg_tid);
}
