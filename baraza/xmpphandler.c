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
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdio.h>
#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <errno.h>
#include <pthread.h>
 

GCRY_THREAD_OPTION_PTHREAD_IMPL;   /* required by gnutls. */
#include "dns.h"
#include "utils.h"
#include "mqueue.h"

#include "xmpphandler.h"
#include "scserver.h"
#include "iksemel.h"

#define DSIZE_HINT 101
#define MAX_FDS 1<<16

#define DEFAULT_TIMEOUT 0 /* because FDSET does the waiting for us. */
/* first 3 bits is connection state. */
#define XMPP_CONNECTING    (1)
#define XMPP_CONNECTED  (1<<1)
#define XMPP_DEAD       (1<<2)
#define XMPP_TLS_TRY    (1<<3)

/* next two bit is for incoming/outgoing. */
#define XMPP_INCOMING    (1<<4)
#define XMPP_OUTGOING    (1<<5)

#define XMPP_USE_TLS      (1<<6)
#define XMPP_DB_SENT      (1<<7)
#define XMPP_DB_CHECK_OK  (1<<8)
#define XMPP_DB_SUPPORTED (1<<9)

#define SET_XMPP_CONN_STATE(x, state) do {				\
    (x)->flags  &= ~(XMPP_CONNECTING|XMPP_DEAD|XMPP_TLS_TRY|XMPP_CONNECTED); \
    (x)->flags  |= (state);						\
  } while(0)

#define XMPP_CONN_SECURE_OK(x) (!((x)->flags & XMPP_USE_TLS) || iks_is_secure((x)->prs))


/* This is for IQ */
#define XMPP_IQ_SET    0
#define XMPP_IQ_GET    1
#define XMPP_IQ_RESULT 2

#define NUM_GET_CONN_TRIES 20
#define WAIT_INTERVAL      1 /* wait one second. */

#define XMPP_PORT 5269
struct DialBackWaiter_t {
     int fd; /* file descriptor of waiter. */
     char id[DEFAULT_BUF_LEN]; /* ID being verified. */
};

typedef struct XMPPConn_t {
     char domain[DEFAULT_BUF_LEN];
     char _pad1;
     char our_domain[DEFAULT_BUF_LEN];
     char _pad2;
     char host[DEFAULT_BUF_LEN];
     char _pad3;
     int port;
     char id[DEFAULT_BUF_LEN];
     unsigned long flags; /* dead, alive, incoming, etc. */
     iksparser *prs; 
     Mutex *m;
     List *db_list; /* of DialbackWaiter */
     unsigned short ver; /* xmpp version. */
} XMPPConn_t;

struct OutgoingReq_t {
     unsigned conn_flags;
     struct DialBackWaiter_t *dx; /* used for dialback requests. */
     char domain[DEFAULT_BUF_LEN];
     char our_domain[DEFAULT_BUF_LEN];
     Octstr *msg;
};

static char mydomain[DEFAULT_BUF_LEN], myhostname[DEFAULT_BUF_LEN];
static Dict *outgoing;  /* indexed by domain name, item is list of XMPPConn_t *. */
static Dict *incoming;  /* indexed by socket number, item is XMPPConn_t *. */
static int xmpp_socket; /* master socket on which we listen. */
static FDSet *xmpp_fds, *xmpp_fds; /* For poll-ing: One for each direction, so that we don't hang on one or the other. */
static long xmpp_th;    /* thread that handles incoming XMPP connections. */
static char xmpp_salt[128]; /* used for generation of dialback keys. */

static List *connlist;   /* list of connections. */
static List *outgoing_requests; /* outgoing requests. List of struct OutgoingReq_t ptr*/


static gnutls_certificate_credentials cred; /* our TLS credentials. */

static void free_xmppconn(XMPPConn_t *xcon);
static void free_xmppconn_list(List *l);
static void s2s_xmpp_listener(void *unused);
static int s2s_xmpp_processor(void *, int type, iks *node);
static void my_iks_log_hook(void *x, const char *data, size_t len, int incoming);
static void read_handler(void);
static void write_handler(void);

static const char *xmpp_conntype(int flags);
static char *xmpp_oflags(int flags, char buf[]);

static void s2s_iks_handler(int fd, int revents, void *x);

static void xmpp2csp_trans(PGconn *c, iks *node, XMPPConn_t *);
static List *xmpp2csp_msg(PGconn *c, iks *node, char domain[], Sender_t *xsender, 
			  void **rto, Octstr **id,  Octstr **err);
static Octstr *csp2xmpp_msg(PGconn *c, void *msg, void *orig_msg, char *from, char *orig_id,
			    List *rcptlist, Octstr *err);

static gnutls_dh_params_t dh_params;

#define DH_BITS 1024
static int generate_dh_params (void)
{

  /* Generate Diffie Hellman parameters - for use with DHE
   * kx algorithms. When short bit length is used, it might
   * be wise to regenerate parameters.
   *
   * 
   */
  gnutls_dh_params_init (&dh_params);
  gnutls_dh_params_generate2 (dh_params, DH_BITS);

  return 0;
}

#if 0
static void tls_logging(int lev, const char *s)
{    
     info(0, "TLS log> %s", s); 
}
#endif

static int xmpp_init(struct imps_conf_t *config)
{
     int i;
     int max_simul;
     
     if (outgoing != NULL || incoming != NULL)
	  return -1;

     gcry_control (GCRYCTL_ENABLE_QUICK_RANDOM, 0);
     gcry_control (GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);

     /* initialise gnutls stuff. */
     if (gnutls_global_init () != 0)
	  return -1;

#if 0
     gnutls_global_set_log_function(tls_logging);    
     gnutls_global_set_log_level(10); 
#endif

     if (gnutls_certificate_allocate_credentials (&cred) != 0)
	  return -1;
	
     if (config->ssl_certkeyfile[0]) {
	  if (gnutls_certificate_set_x509_key_file (cred, 
						    config->ssl_certkeyfile,
						    config->ssl_certkeyfile,
						    GNUTLS_X509_FMT_PEM) != 0)
	       return -1;   
	  if (config->ssl_ca_file[0])
	       if (gnutls_certificate_set_x509_trust_file (cred, config->ssl_ca_file,
							   GNUTLS_X509_FMT_PEM) != 0)
		    return -1;
	  if (config->ssl_crlfile[0])
	       if (gnutls_certificate_set_x509_crl_file (cred, config->ssl_crlfile,
							 GNUTLS_X509_FMT_PEM) != 0)
		    return -1;
     }
	  
     
	  
     generate_dh_params ();
     
     gnutls_certificate_set_dh_params (cred, dh_params);
     
     strncpy(myhostname, config->myhostname, sizeof myhostname);
     strncpy(mydomain,   config->mydomain, sizeof mydomain);

     if (config->xmpp_salt[0])
	  strncpy(xmpp_salt, config->xmpp_salt, sizeof xmpp_salt);
     else { /* put in current date and time. */
	  time_t t = time(NULL);
	  ctime_r(&t, xmpp_salt);
     }
     
     connlist = gwlist_create(); /* for reading and writing handling. */
     gwlist_add_producer(connlist);
     
     outgoing = dict_create(DSIZE_HINT, (void *)free_xmppconn_list);
     incoming = dict_create(DSIZE_HINT, (void *)free_xmppconn);

     xmpp_socket = make_server_socket(config->xmpp_server_port, 
				      config->s2s_interface[0] ? 
				      config->s2s_interface : NULL);

     xmpp_fds = fdset_create();
     
     if (xmpp_socket < 0 ||

	 xmpp_fds == NULL ||

	 (xmpp_th = gwthread_create((void *)s2s_xmpp_listener, NULL)) < 0) {
	  dict_destroy(outgoing);
	  dict_destroy(incoming);

	  if (xmpp_fds) 
	       fdset_destroy(xmpp_fds);
	  gwlist_remove_producer(connlist); 
	  gwlist_destroy(connlist, NULL);
	  return -1;
     }

     max_simul = config->num_threads;
     if (max_simul <  2)
	  max_simul = 2; /* otherwise we can 'hang' in TLS handshake if for some bizarre reason it is with self. Que?! */

     for (i = 0; i<max_simul; i++) /* start the connection handler threads. */
	  gwthread_create((void *)read_handler, NULL);
     
     outgoing_requests = gwlist_create();
     gwlist_add_producer(outgoing_requests);
     
     for (i = 0; i<max_simul; i++) /* start the connection handler threads. */
	  gwthread_create((void *)write_handler, NULL);
     
     return 0;
}

static void xmpp_shutdown(void)
{
     gw_assert(outgoing);
     gw_assert(incoming);
     gw_assert(connlist);

     close(xmpp_socket); /* Kill the server thread. */

     /* Kill connlist. */
     gwlist_remove_producer(connlist); 
     gwthread_join_every((void *)read_handler); /* wait for them to all quit. */     

     info(0, "socket closed");
     gwlist_remove_producer(outgoing_requests);
     gwthread_join_every((void *)write_handler); /* wait for them to all quit. */     
     gwlist_destroy(outgoing_requests, NULL);

     info(0, "write hander closed closed");     
    
     gwthread_cancel(xmpp_th); /* Kill s2s thread. */
     gwthread_join(xmpp_th);
     
     
     dict_destroy(outgoing);
     dict_destroy(incoming);
     gwlist_destroy(connlist, NULL);
     
     fdset_destroy(xmpp_fds);
     connlist =  outgoing_requests = NULL;
     outgoing = incoming = NULL;     


     info(0, "fdset closed closed");    
 
     gnutls_certificate_free_credentials(cred);     
     gnutls_global_deinit();

}

static void *make_xmppconn(char *domain, char *our_domain, char *host, 
			  char *id, int flags)
{
     XMPPConn_t *x = gw_malloc(sizeof x[0]);

     memset(x, 0, sizeof x[0]);
     if (domain)
	  strncpy(x->domain, domain, sizeof x->domain);
     else 
	  x->domain[0] = 0;

     if (our_domain)
	  strncpy(x->our_domain, our_domain, sizeof x->our_domain);
     else 
	  x->our_domain[0] = 0;

     if (id)
	  strncpy(x->id, id, sizeof x->id);
     else 
	  x->id[0] = 0;

     if (host)
	  strncpy(x->host, host, sizeof x->host);
     else 
	  x->host[0] = 0;     
     x->port = 0;
     x->flags = flags;
     x->prs = NULL;
     x->m = mutex_create();
     x->db_list = gwlist_create();

     return x;
}
static void free_xmppconn(XMPPConn_t *xconn)
{
     void *x;
     if (xconn == NULL)
	  return;

     if (xconn->prs) {
	  if (xconn->flags & XMPP_INCOMING) 
	       close(iks_fd(xconn->prs));	  
	  iks_parser_delete(xconn->prs);
     }
     mutex_destroy(xconn->m);

     while ((x = gwlist_extract_first(xconn->db_list)) != NULL)
	  gw_free(x);
     gwlist_destroy(xconn->db_list, NULL);

     gw_free(xconn);
}

static void free_xmppconn_list(List *l)
{
     gwlist_destroy(l, (void *)free_xmppconn);
}

static void s2s_xmpp_listener(void *unused)
{
     while (1) {
	  Octstr *ip;
	  XMPPConn_t *xconn;
	  Octstr *xkey = NULL;
	  Octstr *x;
	  Octstr *id_data; /* we reply with an ID. */

	  struct sockaddr_in addr;
	  socklen_t alen = sizeof addr;
	  int fd;
	  
	  fd = accept(xmpp_socket, (struct sockaddr *)&addr, &alen);
	  if (fd < 0) {
	       if (errno == EINTR)
		    continue;
	       else {
		    info(0, "XMPP listener quits for socket %d: [%d --> %s]!", xmpp_socket, errno, 
			 strerror(errno));
		    break;
	       }
	  }

	  ip  = host_ip(addr);
	  xkey  = octstr_format("%d", fd);
	  x = octstr_format("%d %d", time(NULL), fd);
	  id_data = md5digest(x);

	  info(0, "S2S XMPP: Received new connection from %s", octstr_get_cstr(ip));
	  
	  xconn = make_xmppconn(NULL, NULL, octstr_get_cstr(ip), 
				octstr_get_cstr(id_data), 
				XMPP_CONNECTING | XMPP_INCOMING);
	  
	  xconn->prs = iks_stream_new_ex("jabber:server", xconn,
					   s2s_xmpp_processor, 
					   "id", xconn->id,
					   "xmlns:db", "jabber:server:dialback");
	  octstr_destroy(x);
	  octstr_destroy(id_data);
	  if (xconn->prs == NULL)  {
	       error(0, "failed to create sax parser for connection from %s",
		     octstr_get_cstr(ip));
	       goto loop;
	  } else {
	       iks_set_log_hook(xconn->prs, my_iks_log_hook);
	       iks_set_tls_credentials(xconn->prs, cred);
	  }
	  iks_connect_fd(xconn->prs, fd);

	  dict_put(incoming, xkey, xconn);
	  
	  /* Add to fdset so we can handle data coming in/out. */
	  fdset_register(xmpp_fds, fd, POLLIN, (void *)s2s_iks_handler, xconn);
	  
	  /* now wait for dialback to tell us who this is. */
	  xconn = NULL;
	  
     loop: /* if we get here then we failed. */
	  free_xmppconn(xconn);
	  octstr_destroy(ip);
	  octstr_destroy(xkey);
     }

}


/* Gets a new connection, removes it from the outgoing list. */
static int get_connection(char *domain, char *our_domain, XMPPConn_t **xconn, int flags)
{     
     int i, scount, res;
     SrvRecord_t recs = NULL;
     Octstr *xkey;
     List *l;
     XMPPConn_t *x = NULL;
     gw_assert(domain);
     gw_assert(outgoing);

     *xconn = NULL;
     /* Look in list of connections, pick out one. If none, make a new one. */
     xkey = octstr_create(domain);     
     if ((l = dict_get(outgoing, xkey)) != NULL && gwlist_len(l) > 0) {
	  XMPPConn_t *x;
	  int n;
	  res = SSP_ERROR_TRANSIENT;
	  /* XXX need to start in random location in list. */
	  gwlist_lock(l); {
	       for (i = 0, n = gwlist_len(l); i<n; i++) 
		    if ((x = gwlist_get(l, i)) != NULL) { 
			 int flg;
			 mutex_lock(x->m); { /* take a lock on it before checking flag XXX not clean. */
			      flg = x->flags;			
			      
			      if ((flg & flags)
#if 0 /* don't require a secure connection. */ 
				  && (iks_is_secure(x->prs) || !(flg & XMPP_USE_TLS))
#endif
				   ) { /* we got one: Leave while holding the lock. */
				   *xconn = x;
				   res = SSP_OK;
				   gwlist_delete(l, i, 1); /* remove it from the list. */
				   info(0, "S2S XMPP: Selected %s for domain %s", x->host, x->domain);
				   break;
				   
			      }  else if (x && (flg & XMPP_DEAD)) { /* it died: remove it from list.*/
				   gwlist_delete(l, i, 1);
				   n--;
				   i--;
				   info(0, "Outgoing connection [%s] for %s died: Closing it", x->id, x->domain);
			      }			      
			 } mutex_unlock(x->m);
			 if (flg & XMPP_DEAD) { /* it was seen to have died, so destroy it. */
			      free_xmppconn(x);
			      x = NULL; /* so it does not get deleted below. */
			 }
		    }
	       n = gwlist_len(l);
	  } gwlist_unlock(l);
	  
	  if (res == SSP_OK || n>0)
	       goto done; /* we got something. */
     }
     
     
     /* No alive connection, make a new one: First do DNS lookup. */     
     if ((recs = dns_find_srv(domain, "_xmpp-server._tcp", &scount)) == NULL ||
	 scount == 0) {
	  if (recs)
	       gw_free(recs);	  
	  /* try jabber dns entry. */
	  if ((recs = dns_find_srv(domain, "_jabber._tcp", &scount)) == NULL ||
	      scount == 0) {	 
	       info(0, "S2S XMP: Domain %s does not have xmpp DNS entries,  will try direct connection to port %d", 
		    domain, XMPP_PORT);
	       if (recs)
		    gw_free(recs);
	       recs = dns_make_srv_rec_from_domain(domain, XMPP_PORT);
	       scount = 1;
	       /* ... and then try and connect to it. */
	  }
     }
     
     res = SSP_ERROR_TRANSIENT; /* at this point we know XMPP SRV records exist. */
     
     x = make_xmppconn(domain, our_domain, NULL, 
		       NULL, 
		       XMPP_CONNECTING | XMPP_OUTGOING);
     if ((x->prs = iks_stream_new_ex("jabber:server", x,
				     s2s_xmpp_processor,	       
				     "xmlns:db", "jabber:server:dialback", 
				     "from", x->our_domain)) == NULL)  {
	  error(0, "failed to create sax parser for connection for %s",
		domain);
	  goto done;
     }  else {
	  iks_set_log_hook(x->prs, my_iks_log_hook);
	  iks_set_tls_credentials(x->prs, cred);
     }
     
     for (i = 0; i<scount; i++) 
	  if (iks_connect_via(x->prs, recs[i].host, recs[i].port, x->domain) == IKS_OK) {/* try to connect. */
	       List *l = gwlist_create();
	       
	       if (dict_put_once(outgoing, xkey, l) == 0)   /* make domain list. */
		    l = dict_get(outgoing, xkey);
	       
	       strncpy(x->host, recs[i].host, sizeof x->host);
	       info(0, "S2S XMPP: Connecting to %s for domain %s", x->host, x->domain);
	       
	       
	       x->port = recs[i].port;

	       fdset_register(xmpp_fds, iks_fd(x->prs), POLLIN, (void *)s2s_iks_handler, x);

	       if (x->flags & flags) {/* this is what we want. Return it. */
		    *xconn = x;
		    res = SSP_OK;
		    mutex_lock(x->m); /* grab the lock when returning it. */
	       } else {
		    gwlist_lock(l); {
			 gwlist_append(l, x);
		    } gwlist_unlock(l);
		    x = NULL; /* don't return it. Not what we want. */
	       }
	       
	       goto done; /* initiating connection to one of the authoritative servers */
	  }
     
     res = SSP_ERROR_FATAL; /* it failed to connect. */     
done: /* if x is set at this point, we failed to connect or get a connection. */
     if (x && x != *xconn)
	  free_xmppconn(x);
     if (recs)
	  gw_free(recs);
     
     octstr_destroy(xkey);
     return res;
}

static void return_connection(XMPPConn_t *xconn)
{
     Octstr *key;
     List *l;
     
     gw_assert(xconn);

     mutex_unlock(xconn->m); /* unlock it. */
     gw_assert(xconn->flags & XMPP_OUTGOING);

     key = octstr_create(xconn->domain);
     l = dict_get(outgoing, key);
     
     gw_assert(l);
     
     gwlist_lock(l); {
	  gwlist_append(l, xconn);
     } gwlist_unlock(l);
     octstr_destroy(key);
}

#if 0
static int try_get_connection(char *domain, char *our_domain, XMPPConn_t **xconn, int flags, int num_tries)
{
     int ret, i = 1;
     do {
	  ret = get_connection(domain, our_domain, xconn, flags);
	  
	  if (ret != SSP_OK)
	       gwthread_sleep(WAIT_INTERVAL);
	  info(0, "Waiting for suitable connection to [%s], try #%d", domain, i++);
     } while (--num_tries > 0);
     
     return ret;
}
#endif
static Octstr *mk_db_key(char *id, char *to_domain, char *from_domain)
{
     Octstr *x = octstr_format("%s %s %s %s", id, to_domain, from_domain, xmpp_salt);
     Octstr *y = md5digest(x);
     
     octstr_destroy(x);
     return y;
}

static void my_iks_log_hook(void *x, const char *data, size_t len, int incoming)
{
     char flg[100];
     XMPPConn_t *xconn = x;
     int c_in = (xconn->flags & XMPP_INCOMING);
     info(0, " %s XMPP [%d] host/domain <%s: %s|%s|%s>: [%s:%d/%s] our_domain: [%s], id: [%s] %s",
	  incoming ? " <<== " : " ==>> ", 
	  iks_fd(xconn->prs),
	  c_in ? "INCOMING CONN" : "OUTGOING CONN",
	  iks_is_secure(xconn->prs) ? "SECURE" : "PLAIN",
	  xmpp_conntype(xconn->flags),
	  xmpp_oflags(xconn->flags, flg),
	  xconn->host, xconn->port, xconn->domain, xconn->our_domain, xconn->id, 
	  data);
}

static const char *xmpp_conntype(int flags)
{
     if (flags & XMPP_CONNECTED)
	  return "CONNECTED";     
     else if (flags & XMPP_DEAD)
	  return "DEAD";
     else if (flags & XMPP_CONNECTING)
	  return "CONNECTING";
     else  if (flags & XMPP_TLS_TRY)
	  return "STARTING_TLS";
     else 
	  return "N/A";
}

static char *xmpp_oflags(int flags, char buf[])
{
     char *p = buf;
     buf[0] = 0;
     if (flags &  XMPP_USE_TLS)
	  p += sprintf(p, "USE_TLS ");
     
     if (flags &  XMPP_DB_SENT)
	  p += sprintf(p, "DIALBACK_SENT ");

     if (flags &  XMPP_DB_CHECK_OK)
	  p += sprintf(p, "DIALBACK_SUCCESS ");

     if (flags &  XMPP_DB_SUPPORTED)
	  p += sprintf(p, "DIALBACK_SUPPORTED ");

     return buf;
}

static void send_db_key(XMPPConn_t *xconn)
{
     Octstr *key = mk_db_key(xconn->id, xconn->domain, xconn->our_domain);
     Octstr *x = octstr_format("<db:result to='%s' from='%s'>%S</db:result>",
			       xconn->domain, xconn->our_domain, key);
     iks_send_raw(xconn->prs, octstr_get_cstr(x));			
     xconn->flags |= XMPP_DB_SENT;
     octstr_destroy(x);
     octstr_destroy(key);
}

static int s2s_xmpp_processor(void *x, int type, iks *node)
{
     XMPPConn_t *xconn = x;
     char *name = (type != IKS_NODE_STOP) ? iks_name(node)  : NULL, buf[100];
     PGconn *c = pg_cp_get_conn();
     Octstr *res = NULL;
     void *y;
     char *z;
     /* mutex is alread locked, so do not lock it! 
      * we are called here for reading...
      */
#if 0     
   info(0, "xmpp_processor [%s <%s - %s>]: %s", 
	  xconn->flags & XMPP_INCOMING ? "INCOMING" : "OUTGOING",
	  iks_is_secure(xconn->prs) ? "SECURE" : "PLAIN",
	  xmpp_conntype(xconn->flags),
	  name ? name : "(empty)"); 
#endif
     if (name == NULL || 
	 type == IKS_NODE_STOP || 
	 type == IKS_NODE_ERROR)  /* connection is closing. */
	  SET_XMPP_CONN_STATE(xconn, XMPP_DEAD);
      else if (type == IKS_NODE_START) { /* stream:stream */
	  char *id;
	  char *xver; /* Check for version string. */
	  int version;
	  
	  if ((xver  = iks_find_attrib(node, "version")) != NULL) {
	       unsigned int x = 0, y = 0;
	       sscanf(xver, "%d.%d", &x, &y);
	       
	       version = CSP_VERSION(x, y); /* use this macro XXX not ideal, but... */
	  } else 
	       version = 0;
	  xconn->ver = version;
	  if (xconn->flags & XMPP_OUTGOING) { /* find the id of the connection. */
	       if ((id = iks_find_attrib(node, "id")) != NULL) 
		    strncpy(xconn->id, id, sizeof xconn->id);

	       /* does this puppy support dialback? */
	       xconn->flags |= iks_find_attrib(node, "xmlns:db") ? XMPP_DB_SUPPORTED : 0;

	       /* Send dialback key is tricky. You want to send it in the current <stream>. So:
		* If the other side does TLS, don't send it til we have TLS established.
		* If other side does not do TLS, then figure that out at point of <features/>
		* and send the db key. Otherwise if it is a pre 1.0 XMPP endpoint, send
		* the db key right after the stream is opened. 
		* Of course send the db key only once.
		*/
	       if (!(xconn->flags & XMPP_DB_SENT) && 
		   (xconn->flags & XMPP_DB_SUPPORTED)) {
		    if (version < CSP_VERSION(1,0) ||
			iks_is_secure(xconn->prs))
			 send_db_key(xconn); 
	       }
	       
	       /* we were trying to do starttls and it succeeded, then remove the flag. */
	       if ((xconn->flags & XMPP_TLS_TRY) && iks_is_secure(xconn->prs)) {
		    SET_XMPP_CONN_STATE(xconn, XMPP_CONNECTING);
	       }
	       /* Connection is deemed live if: 
		* - dialback check is complete and
		* - tls is done (if tls was asked for) or version is < 1.0 (meaning we can't do TLS negotiation)
		*/

	       if (xconn->flags & XMPP_DB_CHECK_OK) {
		    if (iks_is_secure(xconn->prs) || version < CSP_VERSION(1,0))
			 SET_XMPP_CONN_STATE(xconn, XMPP_CONNECTED);		    
	       }
	  } else if (xconn->flags & XMPP_INCOMING) { /* on incoming, always send features after receiving header. */
	       if (version < CSP_VERSION(1,0)) 
		    xconn->flags &= ~XMPP_USE_TLS; /* No TLS, since this is not v1 */
	       else 
		    xconn->flags |= XMPP_USE_TLS; /* otherwise assume we must have TLS. */
	       

	       if (!(xconn->flags & XMPP_USE_TLS) || !iks_is_secure(xconn->prs)) {  /* Not yet TLS, send our caps. */
		    /* send greeting only if not yet secure. 
		     * otherwise iksemel will have sent greeting.
		     */
		    iks_send_header(xconn->prs, xconn->domain[0] ? xconn->domain : NULL);
		    if (version >= CSP_VERSION(1,0))
			 iks_send_raw(xconn->prs, "<stream:features xmlns:stream='http://etherx.jabber.org/streams'>"
				      "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>"
				      "<required/>"
				      "</starttls>"
				      "</stream:features>");  		    
	       } else if (xconn->flags & XMPP_DB_CHECK_OK)  
		    /* connection is secure and dialback is complete: connection is live. */
		    SET_XMPP_CONN_STATE(xconn, XMPP_CONNECTED);			 
	       	       
	       if (version >= CSP_VERSION(1,0) && iks_is_secure(xconn->prs))
		    iks_send_raw(xconn->prs, "<stream:features xmlns:stream='http://etherx.jabber.org/streams'/>");  /* empty features when we are in secure mode. */	    
	  }
      } else if (strcmp(name, "stream:features") == 0) { /* only v1.0 and above. */
	   if (xconn->flags & XMPP_OUTGOING) { /* can only show up on out-going. */
		iks *st_node = iks_find(node, "starttls");
	       if (st_node && 
		   !iks_is_secure(xconn->prs) ) { /* the secure check should not be required, but...*/
		    xconn->flags |= XMPP_USE_TLS;
		    if (iks_start_tls(xconn->prs) != IKS_OK) /* start TLS. */
			 xconn->flags |= XMPP_DEAD;
		    else 
			 SET_XMPP_CONN_STATE(xconn, XMPP_TLS_TRY); /* indicate that TLS negotiations in progress.*/	    
	       } else if (st_node == NULL && /* No TLS support, and we haven't send DB key yet: send it*/
			  !(xconn->flags & XMPP_DB_SENT) && xconn->ver >= CSP_VERSION(1,0)) 
		    send_db_key(xconn);
	  }
     } else if (strcmp(name, "db:result") == 0) {
	  /* can only be received on incoming leg. */
	  iks *cdata_node = iks_child(node);
	  char *our_domain = iks_find_attrib(node, "to");
	  char *domain = iks_find_attrib(node, "from");
	  char *key = cdata_node ? iks_cdata(cdata_node) : NULL;
	  char *type = iks_find_attrib(node, "type");
	  
	  if (our_domain == NULL  || domain == NULL ||
		    get_islocal_domain(c, our_domain) != 1) {
	       iks_send_raw(xconn->prs, 
			    "<stream:error><host-unknown/></stream:error></stream:stream>");
	       xconn->flags |= XMPP_DEAD;
	  } else if (type && (xconn->flags & XMPP_OUTGOING)) {  /* outgoing connection recived a db response.*/
	       if (strcasecmp(type, "valid") == 0) 
		    xconn->flags |=  XMPP_DB_CHECK_OK | (XMPP_CONN_SECURE_OK(xconn) ? XMPP_CONNECTED : 0);
	       else 
		    xconn->flags |= XMPP_DEAD;
	  } else  if (xconn->flags & XMPP_OUTGOING) {
	       iks_send_raw(xconn->prs, 
			    "<stream:error><policy-violation/></stream:error></stream:stream>");
	       xconn->flags |= XMPP_DEAD;
	  } else { /* incoming connection. */
	       struct DialBackWaiter_t *dx = gw_malloc(sizeof dx[0]);
	       struct OutgoingReq_t *oreq = gw_malloc(sizeof *oreq);
	       

	       dx->fd = iks_fd(xconn->prs);
	       strncpy(dx->id, xconn->id, sizeof dx->id); /* who are we verifying. */

	       /* build outgoing request struct. */
	       oreq->conn_flags = XMPP_CONNECTING | XMPP_CONNECTED;
	       oreq->dx = dx;
	       oreq->msg = octstr_format("<db:verify from='%s' to='%s' id='%s'>%s</db:verify>",
					 our_domain, domain, xconn->id, key);
	       strncpy(oreq->our_domain, our_domain, sizeof oreq->our_domain);
	       strncpy(oreq->domain, domain, sizeof oreq->domain);

	       /* now send the verify request, and go away. */
	       info(0, "xmpphandler: queued dialback request for domain [%s] ", oreq->domain);

	       gwlist_produce(outgoing_requests, oreq);
	  }
     } else if (strcmp(name, "db:verify") == 0) {
	  iks *cdata_node = iks_child(node);
	  char *our_domain = iks_find_attrib(node, "to");
	  char *domain = iks_find_attrib(node, "from");
	  char *id = iks_find_attrib(node, "id");
	  char *type = iks_find_attrib(node, "type");
	  char *key = cdata_node ? iks_cdata(cdata_node) : NULL;
	  
	  if (our_domain == NULL  || domain == NULL || id == NULL ||
	      get_islocal_domain(c, our_domain) != 1) {
	       iks_send_raw(xconn->prs, 
			    "<stream:error><host-unknown/></stream:error></stream:stream>");
	       xconn->flags |= XMPP_DEAD;
	  } else if (type && id && (xconn->flags &  XMPP_OUTGOING)) { /* a response to our previous request. */
	       struct DialBackWaiter_t *dx = NULL, *dw;
	       int i, n;
	       Octstr *x = NULL;
	       XMPPConn_t *o_xconn;
	       
	       for (i = 0, n = gwlist_len(xconn->db_list); i<n; i++) 
		    if ((dw = gwlist_get(xconn->db_list, i)) != NULL && 
			strncmp(id, dw->id, sizeof dw->id) == 0) {
			 gwlist_delete(xconn->db_list, i, 1);
			 dx = dw;
			 break;
		    } 
	       if (dx &&  /* We found the one for which we sent a dialback. Check result. */
		   (o_xconn = dict_get(incoming, x = octstr_format("%d", dx->fd))) != NULL)  {
		    Octstr *y = octstr_format("<db:result from='%s' to='%s' type='%s'/>",
					      our_domain, domain, type);

		    if (strcasecmp(type, "valid") == 0) {
			 /* record the domain. */
			 strncpy(o_xconn->domain, domain, sizeof o_xconn->domain);
			 strncpy(o_xconn->our_domain, our_domain, sizeof o_xconn->our_domain);
			 
			 o_xconn->flags |=  XMPP_DB_CHECK_OK | (XMPP_CONN_SECURE_OK(o_xconn) ? XMPP_CONNECTED : 0);
		    } else 
			 o_xconn->flags |= XMPP_DEAD;

		    // o_xconn->flags |= (strcasecmp(type, "valid") == 0) ? XMPP_DB_CHECK_OK : XMPP_DEAD;
		    mutex_lock(o_xconn->m); { /* Report result back to the incoming connection, 
					       * and kill it or mark it legit as necessary. 
					       */
			 iks_send_raw(o_xconn->prs, octstr_get_cstr(y));
		    } mutex_unlock(o_xconn->m); 

		    
		    octstr_destroy(y);
	       } else 
		    error(0, "Hmmm, received dialback response for ID[%s], domain[%s], our_domain[%s] "
			  " but no matching request!",
			  id, domain, our_domain);
	       /* on error, we quietly ignore other side. */
	       octstr_destroy(x);
	       if (dx)
		    gw_free(dx);
	  } else if (xconn->flags & XMPP_OUTGOING) { /* no type, yet outgoing? Error. */
	       iks_send_raw(xconn->prs, 
			    "<stream:error><policy-violation/></stream:error></stream:stream>");
	       xconn->flags |= XMPP_DEAD;
	  } else { /* otherwise a check. */
	       Octstr *xkey = mk_db_key(id, domain, our_domain);
	       int valid = (octstr_str_compare(xkey, key) == 0);
	       Octstr *x = octstr_format("<db:verify from='%s' to='%s' type='%s' id='%s'/>",
					 our_domain, domain, 
					 valid ? "valid" : "invalid", 
					 id);
	       
	       iks_send_raw(xconn->prs, octstr_get_cstr(x));
	       octstr_destroy(xkey);
	       octstr_destroy(x);
	  }
	  
     } else if (strcmp(name, "iq") == 0 && 
	      (y = iks_find(node, "query")) != NULL && 
	      (z = iks_find_attrib(y, "xmlns")) != NULL && 
	      strcmp(z, "http://jabber.org/protocol/disco#info") == 0) { /* discovery: fake it. */
	  char *from = iks_find_attrib(node, "from");
	  char *to = iks_find_attrib(node, "to");
	  Octstr *x = octstr_format("<iq from='%s' to='%s' type='result'>"
				    "<query xmlns='http://jabber.org/protocol/disco#info'>"		    
				    "<feature var='urn:xmpp:receipts'/>"				    
				    "</query>"
				    "</iq>", 
				    to, from);
	  iks_send_raw(xconn->prs, octstr_get_cstr(x));
	  octstr_destroy(x);
     } else if (xconn->flags & XMPP_CONNECTED) { 
	  if (xconn->flags & XMPP_OUTGOING)
	       iks_send_raw(xconn->prs, 
			    "<stream:error><undefined-condition xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
			    "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams' xml:lang='en'>"
			    "Received data on a send-only socket."
			    "</text></stream:error>");
	  else 
	       xmpp2csp_trans(c, node, xconn); /* process and send reply as needed. */
     }   else 
	  warning(0, "xmpp_processor received %s, not processed!", name);
#if 0
     info(0, "xmpp_processor complete [%s (%s - %s)]: %s", 
	  xconn->flags & XMPP_INCOMING ? "INCOMING" : "OUTGOING",
	  iks_is_secure(xconn->prs) ? "SECURE" : "PLAIN",
	  xmpp_conntype(xconn->flags),
	  name ? name : "(empty)");
#endif
     pg_cp_return_conn(c);
     if (node) 
	  iks_delete(node); /* ??? */
     octstr_destroy(res);

     info(0, "Leaving XMPP Processor [%d] <%s: %s|%s|%s>: [%s:%d/%s] our_domain: [%s], id: [%s]",
	  iks_fd(xconn->prs),
	  (xconn->flags & XMPP_INCOMING) ? "INCOMING" : "OUTGOING",
	  iks_is_secure(xconn->prs) ? "SECURE" : "PLAIN",
	  xmpp_conntype(xconn->flags),
	  xmpp_oflags(xconn->flags, buf),
	  xconn->host, xconn->port, xconn->domain, xconn->our_domain, xconn->id);

     /* check to see if we need to close an incoming connection. */
     if ((xconn->flags & XMPP_INCOMING) && 
	 (xconn->flags & XMPP_DEAD)) {
	  info(0, "Incoming connection for %s died, closing fd", xconn->domain);
	  close(iks_fd(xconn->prs)); 
     }
     return 0;     
}


static void s2s_iks_handler(int fd, int revents, void *x)
{
     XMPPConn_t *xconn = x;

     gw_assert(x);

     info(0, "s2s_iks_handler [fd=%d], [revents=%d]", fd, revents);
     fdset_unregister(xmpp_fds, fd); /* no more events on this one (until perhaps after read).*/     
     if (revents & (POLLERR | POLLHUP | POLLNVAL )) { 	  /* hangup. */
	  if (xconn->flags & XMPP_INCOMING) {
	       Octstr *key = octstr_format("%d", fd);
	       dict_put(incoming, key, NULL); /* remove it from the dict. */
	       octstr_destroy(key);    		    
	  } else  /* outgoing: simply mark it as dead, we'll remove it 
		    * when looking for outgoing connections.
		    */
	       SET_XMPP_CONN_STATE(xconn, XMPP_DEAD);
	  
     } else if (revents & POLLIN) 
	  gwlist_produce(connlist, x); /* so we don't block because of long-running tasks. */
}

static void write_handler(void)
{
     struct OutgoingReq_t *x;

     while ((x = gwlist_consume(outgoing_requests)) != NULL) {
	  XMPPConn_t *xconn;
	  int ret;
	  
	  if ((ret = get_connection(x->domain, x->our_domain, &xconn, x->conn_flags)) == SSP_ERROR_TRANSIENT) {
	       gwthread_sleep(WAIT_INTERVAL); /* sleep a little to give the connection time to come up. */
	       gwlist_produce(outgoing_requests, x); /* try later. */
	       continue;
	  } else if (ret == SSP_OK) {
	       /* note that we shouldn't grab the lock, as get_connection already does that. */
	       if (x->dx) /* there is a dialback waiter. Record it first. */
		    gwlist_append(xconn->db_list, x->dx); /* record it as a dialback result waiter. */
	       iks_send_raw(xconn->prs, octstr_get_cstr(x->msg));		    
	       return_connection(xconn);
	  } else { /* ret == SSP_ERROR_FATAL */

	       if (x->dx)  {/* dialback: close the original connection, because we couldn't dialback to its authoritative server. */
		    close(x->dx->fd);
		    gw_free(x->dx);
	       }
	       error(0, "ssp xmpphandler: Hmm, failed to send message to %s in response to incoming!",
		     x->domain);	 
	  }
	  info(0, "xmpphandler: outgoing message attempt to domain [%s], get_conn returned %d",
	       x->domain, ret);
	  /* free the stuff. */
	  octstr_destroy(x->msg);
	  gw_free(x);
     }
}

static void read_handler(void)
{
     XMPPConn_t *xconn;
     /* XXX race condition: what if there is a hangup before we read?? */
     while ((xconn = gwlist_consume(connlist)) != NULL) {
	  int fd = iks_fd(xconn->prs);
	  int flag = 0;
#if 0
	  info(0, "[%ld] readhandler callback with <%s,%s> domain=%s [%d]", 
	       gwthread_self(), 
	       (xconn->flags & XMPP_INCOMING) ? "INCOMING" : "OUTGOING",
	       xmpp_conntype(xconn->flags),
	       xconn->domain,
	       fd);
#endif
	  if (mutex_trylock(xconn->m) == 0) { /* if it fails, then read/write is in progress, so go away. */
	       if (iks_recv(xconn->prs, DEFAULT_TIMEOUT) != IKS_OK)
		    SET_XMPP_CONN_STATE(xconn, XMPP_DEAD); /* it died on us! */
	       flag = xconn->flags;
	       mutex_unlock(xconn->m);
	  }
	  if (!(flag & XMPP_DEAD)) /* don't re-register a dead connection. */
	       fdset_register(xmpp_fds, fd, POLLIN, (void *)s2s_iks_handler, xconn); /* put it back. */
     }

     info(0, "read thread [%ld] exits", gwthread_self());
}

/* Make a JID out of a Group_t or User_t */
static Octstr *make_local_jid(void *entity)
{
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     int t = CSP_MSG_TYPE(entity);
     Octstr *x;
     if  (t == Imps_User || t == Imps_UserID) {
	  User_t u = (t == Imps_User) ? entity : NULL;
	  UserID_t user = (t == Imps_User) ? u->user : entity;

	  extract_id_and_domain(csp_String_to_cstr(user), xid, xdomain);
	  if (xdomain[0] == 0)
	       strncpy(xdomain, mydomain, sizeof xdomain); /* default domain assumed. */

	  if (xid[0] == '/')  /* a service. */
	       x = octstr_format("%s%s", xdomain, xid);
	  else {
	       Octstr *clid = u ? make_clientid(u->u.typ == Imps_ClientID ? u->u.val : NULL,
						u->u.typ == Imps_ApplicationID ? u->u.val : NULL) : 
		    octstr_imm("");	 
	       Octstr *fname = u && u->fname ? octstr_format("%s", csp_String_to_cstr(u->fname)) : octstr_imm("");
	       
	       x = octstr_format("%s@%s/u%Hf:%H",xid, xdomain, fname, clid);
	       
	       octstr_destroy(clid);
	       octstr_destroy(fname);
	  }
     } else if (t == Imps_Group || t == Imps_ScreenName || t == Imps_GroupID) {
	  Group_t g = (t == Imps_Group) ? entity : NULL;
	  ScreenName_t sname = (t == Imps_ScreenName) ? entity : 
	       (g == NULL || g->u.typ == Imps_GroupID) ? NULL : g->u.val;
	  GroupID_t gid = (t == Imps_GroupID) ? entity : 
	       (g && g->u.typ == Imps_GroupID) ? g->u.val : 
	       (sname ? sname->gid : NULL);
	  Octstr *s = sname ? octstr_format("%s", csp_String_to_cstr(sname->sname)) : octstr_imm("");
	  char *p;
	  
	  extract_id_and_domain(gid ? csp_String_to_cstr(gid) : "anon@", xid, xdomain);	  
	  if (xdomain[0] == 0)
	       strncpy(xdomain, mydomain, sizeof xdomain); /* default domain assumed. */

	  if ((p = strchr(xid, '/')) != NULL) /* replace the '/' with ~ */
	       *p = '~';
	  
	  x = octstr_format("%s@%s%s%S", xid, xdomain, 
			    octstr_len(s) == 0 ? "" : "/", s);	  
	  octstr_destroy(s);
     } else 
	  x = NULL;
     return x;
}

static void parse_jid(char *jid, char xnode[], char xdomain[], char xrsrc[])
{
     char *p, *q, *r, *s;

     p = strchr(jid, '@');
     q = strrchr(jid, '/');
     
     /* First parse node, domain and resource. */
     if (p) { /* we have a node. */
	  r = xnode;
	  s = jid;
	  
	  while (*s && s < p && r < xnode + (-1 + DEFAULT_BUF_LEN))
	       *r++ = *s++;
	  *r = '\0';
	  jid = p + 1; /* move it forward. */
     } else 
	  xnode[0] = 0;

     /* copy domain part. */
     if (q == NULL)
	  s = jid + strlen(jid);
     else 
	  s = q;

     r = xdomain;
     while (*jid && jid < s && r < xdomain + (-1 + DEFAULT_BUF_LEN))
	  *r++ = *jid++;
     *r = 0;

     /* copy resource. */
     if (q)
	  strncpy(xrsrc, q + 1, -1 + DEFAULT_BUF_LEN);
     else 
	  xrsrc[0] = 0;
     xrsrc[-1 + DEFAULT_BUF_LEN] = 0;
}

static void *parse_local_jid(char *jid, int *type, char xdomain[])
{

     char xnode[DEFAULT_BUF_LEN], xrsrc[DEFAULT_BUF_LEN], *p;
     void *res;
     
     parse_jid(jid, xnode, xdomain, xrsrc);
     
     if ((p = strchr(xnode, '~')) == NULL) {  /* look for marker. If not present, this is a user. */
	  Octstr *x;
	  UserID_t u;
	  if (xnode[0] == 0) { /* a resource. */
	       x = octstr_format("/%s@%s", xrsrc, xdomain);
	       u = csp_String_from_cstr(octstr_get_cstr(x), Imps_UserID);
	  
	       res = csp_msg_new(User, NULL, FV(user, u));
	  } else {
	       x = octstr_format("%s@%s", 
				 xnode, 
				 xdomain);
	       u = csp_String_from_cstr(octstr_get_cstr(x), Imps_UserID);
	       res = csp_msg_new(User, NULL, 
				 FV(user, u));
	       if (xrsrc[0] == 'u') {
		    char *y = strstr(xrsrc + 1, "f:");
		    Octstr *clid = octstr_create_from_data(xrsrc + 1, y ? y - (xrsrc + 1) : strlen(xrsrc));
		    Octstr *fname = y ? octstr_create(y + 2) : NULL;
		    ApplicationID_t app = NULL;
		    ClientID_t clnt = NULL;
		    
		    octstr_hex_to_binary(clid);
		    if (fname) 
			 octstr_hex_to_binary(fname);
		    
		    parse_clientid(clid, &clnt, &app);
	  
		    
		    if (app)
			 CSP_MSG_SET_UFIELD((User_t)res, u, Imps_ApplicationID, app);
		    else if (clnt)
			 CSP_MSG_SET_UFIELD((User_t)res, u, Imps_ClientID, clnt);
		    
		    if (fname)
			 CSP_MSG_SET_FIELD((User_t)res, fname, 
					   csp_String_from_bstr(fname, Imps_FriendlyName));
		    octstr_destroy(fname);
		    octstr_destroy(clid);
	       }
	  }
	  octstr_destroy(x);
	  *type = Imps_User;
     } else if (p) {
	  Octstr *x;
	  GroupID_t gid;
	  
	  *p = '/'; /* change it. */

	  x = octstr_format("%s@%s", xnode, xdomain);
	  gid = csp_String_from_cstr(octstr_get_cstr(x), Imps_GroupID);
	  if (xrsrc[0]) {
	       SName_t sn;
	       ScreenName_t s;

	       sn = csp_String_from_cstr(xrsrc, Imps_SName);
	       s = csp_msg_new(ScreenName, NULL,
			       FV(sname, sn),
			       FV(gid, gid));
	       res = csp_msg_new(Group, NULL, UFV(u, Imps_ScreenName, s));
	  } else 
	       res = csp_msg_new(Group, NULL, UFV(u, Imps_GroupID, gid));
	  *type = Imps_Group;
	  octstr_destroy(x);
     } else 
	  res = NULL;     

     return res;
}

static void *parse_foreign_jid(char *jid, int is_group, char xdomain[])
{
     Octstr *x;
     char xnode[DEFAULT_BUF_LEN], xrsrc[DEFAULT_BUF_LEN];
     void *res;
     
     parse_jid(jid, xnode, xdomain, xrsrc);

     x = octstr_format("%s@%s", 
		      xnode, 
		      xdomain);
     
     if (is_group) {
	  GroupID_t gid = csp_String_from_bstr(x, Imps_GroupID);
	  
	  if (xrsrc[0]) {
	       SName_t sn = csp_String_from_cstr(xrsrc, Imps_SName);
	       ScreenName_t s = csp_msg_new(ScreenName, NULL,
					    FV(sname, sn),
					    FV(gid, gid));
	       res = csp_msg_new(Group, NULL, UFV(u, Imps_ScreenName, s));
	  } else 
	       res = csp_msg_new(Group, NULL, UFV(u, Imps_GroupID, gid));	  	 
     } else {/* a user. */
	  User_t u = res = csp_msg_new(User, NULL,
				       FV(user, csp_String_from_bstr(x, Imps_UserID)));
	  if (xrsrc[0]) {
	       ClientID_t clid = csp_msg_new(ClientID, NULL,
					FV(url, 
					   csp_String_from_cstr(xrsrc, Imps_URL)));
	       CSP_MSG_SET_UFIELD(u, u, Imps_ClientID, clid);	       
	  }
     }
     octstr_destroy(x);	  
     
     return res;
}

/* convert a foreign JID from CSP format to XMPP format. */
static Octstr *make_foreign_jid(void *entity) 
{     
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     int t = CSP_MSG_TYPE(entity);
     Octstr *x;
     if  (t == Imps_User || t == Imps_UserID) {
	  User_t u = (t == Imps_UserID) ? NULL : entity;
	  UserID_t user = (t == Imps_UserID) ? entity : u->user;
	  
	  extract_id_and_domain(csp_String_to_cstr(user), xid, xdomain);

	  if (xid[0] == '/')  /*  a service. */
	       x = octstr_format("%s%s", xdomain, xid);
	  else {
	       ClientID_t clid = u && u->u.typ == Imps_ClientID ? u->u.val : NULL;
	       char *rsrc = (clid && clid->url) ? csp_String_to_cstr(clid->url) : NULL;
	       
	       x = octstr_format("%s@%s%s%s", xid, xdomain, 
				 rsrc ? "/" : "", 
				 rsrc ? rsrc : "");	       
	  }
     } else if (t == Imps_Group || t == Imps_ScreenName || 
	  t == Imps_GroupID) {
	  Group_t g = (t == Imps_Group) ?  entity : NULL;
	  ScreenName_t sname = (t == Imps_ScreenName) ? entity : 
	       (g == NULL || g->u.typ == Imps_GroupID) ? NULL : g->u.val;
	  GroupID_t gid = (t == Imps_GroupID) ? entity : 
	       (g && g->u.typ == Imps_GroupID) ? g->u.val : 
	       (sname ? sname->gid : NULL);
	  
	  x = octstr_format("%s", csp_String_to_cstr(gid));
	  
	  if (sname && sname->sname) 
	       octstr_format_append(x, "/%s", csp_String_to_cstr(sname->sname));	  
     } else 
	  x = NULL;
     return x;
}

static int check_if_muc_context(iks *node)
{
     char *name = iks_name(node);
     void *y;
     char *x;
     
     if (strcmp(name, "message") == 0 && 
	 (x = iks_find_attrib(node, "type")) != NULL && 
	 strcasecmp(x, "groupchat") == 0)
	  return 1;
     if (strcmp(name, "iq") == 0 && 
	 (y = iks_find(node, "query")) != NULL && 
	 (x = iks_find_attrib(y, "xmlns")) != NULL &&
	 strstr(x, "http://jabber.org/protocol/muc") == x)
	  return 1;
     if (strcmp(name, "presence") == 0 && 
	 (y = iks_find(node, "x")) != NULL &&
	 (x = iks_find_attrib(y, "xmlns")) != NULL &&
	 strstr(x, "http://jabber.org/protocol/muc") == x)
	  return 1;
     
     /* more conditions here. */
     return 0;
}

static List *xmpp2csp_msg(PGconn *c, iks *node, char domain[], Sender_t *xsender, void **rto, 
			  Octstr **id,  Octstr **err)
{
     char xsdomain[DEFAULT_BUF_LEN];
     char xrdomain[DEFAULT_BUF_LEN];
     char *name = iks_name(node);
     char *from = iks_find_attrib(node, "from");
     char *to = iks_find_attrib(node, "to");
     char *xid = iks_find_attrib(node, "id");
     int is_group = check_if_muc_context(node), rcpt_type = 0;
     void *x;
     char *y;
     void *rcpt_to;
     Sender_t sender;
     void *xfrom;
     Octstr *e = NULL;
     List *lres = gwlist_create();
     
     if ((xfrom = parse_foreign_jid(from ? from : "anon@anon", is_group, xsdomain)) != NULL)
	  sender = csp_msg_new(Sender, NULL,
			       UFV(u, CSP_MSG_TYPE(xfrom), xfrom));
     else {
	  sender = NULL;
	  xsdomain[0] = 0;
     }
     rcpt_to = parse_local_jid(to, &rcpt_type, xrdomain);
     
     *xsender = sender;
     *rto = rcpt_to;
     *id  = xid ? octstr_create(xid) : NULL;
     
     if (rcpt_to == NULL || get_islocal_domain(c, xrdomain) == 0) {
	  e = octstr_format("<error type='cancel'><service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
			       "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'> "
			       "Domain [%s] not handled here</text></error>", xrdomain);
	  info(0, "XMPPhandler: Hmmm, received request for domain [%s], but that domain is not local!",
	       xrdomain);
     } else if (strcasecmp(xsdomain, domain) != 0)
	  e = octstr_format("<error type='cancel'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
			      "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'> "
			      "Sender domain mismatch: Was expecting [%s], received [%s]</text></error>",
			    domain, xsdomain);	  
     else if (strcasecmp(name, "message") == 0) {
	  iks *enode = iks_find(node, "error");
	  iks *snode = (x = iks_find(node, "subject")) ? iks_child(x) : NULL;	  	  
	  iks *xnode = iks_find(node, "x");
	  void *res = NULL;

	  if (enode) { /* a send message response. */

	       char *code = iks_find_attrib(enode, "code");
	       iks *tnode_cdata = (x = iks_find(enode, "text")) ? iks_child(x) : NULL;
	       Octstr *y = octstr_format("Error: %s: %s",
					 to,
					 tnode_cdata ? iks_cdata(tnode_cdata) : "Sending failed");
	       Result_t r = csp_msg_new(Result, NULL,
					FV(code, code ? atoi(code) : 400),
					FV(descr, csp_String_from_bstr(y, Imps_Description)));

	       res = csp_msg_new(SendMessage_Response, NULL, 
				 FV(res, r));	       
	       gwlist_append(lres, res);
	       octstr_destroy(y);
	  } else { /* a real message or group subject/topic change */
	       iks *bnode = (x = iks_find(node, "body")) ? iks_child(x) : NULL;
	       iks *rnode = iks_find(node, "received");
	       iks *inode = xnode ? iks_find(xnode, "invite") : NULL;
	       
	       if (CSP_MSG_TYPE(rcpt_to) == Imps_Group && bnode == NULL && rnode == NULL) {

		    Group_t g = rcpt_to;
		    ScreenName_t sn = g->u.typ == Imps_ScreenName ? g->u.val : NULL;
		    GroupID_t gid = sn ? sn->gid : g->u.val;
		    
		    if (snode != NULL && inode == NULL) { 		    /* group topic change. */
			 Property_t p = csp_msg_new(Property, NULL,
						    FV(name, csp_String_from_cstr("Topic", Imps_Name)),
						    FV(value, csp_String_from_cstr(iks_cdata(snode), Imps_Value)));
			 GroupProperties_t gp = csp_msg_new(GroupProperties,NULL, 
							    FV(plist, gwlist_create_ex(p)));
			 
			 res = csp_msg_new(SetGroupProps_Request, NULL, 
					   FV(gid, csp_msg_copy(gid)), 
					   FV(gprop, gp));
		    } else if (inode != NULL && (y = iks_find_attrib(inode, "to")) != NULL) {
			 iks *rnode = iks_find(inode, "reason");
			 char *reason = rnode && (x = iks_child(rnode)) != NULL ? iks_cdata(x) : NULL;
			 char tmp[DEFAULT_BUF_LEN];
			 void *xto = parse_foreign_jid(y, 0, tmp);
			 Recipient_t r = csp_msg_new(Recipient, NULL,
						     FV(ulist, gwlist_create()));
			 
			 if (xto)
			      gwlist_append(r->ulist, xto);
			 res = csp_msg_new(Invite_Request, NULL,
					   FV(invid, csp_String_from_cstr(xid, Imps_InviteID)),
					   FV(invtype, csp_String_from_cstr("GR", Imps_InviteType)),
					   FV(gid, csp_msg_copy(gid)),
					   FV(inote, reason ? csp_String_from_cstr(reason, Imps_InviteNote) : NULL),
					   FV(rcpt, r));
		    }
	       } else if (bnode && rcpt_to) { /* an actual message. Others we ignore. */
		    void *xto = csp_msg_copy(rcpt_to);
		    int drep = (iks_find(node, "request") != NULL);
		    List *ulist = CSP_MSG_TYPE(rcpt_to) == Imps_User ? gwlist_create_ex(xto) : NULL;
		    List *glist = CSP_MSG_TYPE(rcpt_to) == Imps_Group ? gwlist_create_ex(xto) : NULL;
		    Recipient_t r = csp_msg_new(Recipient, NULL, 
						FV(ulist, ulist),
					   FV(glist, glist));		
		    Octstr *zz = octstr_create(bnode ?  iks_cdata(bnode) : "");			   
		    MessageInfo_t minfo = csp_msg_new(MessageInfo, NULL,
						      FV(ctype, csp_String_from_cstr("text/plain", Imps_ContentType)),
						      FV(sender, csp_msg_copy(sender)),
						      FV(rcpt, r),
						      FV(tdate, time(NULL)),
						      FV(valid, DEFAULT_EXPIRY));


		    if (xid) 
			 CSP_MSG_SET_FIELD(minfo, msgid, csp_String_from_cstr(xid, Imps_MessageID));
		    
		    octstr_convert_from_html_entities(zz); /* unquote html characters. */
		    res = csp_msg_new(SendMessage_Request, NULL,
				      FV(msginfo, minfo),
				      FV(dreport, drep),
				      FV(data, csp_String_from_bstr(zz, Imps_ContentData)));
		    octstr_destroy(zz);
	       } else if (rnode && rcpt_to) { /* delivery report. */
		    void *xto = csp_msg_copy(rcpt_to);
		    List *ulist = CSP_MSG_TYPE(rcpt_to) == Imps_User ? gwlist_create_ex(xto) : NULL;
		    List *glist = CSP_MSG_TYPE(rcpt_to) == Imps_Group ? gwlist_create_ex(xto) : NULL;
		    Recipient_t r = csp_msg_new(Recipient, NULL, 
						FV(ulist, ulist),
						FV(glist, glist));					   
		    MessageInfo_t minfo = csp_msg_new(MessageInfo, NULL,
						      FV(msgid, csp_String_from_cstr(xid, Imps_MessageID)),
						      FV(tdate, time(NULL)),
						      FV(sender, csp_msg_copy(sender)),
						      FV(rcpt, r));
		    Result_t rx = csp_msg_new(Result, NULL, FV(code, 200));

		    res = csp_msg_new(DeliveryReport_Request, NULL,
				      FV(res, rx), FV(dtime, time(NULL)), FV(minfo, minfo));
	       }
	  }
	  if (res)
	       gwlist_append(lres, res);	  
     } else if (strcmp(name, "presence") == 0) {
	  char *type = iks_find_attrib(node, "type");
	  iks *show_node = (x = iks_find(node, "show")) ? iks_child(x) : NULL;
	  iks *status_node = (x = iks_find(node, "status")) ? iks_child(x) : NULL;
	  // iks *prio_node = (x = iks_find(node, "priority")) ? iks_child(x) : NULL;
	  iks *enode = iks_find(node, "error");
	  void *res = NULL;
	  
	  if (enode) { /* we had an error, turn it into a status bit. */
	       int code = (y = iks_find_attrib(enode, "code")) != NULL ? atoi(y) : 400;
	       char *reason = (x = iks_find(enode, "text")) != NULL && 
		    (x = iks_child(x)) != NULL ? iks_cdata(x) : NULL;
	       Result_t r = csp_msg_new(Result, NULL, 
					FV(code, code),
					FV(descr, reason ?
					   csp_String_from_cstr(reason, 
								Imps_Description) : NULL));
	       res = csp_msg_new(Status, NULL, FV(res, r));
	  } else if (type == NULL || 
		     strcmp(type, "unavailable") == 0) { /* presence update or enter group. */
	       if (rcpt_to && CSP_MSG_TYPE(rcpt_to) == Imps_Group) { /* enter or leave. */
		    if (CSP_MSG_TYPE(xfrom) != Imps_User) {
			 error(0, "xmpphandler: Received %sGroup request, but sender is not a user!", 
			       type == NULL ? "Join" : "Leave");
			 e = octstr_format("<error type='cancel'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
					   "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'> "
					   "Invalid sender [%s] </text></error>", from);
		    } else if (((Group_t)rcpt_to)->u.typ != Imps_ScreenName) {
			 error(0, "xmpphandler: Received %sGroup request, but recipient is not a screen name!", 
			       type == NULL ? "Join" : "Leave");			 
			 e = octstr_format("<error type='cancel'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
					   "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'> "
					   "Invalid recipient [%s], must be a screen name/alias</text></error>", from);
		    } else {
			 ScreenName_t sn = ((Group_t)rcpt_to)->u.val;
			 GroupID_t gid = sn->gid;
			 /* XXX join must send presence broadcast to other members. */
			 res = (type == NULL) ? (void *)csp_msg_new(JoinGroup_Request, NULL,
								    FV(gid, csp_msg_copy(gid)),
								    FV(sname, csp_msg_copy(sn)),
								    FV(snotify, 1))
			      : csp_msg_new(LeaveGroup_Request, NULL, FV(gid, csp_msg_copy(gid)));			 
		    }
	       } else if (CSP_MSG_TYPE(xfrom) == Imps_Group) { /* group change notice. */
		    iks *inode = iks_find(node, "item");
		    char *role = inode ? iks_find_attrib(node, "role") : NULL;
		    iks  *xnode = iks_find(node, "x");
		    Group_t g = xfrom;
		    ScreenName_t sn = g->u.typ == Imps_ScreenName ? g->u.val : NULL;
		    GroupID_t gid = sn ? sn->gid : g->u.val;
		    
		    if (xnode && (y = iks_find_attrib(xnode, "xmlns")) != NULL && 
			strcasecmp(y, "http://jabber.org/protocol/muc#user") == 0) {
			 UserList_t ul = sn ? csp_msg_new(UserList, NULL, 
							  FV(slist, gwlist_create_ex(csp_msg_copy(sn)))) : NULL;
			 Joined_t j = (role && strcasecmp(role, "none") != 0) ? 
			      csp_msg_new(Joined, NULL, FV(ulist, ul)) : NULL;
			 Left_t l = (role == NULL || strcasecmp(role, "none") == 0) ? 
			      csp_msg_new(Left, NULL, FV(ulist, ul)) : NULL;
			 
			 res = csp_msg_new(GroupChangeNotice, NULL,
					   FV(gid, csp_msg_copy(gid)),
					   FV(joined, j),
					   FV(left, l));		    
		    }
	       } else {
		    UserID_t u = ((User_t)xfrom)->user;
		    /*		    int prio = prio_node ? atoi(iks_cdata(prio_node)) : 0; */
		    char *xuser = csp_String_to_cstr(u);

		    char *status = show_node ? iks_cdata(show_node) : NULL;
		    char *xstatus = type ? "NOT_AVAILABLE" :  /* we are logging off. */
			 ((status == NULL || strcmp(status, "chat") == 0) ? "AVAILABLE" : "DISCREET");
		    char *xtxt = status_node ? iks_cdata(status_node) : (status ? status : ""); /* XX do better conversion.*/
		    int is_online = (type) ? 0 : 1;
		    OnlineStatus_t os = csp_msg_new(OnlineStatus, NULL,
						    FV(qual, 1),
						    FV(pvalue, csp_String_from_cstr(is_online ? "T" : "F", 
										    Imps_PresenceValue)));
		    ClientInfo_t cinfo = csp_msg_new(ClientInfo, NULL,
						     FV(qual, 1),
						     FV(ctype, csp_String_from_cstr("COMPUTER", Imps_ClientType)));
		    
		    UserAvailability_t ua = csp_msg_new(UserAvailability, NULL,
							FV(qual, 1), 
							FV(pvalue, csp_String_from_cstr(xstatus, 
											Imps_PresenceValue)));
		    StatusText_t st = (xtxt && strlen(xtxt) > 0) ? csp_msg_new(StatusText, NULL,
									       FV(qual, 1), 
									       FV(pvalue, csp_String_from_cstr(xtxt, 
													       Imps_PresenceValue))) :
		      NULL;	       
		    Status_t xcstatus = csp_msg_new(Status, NULL, FV(_content, octstr_imm("OPEN")));
		    CommC_t cc = csp_msg_new(CommC, NULL,
					     FV(cap, csp_String_from_cstr("IM", Imps_Cap)),
					     FV(status, xcstatus),
					     FV(contact, csp_String_from_cstr(xuser, Imps_Contact)),
					     FV(note, csp_String_from_cstr("IM online", Imps_Note)));
		    CommCap_t ccp = csp_msg_new(CommCap, NULL,
						FV(commc, gwlist_create_ex(cc)),
						FV(qual, 1));
		    PresenceSubList_t p = csp_msg_new(PresenceSubList, 
						      octstr_imm("http://www.openmobilealliance.org/DTD/IMPS-PA1.3"),
						      FV(ostatus, gwlist_create_ex(os)),
						      FV(cinfo, gwlist_create_ex(cinfo)),
						      FV(status_txt, st),
						      FV(avail, ua),
						      FV(commcap, gwlist_create_ex(ccp)));
		    _User_Presence_t up = csp_msg_new(_User_Presence, NULL,
						      FV(user, csp_msg_copy(u)));
		    Presence_t px = csp_msg_new(Presence, NULL, UFV(pres, Imps__User_Presence, up),
					   FV(pslist, gwlist_create_ex(p)));
		    
		    res = csp_msg_new(PresenceNotification_Request, NULL,
				      FV(plist, gwlist_create_ex(px)));
	       }
	  } else if (strcmp(type,"subscribe") == 0) { /* an attempt to subscribe. */
	       User_t u = (CSP_MSG_TYPE(rcpt_to) == Imps_User) ? csp_msg_copy(rcpt_to) : NULL;
	       if (u)  {
		    PresenceSubList_t ps = csp_msg_new(PresenceSubList, NULL,
						       FV(ostatus, gwlist_create()),
						       FV(cinfo, gwlist_create()),
						       FV(status_txt, NULL),
						       FV(avail, NULL), 
						       FV(status_mood, NULL)); /* csp processor uses only bit flags, so NULLs OK. */
		    /* XXX trans needs to notice successful subscribe and report it. */
		    res = csp_msg_new(SubscribePresence_Request, NULL,
				      FV(ulist, gwlist_create_ex(u)),
				      FV(plist, ps));
	       }  else 
		    e = octstr_format("<error type='cancel'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
					  "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'> "
					       "Request for presence of non-user: [%s]</text></error>", to);	  	       
	  } else if (strcmp(type,"unsubscribe") == 0 || /* an attempt to unsubscribe. */
		     strcmp(type, "unsubscribed") == 0) { 
	       User_t u = (CSP_MSG_TYPE(rcpt_to) == Imps_User) ? csp_msg_copy(rcpt_to) : NULL;
	       
	       if (u)  /* XXX trans needs to notice successful unsubscribe and report it. */
		    res = csp_msg_new(UnsubscribePresence_Request, NULL,
				      FV(ulist, gwlist_create_ex(u)));
	       else 
		    e = octstr_format("<error type='cancel'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
					  "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'> "
					  "Unsubscribe presence of non-user: [%s]</text></error>", to);	  	       
	  } else if (strcmp(type, "probe") == 0) { /* presence request. */
	       User_t u = (CSP_MSG_TYPE(rcpt_to) == Imps_User) ? csp_msg_copy(rcpt_to) : NULL;
	       if (u)  {
		    PresenceSubList_t ps = csp_msg_new(PresenceSubList, 
						       octstr_imm("http://www.openmobilealliance.org/DTD/IMPS-PA1.3"),
						       FV(ostatus, gwlist_create()),
						       FV(cinfo, gwlist_create()),
						       FV(status_txt, NULL),
						       FV(avail, NULL)); /* csp processor uses only bit flags, so NULLs OK. */	    
		    _User_List_t ul = csp_msg_new(_User_List, NULL, FV(ulist, gwlist_create_ex(u)));
		    res = csp_msg_new(GetPresence_Request, NULL,
				      UFV(u, Imps__User_List, ul),
				      FV(pslist, ps));
	       }  else 
		    e = octstr_format("<error type='cancel'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
					  "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'> "
					  "Request for presence of non-user: [%s]</text></error>", to);	  	       
	  }  /* else  we ignore type = susbcribed|error because reliable translation is 
	      * tricky at best.
	      */
	  if (res)
	       gwlist_append(lres, res);
     } else if (strcmp(name, "iq") == 0 && 
		(x = iks_find(node, "query")) != NULL && 
		(y = iks_find_attrib(x, "xmlns")) != NULL && 
		strcmp(y, "http://jabber.org/protocol/muc#admin") == 0) { /* group management. */
	  char *xtyp = iks_find_attrib(node, "type");
	  int typ = strcasecmp(xtyp, "get") == 0 ? XMPP_IQ_GET : (strcasecmp(xtyp, "set") == 0 ? XMPP_IQ_SET :
								  XMPP_IQ_RESULT);
	  iks *xchild = iks_first_tag(x);
	  
	  if (CSP_MSG_TYPE(rcpt_to) != Imps_Group &&
	      (typ == XMPP_IQ_SET || typ == XMPP_IQ_GET)) {
	       error(0, "xmpphandler: Received Group management request, but recipient is not a group!");
	       e = octstr_format("<error type='cancel'><forbidden xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
				 "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'> "
				 "Invalid recipient [%s] </text></error>", to);	       
	  } else if (typ == XMPP_IQ_GET) { /* member request or banlist request. */
	       Group_t g = rcpt_to;
	       ScreenName_t sn = g->u.typ == Imps_ScreenName ? g->u.val : NULL;
	       GroupID_t gid = sn ? sn->gid : g->u.val;

	       while (xchild) {
		    if (strcmp(iks_name(xchild), "item") == 0) {
			 void *res = NULL;
			 char *mtype = iks_find_attrib(xchild, "affiliation");		
			 if (mtype == NULL || strcasecmp(mtype, "outcast") != 0) {
			      Value_t v = csp_String_from_cstr(mtype ? mtype : "member", Imps_Value);
			      res = csp_msg_new(GetGroupMembers_Request, NULL, FV(gid, csp_msg_copy(gid)),
						FV(mtype, v));	 
			 } else  /* get banned. */
			      res = csp_msg_new(RejectList_Request, NULL, FV(gid, csp_msg_copy(gid)));	 
			 
			 if (res)
			      gwlist_append(lres, res);
		    }
		    xchild = iks_next_tag(xchild);
	       }	       
	  } else if (typ == XMPP_IQ_SET) { /* memberaccess or ban request. */
	       /* XXX we don't (yet) support these. */

	  }
     }
     
     if (e) {
	  *err = (from) ? 
	       octstr_format("<%s  xmlns='jabber:server' to='%s' type='error'>%S</%s>", name, from, e, name) : 
	       octstr_format("<%s  xmlns='jabber:server' type='error'>%S</%s>", name, from, e, name);
	  octstr_destroy(e);
     }
     if (gwlist_len(lres) == 0) {
	  gwlist_destroy(lres, _csp_msg_free);
	  lres = NULL;
     }
     return lres;
}

static void append_stanzas_for_rcpt(Octstr *res, const char *tag, char *attribs, char *id,
				    char *attrib_for_grp,
				    char *from, Recipient_t r, Octstr *body)
{
     int i, n;
     User_t u;
     Group_t g;
     
     /* queue to send to groups and users. */
     for (i = 0, n = gwlist_len(r->ulist); i<n; i++)
	  if ((u = gwlist_get(r->ulist, i)) != NULL) {
	       Octstr *to = make_foreign_jid(u);			 
	       octstr_format_append(res, "<%s  xmlns='jabber:server'  to='%S' from='%s' %s id='%s'>"
				    "%S"
				    "</%s>",
				    tag,
				    to ? to : octstr_imm(""),
				    from ? from : "",
				    attribs ? attribs : "",
				    id,
				    body,
				    tag);
	       octstr_destroy(to);
	  }
     
     for (i = 0, n = gwlist_len(r->glist); i<n; i++)
	  if ((g = gwlist_get(r->glist, i)) != NULL) {
	       Octstr *to = make_foreign_jid(g);	
	       octstr_format_append(res, "<%s  xmlns='jabber:server'   to='%S' from='%s' %s id='%S'>"
				    "%S"
				    "</%s>",
				    tag,
				    to ? to : octstr_imm(""),
				    from ? from : "",
				    attrib_for_grp && (g->u.typ == Imps_GroupID) ?
				    attrib_for_grp : (attribs ? attribs : ""),
				    id,
				    body,
				    tag);		 
	       octstr_destroy(to);
	  }
}

/* we ignore error results for certain messages. */
static int ignore_error_for_msg_type(int type)
{

     switch(type) {
     case Imps_UnsubscribePresence_Request:
	  return 1;
     default:
	  return 0;
     }
}

static Octstr *make_result_stanza_from_code(PGconn *c, int code, char *descr, void *orig_msg, 
					    char *orig_id,
					    char *tag, char *from, 
					    List *rcptlist)
{
     Octstr *res;
     if (!CSP_SUCCESS(code)) {
	  Octstr *x = octstr_format("<error type='cancel'>"
				    "<service-unavailable xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/>"
				    "<text xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'> "
				    "%d: %s</text></error>", code,
				    descr);
	  
	  if (orig_msg && 
	      ignore_error_for_msg_type(CSP_MSG_TYPE(orig_msg)))
	       res = NULL;
	  else if (orig_msg)
	       res = csp2xmpp_msg(c, orig_msg, NULL, from, orig_id, NULL, x);
	  else if (tag)
	    res = octstr_format("<%s type='error' to='%s'>%S</%s>", tag, from, x, tag);
	  else 
	       res = NULL;
	  octstr_destroy(x);
     } else {
	  SSPRecipient_t *sr = gwlist_len(rcptlist) > 0 ? gwlist_get(rcptlist, 0) : NULL;
	  void  *xto = sr ? sr->to : NULL;
	  Octstr *to = xto ? make_foreign_jid(xto) : NULL;

	  if (sr) sr->sent = 1;
	  res = NULL;
	  if (to && orig_msg) { /* handle ones which return status. */
	       if (CSP_MSG_TYPE(orig_msg) == Imps_SubscribePresence_Request) 
		    res = octstr_format("<presence   "
					"from='%s' to='%S' type='subscribed'/>", 
					from, to);	       
	       else if (CSP_MSG_TYPE(orig_msg) == Imps_UnsubscribePresence_Request) 
		    res = octstr_format("<presence   "
					" from='%s' to='%S' type='unsubscribed'/>", 
					from, to);	       
	  } 
	  octstr_destroy(to);
     }
     
     return res;
}

static Octstr *make_result_stanzas(PGconn *c, Result_t r, void *orig_msg, 
				   char *orig_id,
				   char *tag, char *from, 
				   List *rcptlist)
{
     DetailedResult_t dr;
     int i, n;
     Octstr *res = NULL;
     
     if (gwlist_len(r->drlist) == 0) 
	  res = make_result_stanza_from_code(c, r->code, 
					     r->descr ? csp_String_to_cstr(r->descr) : "",
					     orig_msg, orig_id, tag, from, rcptlist);
     else 
	  for (i = 0, n = gwlist_len(r->drlist); i<n; i++)
	       if ((dr = gwlist_get(r->drlist, i)) != NULL) {
		    Octstr *x;
		    x = make_result_stanza_from_code(c, dr->code, 
						    dr->descr ? csp_String_to_cstr(dr->descr) : "",
						    orig_msg, orig_id, tag, from, rcptlist);
		    if (x) {
			 if (res == NULL)
			      res = x;			
			 else {
			      octstr_append(res, x);
			      octstr_destroy(x);			      
			 }
		    }
	       }
     return res;
}

/* append from a list of Presence_t */
static void append_presence_list(Octstr *res, List *pslist, List *rcptlist)
{
     Presence_t p;
     int i, n, j, m;
     UserID_t ux;
     PresenceSubList_t psl;
     
     for (i = 0, n = gwlist_len(pslist); i<n; i++) 
	  if ((p = gwlist_get(pslist, i)) == NULL ||
	      p->pres.typ != Imps__User_Presence  ||  /* only user presence possible here.*/
	      p->pres.val == NULL || 
	      (ux = ((_User_Presence_t)p->pres.val)->user) == NULL)
	       continue;
	  else
	       for (j = 0, m = gwlist_len(p->pslist); j<m; j++) 
		    if ((psl = gwlist_get(p->pslist, j)) != NULL) { /* go through each presence sublist. */
			 OnlineStatus_t os;
			 int k, l;
			 char *status_txt = NULL, *show = NULL;
			 int i, n;
			 SSPRecipient_t *sr;
			 int online = 0, hidden = 0;
			 User_t user = csp_msg_new(User, NULL,
						   FV(user, csp_msg_copy(ux)));
			 Octstr *xfrom = make_local_jid(user);
			 Octstr *xto;
			 
			 /* pass through list, look for:
			  * - availability
			  * - status 
			  * - show
			  *
			  * First we pick up the data for the <show> and <status> elements. 
			  */
			 if (csp_msg_field_isset(psl, avail) && 
			     psl->avail && 
			     psl->avail->qual && psl->avail->pvalue) {
			      char *x = csp_String_to_cstr(psl->avail->pvalue);
			      
			      if (strcasecmp(x, "AVAILABLE") == 0)
				   show = "chat";
			      else if (strcasecmp(x, "DISCREET") == 0)
				   show = "dnd";
			      else if (strcasecmp(x, "NOT_AVAILABLE") == 0) {
				   hidden = 1;
				   show = NULL;
			      } else 
				   show = "xa";					
			 } else 
			      show = NULL;
			 
			 if (csp_msg_field_isset(psl, status_txt) && 
			     psl->status_txt && psl->status_txt->qual && 
			     psl->status_txt->pvalue) 
			      status_txt = csp_String_to_cstr(psl->status_txt->pvalue);		
			 else 
			      status_txt = "On mobile with Baraza (www.baraza.im)";
			 
			 /* Next, pass through each of the availabilities, pick up avail 
			  * status, and report it 
			  */
			 if (csp_msg_field_isset(psl, ostatus))
			      for (k = 0, l = gwlist_len(psl->ostatus); k<l; k++)
				   if ((os = gwlist_get(psl->ostatus, k)) != NULL && 
				       os->qual && os->pvalue && 
				       strcasecmp(csp_String_to_cstr(os->pvalue), "T") == 0)
					online = 1;
			 
			 /* build for each of the recipients. */
			 for (i = 0, n = gwlist_len(rcptlist); i<n; i++) 
			      if ((sr = gwlist_get(rcptlist, i)) != NULL && 
				  (xto = make_foreign_jid(sr->to)) != NULL) {
				   sr->sent = 1; /* mark as sent. */
				   octstr_format_append(res, 
							"<presence    "
							" from='%S' to='%S'",
							xfrom, xto);
				   if (online && !hidden) {
					octstr_append_cstr(res, ">"); 
					if (show)
					     octstr_format_append(res, "<show>%s</show>", show);
					if (status_txt)
					     octstr_format_append(res, "<status>%s</status>", 
								  status_txt);
					octstr_append_cstr(res, "<priority>0</priority>");
					octstr_append_cstr(res, "</presence>");
				   } else 
					octstr_append_cstr(res, " type='unavailable'/>");
				   octstr_destroy(xto);
			      }
			 octstr_destroy(xfrom);
			 csp_msg_free(user);		    				   
		    }	 	       	                 
}
/* To call this macro incorrect is an understatement! */
#define APPEND_GROUP_USER_LIST(str, ulist, af) do {	     \
	  int _i, _n = gwlist_len(ulist);				\
	  void *_u;							\
	  for (_i = 0; _i<_n; _i++)					\
	       if ((_u = gwlist_get((ulist), _i)) != NULL) {		\
		    Octstr *_xto = make_foreign_jid(_u); /* XXX not strictly correct. */ \
		    octstr_format_append((str), "<item affiliation='%s' jid='%S' " \
					 "nic='blah'/>", (af), _xto);	\
		    octstr_destroy(_xto);				\
	       }							\
     } while(0)

/* rcptlist will be list of recipients. On reply path, will be set by caller to original sender. */

static Octstr *csp2xmpp_msg(PGconn *c, void *msg, void *orig_msg, char *from, char *orig_id,
			    List *rcptlist, Octstr *err)
{
     Octstr *res = NULL;
     char *p, tmpfrom[DEFAULT_BUF_LEN] = "", *bare_from = tmpfrom;
          
     gw_assert(msg);

     
     if (from && (p = strrchr(from, '/')) != NULL)
	  strncpy(bare_from, from, p-from);
     else if (from)
	  bare_from = from;

     switch(CSP_MSG_TYPE(msg)) {
     default: /* do nothing for most. */
	  
	  break;
     case Imps_SendMessage_Request:
	  if (msg && ((SendMessage_Request_t)msg)->msginfo) {
	       SendMessage_Request_t sm = msg;
	       MessageInfo_t minfo = sm->msginfo;
	       Octstr *body;
	       Recipient_t r = minfo->rcpt;
	       char *msgid = minfo->msgid ? csp_String_to_cstr(minfo->msgid) : "000";
	       char *dlr = (err == NULL && sm->dreport) ? "<request xmlns='urn:xmpp:receipts'/>" : "";

	       if (minfo->ctype && 
		   strcasestr(csp_String_to_cstr(minfo->ctype), "text/plain") == NULL)  /* Not text, put to
											 * SC server.
											 */
		    body = sc_add_content(c, csp_String_to_cstr(minfo->ctype), 
				   minfo->enc ? csp_String_to_cstr(minfo->enc) : NULL,
				   sm->data ? csp_String_to_cstr(sm->data) : "",
				   sm->data ? csp_String_len(sm->data) : 0);
	       else {
		    body = csp_String_to_bstr(sm->data);
		    if (minfo->enc && 
			(strcasecmp(csp_String_to_cstr(minfo->enc), "base64") == 0))
			 octstr_base64_to_binary(body);

	       }
	       octstr_convert_to_html_entities(body); /* quote html characters. */	       
	       
	       if (err != NULL) 
		    res = octstr_format("<message xmlns='jabber:server' "
					" to='%s' "
					" type='error' id='%S'> "
					"<body>%S%S</body>"
					"</message>",					
					from ? from : "",
					msgid,
					body,
					err);
	       else {
		    Octstr *x = octstr_format("<body>%S</body>%s", body, dlr);
		    
		    res = octstr_create("");
		    
		    /* queue to send to groups and users. */		    
		    append_stanzas_for_rcpt(res, "message", "type='chat'", msgid, "type='groupchat'", 
					    from, r, x);
		    octstr_destroy(x);
	       }
	       octstr_destroy(body);
	  }
	  break;	  
     case Imps_SendMessage_Response:
	  if (((SendMessage_Response_t)msg)->res && 
	      ((SendMessage_Response_t)msg)->res->code != 200) {
	       SendMessage_Response_t sr = msg;

	       res = make_result_stanzas(c, sr->res, NULL, 
					 orig_id,
					 "message", from, rcptlist);
	  } /* else ignore success. */
	  
	  break;
     case Imps_Status:
	  msg = ((Status_t)msg)->res;
	  /* fall through. */
     case Imps_Result:
	  if (orig_msg)
	       res = make_result_stanzas(c, msg, orig_msg, orig_id, NULL, from, rcptlist);
	  else 
	       error(0, "csp2xmpp: asked to convert Result record without orig msg");
	  break;
     case Imps_Invite_Request:
	  if (err != NULL) 
	       res = octstr_format("<message  xmlns='jabber:server' "
				   " to='%s' "
				   " type='error'> "
				   "%S"
				   "</message>",					
				   from ? from : "",
				   err);
	  else  {
	       int i, n;
	       Invite_Request_t inv = msg;
	       char *inote = inv->inote ? csp_String_to_cstr(inv->inote) : "";
	       char *x = inv->invtype ? csp_String_to_cstr(inv->invtype) : "";
	       User_t u;
	       
	       /* we only support GR, GM. PR doesn't seem to have a good equivalent. */
	       if (strcasecmp(x, "GR") == 0 ||
		   strcasecmp(x, "GM") == 0) {
		    Octstr *xgrp = inv->gid ?  make_local_jid(inv->gid) : octstr_imm("nogroup@nogroup");
		    Recipient_t r = inv->rcpt;
		    res = octstr_create("");
		    if (r)
			 for (i = 0, n = gwlist_len(r->ulist); i<n; i++)
			      if ((u = gwlist_get(r->ulist, i)) != NULL) {
				   Octstr *to = make_foreign_jid(u);			 			   
				   octstr_format_append(res,"<message   xmlns='jabber:server' "
							"from='%s' to='%S'>"
							"<x xmlns='http://jabber.org/protocol/muc#user'>"
							"<invite to='%S'>"
							"<reason>%s</reason>"
							"</invite>"
							"</x>"
							"</message>",
							from ? from : "", 
							xgrp, to, inote);
				   octstr_destroy(to);
			      }
		    octstr_destroy(xgrp);
	       } else if (strcasecmp(x, "PR") == 0) { /* presence invite */
		    Recipient_t r = inv->rcpt;
		    User_t u;
		    res = octstr_create("");
		    if (r)
			 for (i = 0, n = gwlist_len(r->ulist); i<n; i++)
			      if ((u = gwlist_get(r->ulist, i)) != NULL) {
				   Octstr *to = make_foreign_jid(u);			 			   
				   octstr_format_append(res, 
							"<presence  xmlns='jabber:server'  "
							"to='%S' from='%s' type='subscribe'/>", 
							to, bare_from);				   
				   octstr_destroy(to);
			      }
	       } else 
		    warning(0, "csp2xmpp: unsupported invite type: %s", (char *)x);
	  }
	  
	  break;
     case Imps_SubscribePresence_Request: 
	  if (err != NULL)
	       res = octstr_format( "<presence  xmlns='jabber:server' "
				    "to='%s' type='error'>%S</presence>", 
				    from ? from : "", err);
	  else if (from) {
	       int i, n;
	       void *u;
	       SubscribePresence_Request_t sp = msg;
	       List *ul = sp->uidlist ? sp->uidlist->ulist : sp->ulist; /* difference between 1.3 and earlier... */
	       
	       res = octstr_create("");
	       
	       for (i = 0, n = gwlist_len(ul); i<n; i++)
		    if ((u = gwlist_get(ul, i)) != NULL) {
			 void *ux = (CSP_MSG_TYPE(u) == Imps_User) ? ((User_t)u)->user : u;
			 Octstr *to = make_foreign_jid(ux);
			 octstr_format_append(res, 
					      "<presence  xmlns='jabber:server'  "
					      "to='%S' from='%s' type='subscribe'/>", 
					      to, bare_from);
			 octstr_destroy(to);
		    }	  
	  }
	  break;

     case Imps_UnsubscribePresence_Request: 
	  if (err != NULL && from)
	       res = octstr_format( "<presence  xmlns='jabber:server' to='%s' type='error'>%S</presence>", from, err);
	  else if (from) {
	       int i, n;
	       void *u;
	       UnsubscribePresence_Request_t sp = msg;
	       List *ul = sp->uidlist ? sp->uidlist->ulist : sp->ulist; /* difference between 1.3 and earlier... */
	       
	       res = octstr_create("");
	       
	       for (i = 0, n = gwlist_len(ul); i<n; i++)
		    if ((u = gwlist_get(ul, i)) != NULL) {
			 void *ux = (CSP_MSG_TYPE(u) == Imps_User) ? ((User_t)u)->user : u;
			 Octstr *to = make_foreign_jid(ux);
			 octstr_format_append(res, 
					      "<presence  xmlns='jabber:server' "
					      "to='%S' from='%s' type='unsubscribe'/>", 
					      to, bare_from);
			 octstr_destroy(to);
		    }	  
	  }
	  break;
     case Imps_PresenceNotification_Request: 
	  if (err == NULL) { /* can't have an error on a notify. */
	       PresenceNotification_Request_t pr = msg;	       

	       res = octstr_create("");
	       append_presence_list(res, pr->plist, rcptlist);
	  }
	  break;
     case Imps_GetPresence_Request:
	  if (err)
	       res = octstr_format( "<presence  xmlns='jabber:server' "
				    " to='%s' type='error'>%S</presence>", from, err);
	  else  {
	       GetPresence_Request_t gp = msg;
	       int i, n;
	       List *ul;
	       void *u;
	       Octstr *xto;
	       if (gp->u.typ == Imps_UserIDList)
		    ul = gp->u.val ? ((UserIDList_t)gp->u.val)->ulist : NULL;
	       else if (gp->u.typ == Imps__User_List)
		    ul = gp->u.val ? ((_User_List_t)gp->u.val)->ulist : NULL; /* list of User_t. */
	       else 
		    ul = NULL;

	       res = octstr_create("");
	       for (i = 0, n = gwlist_len(ul); i < n; i++)
		    if ((u = gwlist_get(ul, i)) != NULL) { 
			 void *ux = (CSP_MSG_TYPE(u) == Imps_User) ? ((User_t)u)->user : u;
			 if ((xto = make_foreign_jid(ux)) == NULL) 
			      continue;
			 
			 octstr_format_append(res, "<presence  xmlns='jabber:server' "
					      " to='%S' from='%s' type='probe'/>",
					      xto, bare_from);
			 octstr_destroy(xto);
		    }
	  }
	  break;
     case Imps_GetPresence_Response:
	  if (((GetPresence_Response_t)msg)->res &&
	      ((GetPresence_Response_t)msg)->res->code != 200) /* We have some errors. */
	       res = make_result_stanzas(c, ((GetPresence_Response_t)msg)->res, NULL, 
					 orig_id, "presence", from, rcptlist);

	  if (((GetPresence_Response_t)msg)->plist) {
	       GetPresence_Response_t gp = msg;
	       if (res == NULL) 
		    res = octstr_create("");
	       append_presence_list(res, gp->plist, rcptlist);	       
	  }
	  break;
     case Imps_DeliveryReport_Request:
	  if (((DeliveryReport_Request_t)msg)->res && 
	      ((DeliveryReport_Request_t)msg)->res->code == 200) { /* success.  what about fail??*/
	       DeliveryReport_Request_t drl = msg;
	       MessageInfo_t minfo = drl->minfo;
	       char *msgid = minfo && minfo->msgid ? csp_String_to_cstr(minfo->msgid) : "000";
	       
	       res = octstr_create("");	       
	       append_stanzas_for_rcpt(res, "message", NULL, msgid, NULL, from, minfo->rcpt, 
				       octstr_imm("<received xmlns='urn:xmpp:receipts'/>"));	       
	  } else 
	       error(0, "csp2xmpp: Hmmm DeliveryReport Request with an error??");
	  break;
     case Imps_JoinGroup_Request:
       if (err == NULL) {
	    JoinGroup_Request_t jg = msg;
	    if (jg->sname) {
		 Octstr *xto = make_foreign_jid(jg->sname);
		 
		 res = octstr_format("<presence  xmlns='jabber:server' from='%s' to='%S'>"
				     "<x = xmlns='http://jabber.org/protocol/muc'/>"
				     "</presence>",
				     from, xto);
		 octstr_destroy(xto);
	    }
       }
       break;
     case Imps_LeaveGroup_Request:
	  break; /* we don't know how to handle! We have no screenname. */
     case Imps_GetGroupMembers_Request:
	  if (err == NULL) {
	       GetGroupMembers_Request_t gm = msg;
	       Octstr *xto = make_foreign_jid(gm->gid);
	       res = octstr_format("<iq  xmlns='jabber:server' from='%s'id='0001' "
				   "to='%S' type='get'> "
				   "<query xmlns='http://jabber.org/protocol/muc#admin'>"
				   "<item affiliation='member'/>"
				   "</query>"
				   "</iq>",
				   from, xto);
	       octstr_destroy(xto);
	  } else 
	       res = octstr_format("<iq  xmlns='jabber:server' 'id='0001' "
				   "to='%s' type='error'> "
				   "<query xmlns='http://jabber.org/protocol/muc#admin'>"
				   "<item affiliation='member'/>"
				   "</query>%S"
				   "</iq>",
				   from, err);
	  break;
     case Imps_GetGroupMembers_Response:
	  if (err)
	       res = octstr_format("<iq  xmlns='jabber:server' 'id='%s' "
				   "to='%s' type='error'> "
				   "<query xmlns='http://jabber.org/protocol/muc#admin'>"
				   "<item affiliation='member'/>"
				   "</query>%S"
				   "</iq>",
				   orig_id ? orig_id : "0001",
				   from, err);
	  else {
	       GetGroupMembers_Response_t gm = msg;
	       SSPRecipient_t *sr = gwlist_len(rcptlist) > 0 ? gwlist_get(rcptlist, 0) : NULL;
	       void *to = sr ? sr->to : NULL;
	       Octstr *xto = to ? make_foreign_jid(to) : NULL;
	       
	       if (xto) {
		    res = octstr_format("<iq  xmlns='jabber:server' from='%s' id='%s' "
					"to='%S'  type='result'>"
					"<query xmlns='http://jabber.org/protocol/muc#admin'>",
					from, orig_id ? orig_id : "0001");
		    
		    if (gm->admin && gm->admin->ulist)
			 APPEND_GROUP_USER_LIST(res, gm->admin->ulist->ulist, "admin");
		    if (gm->mod && gm->mod->ulist)
			 APPEND_GROUP_USER_LIST(res, gm->mod->ulist->ulist, "moderator");
		    if (gm->ulist)
			 APPEND_GROUP_USER_LIST(res, gm->ulist->ulist, "member");
		    octstr_append_cstr(res, "</query></iq>");
	       }
	       
	  }
	  break;
     }

     return res;
}

static int xmpp_msg_send(PGconn *c, EmptyObject_t msg, List *rcptlist,  Sender_t sender, 
			 char *domain, int64_t tid)
{
     XMPPConn_t *xconn = NULL;
     int ret = SSP_OK;
     Octstr *from_domain = sender ?  get_sender_domain(sender) : octstr_create(mydomain);
     Octstr *from = sender ? make_local_jid(sender->u.val) : octstr_imm("");
     Octstr *res = csp2xmpp_msg(c, msg, NULL, octstr_get_cstr(from), NULL, rcptlist, NULL);
     
     if (octstr_len(res) > 0 &&  /* something to send. */
	 (ret = get_connection(domain, 
			       octstr_get_cstr(from_domain), &xconn, XMPP_CONNECTED)) == SSP_OK) {

	  /* get_connection already grabbed the lock. */
	  iks_send_raw(xconn->prs, octstr_get_cstr(res));

	  return_connection(xconn);
     }

     octstr_destroy(from);
     octstr_destroy(res);
     octstr_destroy(from_domain);

     return ret;
}

static void xmpp2csp_trans(PGconn *c, iks *node, XMPPConn_t *xconn)
{

     Sender_t sender  = NULL;
     void *to = NULL;
     Octstr *id = NULL, *err  = NULL;
     List *mlist;
     void *msg;
     char *domain = xconn->domain;
     Octstr *out = octstr_create("");
     
     mlist = xmpp2csp_msg(c, node, domain, &sender, &to, &id, &err);
     if (err)
	  octstr_append(out, err);
     else if (mlist)
	  while  ((msg = gwlist_extract_first(mlist)) != NULL) {
	       Octstr *xuserid = NULL, *xclientid = NULL;	  
	       Recipient_t rto = NULL, *rto_ptr = NULL;
	       List *el = NULL;
	       Octstr *xres = NULL;
	       Octstr *res;
	       int dont_send = 0;
	       int mtype;
	       
	       if (sender && 			 
		   sender->u.typ == Imps_User) {
		    User_t u = sender->u.val;
		    ApplicationID_t appid = (u->u.typ == Imps_ApplicationID) ? u->u.val : NULL;
		    ClientID_t clnt = (u->u.typ == Imps_ApplicationID) ? NULL : u->u.val;
		    
		    xclientid = make_clientid(clnt, appid);
		    xuserid = csp_String_to_bstr(u->user);			 
	       } 
	       
	       switch (mtype = CSP_MSG_TYPE(msg)) {
		    /* handle the ones that must be handled (queued) from here. */
	       case Imps_InviteUser_Response: 
		    rto_ptr = &((InviteUser_Response_t)msg)->rcpt;
		    goto process;
	       case Imps_DeliveryReport_Request:
		    if (((DeliveryReport_Request_t)msg)->minfo)
			 rto_ptr = &((DeliveryReport_Request_t)msg)->minfo->rcpt;
		    goto process;
	       case Imps_Result: /* can this occur on this interface?? */			 
		    if (((Result_t)msg)->code == 200) /* ignore success :-) */
			 dont_send = 1;
		    else { 	       /* change to status. */
			 msg = (void *)csp_msg_new(Status, NULL, FV(res, msg));
			 mtype = Imps_Status;
		    }
		    goto process;
	       case Imps_PresenceNotification_Request:
	       case Imps_GetPresence_Response:
	       case Imps_JoinGroup_Response:
	       case Imps_LeaveGroup_Response:
	       case Imps_GetGroupMembers_Response:
	       case Imps_GetJoinedUsers_Response:
	       case Imps_GetGroupProps_Response:
	       case Imps_RejectList_Response:
	       case Imps_GroupChangeNotice:
	       case Imps_SubscribeGroupNotice_Response: 
		    
	       process:
		    if (rto_ptr) 
			 rto = csp_msg_copy(*rto_ptr);
		    else if (to) {
			 rto = csp_msg_new(Recipient, NULL,
					   FV(ulist, gwlist_create()),
					   FV(glist, gwlist_create())
			      );	       
			 if (CSP_MSG_TYPE(to) == Imps_User)
			      gwlist_append(rto->ulist, csp_msg_copy(to));
			 else 
			      gwlist_append(rto->glist, csp_msg_copy(to));
		    }
		    /* queue it and send no reply. */
		    if (!dont_send && rto && sender)
			 xres = queue_msg(c, sender, -1, xuserid,
					  xclientid ? octstr_get_cstr(xclientid) : NULL,
					  rto, msg,  rto_ptr, 0, 0, NULL, 
					  time(NULL) + DEFAULT_EXPIRY, 1, CSP_VERSION(1,3), &el);
		    res = NULL;
		    break;
	       default:
		    if (xuserid) {/* the rest we use csp processor. */
			 RequestInfo_t r = {0};
			 Octstr *ip = octstr_create(xconn->host);
			 
			 r.c = c;
			 r.req_ip = ip;
			 strncpy(r.xsessid,  xconn->id ? xconn->id : "001-xmpp", sizeof r.xsessid);
			 r.is_ssp = 1;
			 r.uid = r.sessid = -1;
			 r.ver = CSP_VERSION(1,3); /* we lie! */
			 
			 r.userid = xuserid;
			 r.clientid = xclientid;
			 
			 if (req_funcs[mtype] == NULL) {
			      error(0, 
				    "unsupported request type [%d:%s] on XMPP S2S interface, rejected", 
				    mtype, csp_obj_name(mtype));
			      res = NULL;
			 } else {
			      EmptyObject_t xres = req_funcs[mtype](&r, msg);
			      
			      if (xres) {			
				   User_t reply_to = sender && sender->u.typ == Imps_User ? 
					sender->u.val : NULL;
				   List *rlist;
				   Octstr *rfrom = to ? make_foreign_jid(to) : NULL;

				   if (reply_to) {
					SSPRecipient_t *sr = gw_malloc(sizeof *sr);
					sr->id = -1;
					sr->sent = 0;
					sr->to = reply_to;
					
					rlist = gwlist_create_ex(sr);
				   } else 
					rlist = NULL;
				   res = csp2xmpp_msg(c, xres, msg, 
						      rfrom ? octstr_get_cstr(rfrom) : "", 
						      id ? octstr_get_cstr(id) : NULL,
						      rlist, NULL);
				   
				   csp_msg_free(xres);
				   octstr_destroy(rfrom);
				   
				   if (gwlist_len(rlist) > 0)
					gw_free(gwlist_get(rlist, 0));
				   gwlist_destroy(rlist, NULL); /* we didn't copy reply_to above! */
			      } else 
				   res = NULL;
			 }       
			 octstr_destroy(ip);
		    } else 
			 res = NULL;
		    break;
	       }
	       octstr_destroy(xclientid);
	       octstr_destroy(xuserid);
	       octstr_destroy(xres);
	       gwlist_destroy(el, (void *)_csp_msg_free);
	       csp_msg_free(rto);		    		    
	       csp_msg_free(msg);
	       
	       if (res) 
		    octstr_append(out, res); 
	       octstr_destroy(res);
	       
	  }

     csp_msg_free(to);
     octstr_destroy(id);
     octstr_destroy(err);
     csp_msg_free(sender);
     gwlist_destroy(mlist, NULL);

     if (octstr_len(out) > 0) {
	  struct OutgoingReq_t *x = gw_malloc(sizeof *x);

	  x->msg = out;
	  strncpy(x->domain, xconn->domain, sizeof x->domain);
	  strncpy(x->our_domain, xconn->our_domain, sizeof x->our_domain);
	  
	  x->conn_flags = XMPP_CONNECTED;
	  x->dx = NULL;
	  
	  gwlist_produce(outgoing_requests, x); /* send it outwards. */
     } else 
	  octstr_destroy(out);
}
static s2sHandler_t xmpp_h =  {
     "XMPP S2S",
     xmpp_init,
     xmpp_msg_send, 
     xmpp_shutdown
};

s2sHandler_t *xmpp_ssp_handler = &xmpp_h;
