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
     sprintf(buf, "CREATE DATABASE %s  WITH TEMPLATE=template0 ENCODING = \'SQL_ASCII\'", dbname);
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

#include "tables.h"
