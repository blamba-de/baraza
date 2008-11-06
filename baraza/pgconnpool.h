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
#ifndef __PGCONNPOOL_INCLUDED__
#define __PGCONNPOOL_INCLUDED__
#include <libpq-fe.h>
/* PostgreSQL connection pooling. */
int pg_cp_init(long num_conns, char *dbhost, char *dbuser, char *dbpass, char *dbname, int dbport, 
	       char *mydomain);
int pg_cp_cleanup(void);
PGconn *pg_cp_get_conn(void);
void pg_cp_return_conn(PGconn *c);
void pg_cp_on_commit(PGconn *c, void (*func)(void *), void *data);
#endif
