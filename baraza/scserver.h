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
#ifndef __SC_SERVER__INCLUDED__
#define __SC_SERVER__INCLUDED__
#include <gwlib/gwlib.h>
#include "utils.h"
#include "pgconnpool.h"
/* Content server interface */
int sc_init_server(struct imps_conf_t *config);
void sc_shutdown_server(void);
List *sc_requests;
Octstr *sc_add_content(PGconn *c, char *ctype, char *enc, char *data, long dsize);
#endif
