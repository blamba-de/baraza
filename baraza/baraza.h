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
#ifndef __BARAZA_INCLUDED__
#define __BARAZA_INCLUDED__
#include "utils.h"
#include "pgconnpool.h"
extern struct imps_conf_t *config;

extern void start_cspd(void);
extern void stop_cspd(void);

extern void start_sspd(void);
extern void stop_sspd(void);

extern List *csp_requests;

#endif
