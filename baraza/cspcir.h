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
#ifndef __CSPCIR_INCLUDED__
#define __CSPCIR_INCLUDED__
#include "utils.h"
#include "conf.h"
extern List *http_cir_requests;
typedef struct CIRTarget_t CIRTarget_t;

CIRTarget_t *make_cir_target(int64_t uid, char clientid[]);

void start_CIR_handlers(int num_threads, int cir_stcp_port, enum cir_methods_t xcir_methods[], 
			char *send_sms_url);

void stop_CIR_handlers(void);

/* inform (via CIR) client of new message. */
void cir_newmsg(CIRTarget_t *);
#endif
