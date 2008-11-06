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
#ifndef __SSP_MESSAGES_INCLUDED__
#define __SSP_MESSAGES_INCLUDED__
#include "ssp.h"


/* Convert message to list of Octstr * (xml), each for one recipient. 
 * rcplist is of struct SSPRecipient_t 
 */
List *csp2ssp_msg(void *msg, void *orig_msg, Sender_t sender, List *rcptlist);

/* convert ssp message to csp as first step to dealing with it. 
 * orig_msg is the message (if any) that resulted in this response message.
 */
void *ssp2csp_msg(xmlNodePtr node, List **other_res, User_t *sending_user, 
		  int csp_ver, void *orig_msg);

#endif
