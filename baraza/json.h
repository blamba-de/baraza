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
#ifndef __JSON_INCLUDED__
#define __JSON_INCLUDED__

#include <gwlib/gwlib.h>

#include "cspmessages.h"


Octstr *make_json_packet(WV_CSP_Message_t msg);
WV_CSP_Message_t parse_json_packet(Octstr *in);

#endif
