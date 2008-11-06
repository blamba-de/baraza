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
#ifndef __CSP_PRESENCE__INCLUDED__
#define __CSP_PRESENCE__INCLUDED__
/* Presence functions. */
#include <gwlib/gwlib.h>
#include "cspmessages.h"

#include "utils.h"

#define ALL_PRES_ATTRIBS ((1UL<<27)-1) /* must exceed number of presence attribs  in PresenceSubList structure, but not cause integer wrap! XXX */

GetList_Response_t handle_get_list(RequestInfo_t *ri, void *unused);
CreateList_Response_t handle_create_list(RequestInfo_t *ri, CreateList_Request_t req );
Status_t handle_delete_list(RequestInfo_t *ri, DeleteList_Request_t req);
ListManage_Response_t handle_manage_list(RequestInfo_t *ri, ListManage_Request_t req);

Status_t handle_create_attribs(RequestInfo_t *ri, CreateAttributeList_Request_t req );
Status_t handle_delete_attribs(RequestInfo_t *ri, DeleteAttributeList_Request_t req );
GetAttributeList_Response_t handle_get_attribs(RequestInfo_t *ri, GetAttributeList_Request_t req  );

Status_t handle_pres_subscribe(RequestInfo_t *ri, SubscribePresence_Request_t req);
Status_t handle_pres_unsubscribe(RequestInfo_t *ri, UnsubscribePresence_Request_t req);
Status_t handle_pres_auth_user(RequestInfo_t *ri, PresenceAuth_User_t req  );
GetPresence_Response_t handle_get_presence(RequestInfo_t *ri, GetPresence_Request_t req );

#define PRES_FROM_SERVER 1
#define PRES_FROM_CLIENT 2
/* update presence info internall to the session. Indicate source of presence update, 
 * so we know which fields to mask 
 */
int update_pres_info(PGconn *c, PresenceSubList_t newps, int64_t sessid, int64_t uid, int src);
Status_t handle_update_presence(RequestInfo_t *ri, UpdatePresence_Request_t req  );
GetWatcherList_Response_t handle_get_watcher(RequestInfo_t *ri, GetWatcherList_Request_t req  );

void fixup_pres_for_cspversion(PresenceSubList_t p, int csp_version);

#endif
