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
#ifndef __CSPTRANS_INCLUDED__
#define __CSPTRANS_INCLUDED__
#include "cspmessages.h"
#include "utils.h"

Login_Response_t handle_login(RequestInfo_t *ri, Login_Request_t req);
void *handle_logout(RequestInfo_t *ri, void *unused);
Service_Response_t handle_serviceRequest(RequestInfo_t *ri, Service_Request_t req);
ClientCapability_Response_t handle_cap_request(RequestInfo_t *ri, ClientCapability_Request_t req);
Search_Response_t handle_search(RequestInfo_t *ri, Search_Request_t req);
Status_t handle_stopsearch(RequestInfo_t *ri, StopSearch_Request_t req);
Status_t handle_invite_request(RequestInfo_t *ri, Invite_Request_t req);
Status_t handle_cancel_invite_request(RequestInfo_t *ri, CancelInvite_Request_t req);
Status_t handle_invite_user_response(RequestInfo_t *ri, InviteUser_Response_t req);

Status_t handle_verifyID(RequestInfo_t *ri, VerifyID_Request_t req);
void *handle_noop(RequestInfo_t *ri, void *unsed);
KeepAlive_Response_t handle_keepalive(RequestInfo_t *ri, KeepAlive_Request_t req);
void *handle_poll_req(RequestInfo_t *ri, void *unused);
GetSPInfo_Response_t handle_get_spinfo(RequestInfo_t *ri, GetSPInfo_Request_t req);

Registration_Response_t handle_register(RequestInfo_t *ri, Registration_Request_t req);

/* utility function. */
int verify_sender(PGconn *c, Sender_t *xsender, int64_t uid, 
		  Octstr *userid,
		  Octstr *clientid, int64_t *mygid, char **err);
#endif
