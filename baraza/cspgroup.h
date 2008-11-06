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
#ifndef __CSP_GROUP_INCLUDED__
#define __CSP_GROUP_INCLUDED__
/* Group Messaging functions */
#include <gwlib/gwlib.h>
#include "cspmessages.h"
#include "utils.h"
Status_t handle_create_group(RequestInfo_t *ri, CreateGroup_Request_t req);
Status_t handle_delete_group(RequestInfo_t *ri, DeleteGroup_Request_t req);
LeaveGroup_Response_t handle_leave_group(RequestInfo_t *ri, LeaveGroup_Request_t req);
GetGroupMembers_Response_t handle_get_group_members(RequestInfo_t *ri, GetGroupMembers_Request_t req);
GetJoinedUsers_Response_t handle_get_joined_users(RequestInfo_t *ri, GetJoinedUsers_Request_t req);
JoinGroup_Response_t handle_join_group(RequestInfo_t *ri, JoinGroup_Request_t req);
Status_t handle_add_members(RequestInfo_t *ri, AddGroupMembers_Request_t req);
Status_t handle_del_members(RequestInfo_t *ri, RemoveGroupMembers_Request_t req);
Status_t handle_member_access(RequestInfo_t *ri, MemberAccess_Request_t req);
GetGroupProps_Response_t handle_get_props(RequestInfo_t *ri, GetGroupProps_Request_t req);
Status_t handle_set_props(RequestInfo_t *ri, SetGroupProps_Request_t req);
RejectList_Response_t handle_reject(RequestInfo_t *ri, RejectList_Request_t req);
SubscribeGroupNotice_Response_t handle_subscribe_notice(RequestInfo_t *ri, 
							SubscribeGroupNotice_Request_t req);

/* User leaves all the groups he/she's joined to */
void leave_all_groups(PGconn *c, int64_t uid, Octstr *clientid, int ver, int reason, int send_msg);

/* user joins all groups that he/she should auto-join. */
void join_all_auto_groups(RequestInfo_t *ri);

#endif
