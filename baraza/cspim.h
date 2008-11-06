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
#ifndef __CSP_IM_INCLUDED__
#define __CSP_IM_INCLUDED__
/* Instant Messaging functions */
#include <gwlib/gwlib.h>
#include "cspmessages.h"
#include "utils.h"

/* first argument to send_im is NULL or the connection that has already been allocated. */
SendMessage_Response_t handle_send_im(RequestInfo_t *ri, SendMessage_Request_t req);
Status_t handle_setd_method(RequestInfo_t *ri, SetDeliveryMethod_Request_t req);
Status_t handle_fwd_msg(RequestInfo_t *ri, ForwardMessage_Request_t req);
Status_t handle_msg_delivered(RequestInfo_t *ri, MessageDelivered_t req);
GetMessage_Response_t handle_get_msg(RequestInfo_t *ri, GetMessage_Request_t req);
Status_t handle_reject_msg(RequestInfo_t *ri, RejectMessage_Request_t req);
GetMessageList_Response_t handle_get_message_list(RequestInfo_t *ri, GetMessageList_Request_t req);
GetBlockedList_Response_t handle_get_block_list(RequestInfo_t *ri, void *unused);
Status_t handle_block_entity_req(RequestInfo_t *ri, BlockEntity_Request_t req);

/* take a recipient structure, remove all users but the target user. */
void fixup_rcpt_field(Recipient_t rcpt, char *sname, char *uname, char *clientid);
#endif
