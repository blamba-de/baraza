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
#ifndef __DNS_STUFF_INCLUDED__
#define __DNS_STUFF_INCLUDED__
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/socket.h>

#include <gwlib/gwlib.h>
typedef struct SrvRecord_t {
     unsigned long priority, weight, port, rweight;
     
     char host[NS_MAXDNAME];
     unsigned char _pad[2];
} *SrvRecord_t;

/* Does a lookup for SRV records of the given type (e.g. "xmpp-server") and proto (e.g. "tcp") 
 * returns array of these, and sets count variable 
 */
SrvRecord_t dns_find_srv(char *domain, char *service, int *count);

SrvRecord_t dns_make_srv_rec_from_domain(char *domain, int port);

#endif
