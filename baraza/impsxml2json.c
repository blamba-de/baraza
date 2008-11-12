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
/* XML to JSON format convertor */
#include <gwlib/gwlib.h>
#include "json.h"
#include "utils.h"

/* To make it compile! */
struct imps_conf_t *config;

void *xmpp_ssp_handler, *imps_ssp_handler; 
int main(int argc, char *argv[])
{
     Octstr *s;
     
     gwlib_init();
     s = octstr_read_pipe(stdin);
     
     xmlDocPtr xml = xmlParseMemory(octstr_get_cstr(s), octstr_len(s));
     void *start = xml ? find_node(xml->xmlChildrenNode, "WV-CSP-Message", 3) : NULL;
     
     if (start) {
	  void *r = NULL, *e;
          
	  parse_WV_CSP_Message(start, &e, 0, (void *)&r);
	  
	  if (r) {
	       Octstr *x = make_json_packet(r);
	       
	       printf("%s\n", octstr_get_cstr(x));
	       
	       octstr_destroy(x);
	  }
	  return 0;
     } else 
	  fprintf(stderr, "Failed to parse XML!\n");
     
     return -1;
}
