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
#ifndef __CSPWBXML_INCLUDED__
#define __CSPWBXML_INCLUDED__

typedef struct Node_t {
     Dict   *attr;        /* attributes, if any. */
     Octstr *content;     /* node content... */
     enum {WBXML_UNKNOWN_VALUE = -1, WBXML_OPAQUE_VALUE, WBXML_STRING_VALUE} value_type;
     struct Node_t *children; /* ... or children. */

     struct Node_t *next;   /* next node in the list. */ 

     char tag[1]; 
 /* hidden space here, so careful! */
} *Node_t;

typedef struct {
     u_int8_t version;
     
     Octstr *publicid;
     long charset;
     Octstr *strtbl;
     
     long tag_page, attr_page;
     int csp_version; /* detected version. */
     Node_t body;     
} *WBXML_t; /* result of parsing. */

typedef struct WBXMLGen_t WBXMLGen_t;

typedef struct WBXMLHead_t *WBXMLHead_t;
typedef struct XMLHead_t *XMLHead_t;

WBXML_t parse_wbxml(Octstr *in);
void free_wbxml(WBXML_t wbxml);
WBXMLGen_t *wbxml_pack_state(u_int8_t wbxml_version, Octstr *publicid, long charset, int csp_version); 
void wbxml_pack_state_free(WBXMLGen_t *state);

Octstr *xml_make_preamble(char *dtdname, char *ext_id, char *sysid);
Octstr *wbxml_make_preamble(WBXMLGen_t *state);

Octstr *pack_wbxml_value(Octstr *val, int is_opaque, WBXMLGen_t *state, int attr);

XMLHead_t pack_xml_element_start(const char *name, Dict *attribs,  void *state);
Octstr *pack_xml_element_end(XMLHead_t hd, Octstr *content, void *state);

WBXMLHead_t pack_wbxml_element_start(const char *name, Dict *attribs,  WBXMLGen_t *state);
Octstr *pack_wbxml_element_end(WBXMLHead_t hd, Octstr *content,   WBXMLGen_t *state);
Octstr *pack_xml_value(Octstr *content);

/* Output WBXML content. */
Octstr *dump_wbxml(WBXML_t wbxml);
#endif

