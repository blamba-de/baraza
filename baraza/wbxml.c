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
#include <ctype.h>
#include <gwlib/gwlib.h>
#include "wbxml.h"
#include "utils.h"

/* wbxml parser and generator. */

#define WBXML_SWITCH_PAGE       0x0
#define WBXML_END       0x1
#define WBXML_ENTITY    0x2
#define WBXML_STR_I     0x3
#define WBXML_LITERAL   0x4
#define WBXML_EXT_I_0   0x40
#define WBXML_EXT_I_1   0x41
#define WBXML_EXT_I_2   0x42
#define WBXML_PI        0x43
#define WBXML_LITERAL_C 0x44
#define WBXML_EXT_T_0   0x80
#define WBXML_EXT_T_1   0x81
#define WBXML_EXT_T_2   0x82
#define WBXML_STR_T     0x83
#define WBXML_LITERAL_A 0x84
#define WBXML_EXT_0     0xC0
#define WBXML_EXT_1     0xC1
#define WBXML_EXT_2     0xC2
#define WBXML_OPAQUE    0xC3
#define WBXML_LITERAL_AC        0xC4

#define is_STR(t) ((t) == WBXML_STR_I || (t) == WBXML_STR_T)
#define is_EXT(t) ((t) == WBXML_EXT_T_0 || (t) == WBXML_EXT_T_1 || (t) == WBXML_EXT_T_2)
#define is_ENT(t) ((t) == WBXML_ENTITY)
#define TAG_MASK ~(0x03<<6)
#define CONTENT_MASK (0x01<<6)
#define ATTR_MASK (0x01<<7)

#define CHECK_VERSION(ver,min,max) ((ver)>=(min) && (ver)<=(max))

static Octstr *str_from_table(Octstr *tbl, long offset)
{
     int i = octstr_search_char(tbl, 0, offset);
     return (i>=0) ? octstr_copy(tbl, offset, i-offset) : NULL;
}

/* returns the type of value. */
static int parse_value(ParseContext *p, long tok, long page, int csp_version, Octstr *strtbl, Octstr **value)
{
     int tov = WBXML_STRING_VALUE; /* default. */

     *value = NULL;
     if (tok == WBXML_STR_I || 
	 tok == WBXML_STR_T) 
	  *value = (tok ==  WBXML_STR_I) ? parse_get_nul_string(p) : 
	       str_from_table(strtbl, parse_get_uintvar(p));		    
     else if (tok == WBXML_EXT_I_0 || 
	      tok == WBXML_EXT_I_1 || 
	      tok == WBXML_EXT_I_2)  /* don't know what they are, assume plain text. */
	  *value = parse_get_nul_string(p);
     else if (tok == WBXML_EXT_T_0 || 
	      tok == WBXML_EXT_T_1 || 
	      tok == WBXML_EXT_T_2) {
	  long t = parse_get_uintvar(p);
	  /* try to map it. */

#define CSP_ALL 1
#define CSP_Access   page == 1 || page == 10 || page == 3 /* XXX needs some work. */
#define CSP_Presence page == 4 || page == 5 || page == 0
#define WBTAG(a,b,c)
#define WBATTR(a,b,c)
#define WBPUBID(x,y) /* below: we are liberal in what we accept: all. */
#define WBVAL(crit,val,oval,code,minver,maxver) else if ((t == (code)) && (crit) && CHECK_VERSION(csp_version,minver,maxver)) *value = octstr_create(val);
		    if (0)
			 (void)0;
#include "wbxml.def"
#undef CSP_ALL
#undef CSP_Access
#undef CSP_Presence
#undef WBTAG
#undef WBATTR
#undef WBVAL
#undef WBPUBID		    
		    else {
			 error(0, "unknown EXT_T code %ld:%ld (page %d, csp_verion=%d), skipped!", 
			       tok, t, (int)page, csp_version);	    
			 tov = -1;
		    }
     } else if (tok == WBXML_EXT_0 || 
		tok == WBXML_EXT_1 || 
		tok == WBXML_EXT_2)  /* don't know what they are, ignore them. */
	  parse_get_char(p);
     else if (tok == WBXML_OPAQUE) {
	  *value = parse_get_octets(p, parse_get_uintvar(p));
	  tov = WBXML_OPAQUE_VALUE;
     } else if (tok == WBXML_ENTITY) {
	   long ch = parse_get_uintvar(p);		    
	   *value = octstr_create("");
	   octstr_append_char(*value, ch); /* convert it? XXX need to do better */
      }  else 
	   return -1;
     return tov;
}
#if 0
static char *value_type2str(int typ)
{
     static char *x[] = {"none", "opaque", "string"};

     if (typ < -1 || typ > WBXML_STRING_VALUE)
	  return "N/A";
     else 
	  return x[typ+1];     
}
#endif
int parse_wbxml_attributes(Dict *d, ParseContext *p, WBXML_t wbxml, char *tag);
Node_t parse_wbxml_element(ParseContext *p, long lookahead, WBXML_t wbxml)
{    
     Node_t elem, *lastch;
     long stag = (lookahead >= 0) ? lookahead : parse_get_char(p), len;
     Octstr *tag = NULL;
     int tov = -1;

     while (stag == WBXML_SWITCH_PAGE) {
	  wbxml->tag_page = parse_get_char(p);
	  stag = parse_get_char(p);
     }
     
     if ((stag&TAG_MASK) == WBXML_LITERAL) {
	  long offset = parse_get_uintvar(p);
	  tag = str_from_table(wbxml->strtbl, offset);
     } else  {
#define WBTAG(nmtag,pg,code) else if (wbxml->tag_page == pg && (stag&TAG_MASK) == code) tag = octstr_imm(#nmtag);
#define  WBATTR(wh,t,a)
#define  WBVAL(wh,t,a,x,min,max)
#define WBPUBID(x,y)
	  if (0)
	       (void)0;
#include "wbxml.def"
#undef WBTAG
#undef WBATTR
#undef WBVAL
#undef WBPUBID
	  else 
	       tag = NULL;
     }

     if (tag == NULL) {
	  warning(0, "Parse error: Unknown WBXML tag with val [0x%02X] in code page %d", (int)(stag&TAG_MASK), (int)wbxml->tag_page);
	  tag = octstr_imm("##unknown##");
     }

     /* we have a tag */     
#if 0
     info(0, "parsed tag <%s> %s %s", octstr_get_cstr(tag), 
	  stag&CONTENT_MASK ? "has_content" : "" ,
	  stag&ATTR_MASK ? "has_attr" : "");
#endif
     len = octstr_len(tag);
     elem = gw_malloc(len + sizeof *elem);
     strcpy(elem->tag, octstr_get_cstr(tag));
     elem->tag[len] = 0; /* add NULL byte. */
     
     elem->content = octstr_create("");
     elem->next = elem->children = NULL;
     lastch = &elem->children;
     elem->attr = (stag&ATTR_MASK) ? dict_create(7, (void *)octstr_destroy) : NULL;
     elem->value_type = -1; /* not known. */

     if (stag&ATTR_MASK)
	  parse_wbxml_attributes(elem->attr, p, wbxml, elem->tag);
     if (stag&CONTENT_MASK) {  /* handle content: element, string, extension, entity, pi, opaque. */
	  long tok;
	  Octstr *s;
	  /* XXX this content parsing is a bit screwed up if we have text inter-spersed with 
	   * nodes. But since these don't occur in CSP, we ignore it, can't happen. 
	   */
	  while ((tok = parse_get_char(p)) != WBXML_END && tok != -1) 
	       if (tok == WBXML_SWITCH_PAGE) 
		    wbxml->tag_page = parse_get_char(p);
	        else if (tok == WBXML_PI) {
		     parse_wbxml_attributes(NULL, p, wbxml, NULL); /* parse and discard attributes. */
		    parse_get_char(p); /* get end char. */
		} else if ((tov = parse_value(p, tok,wbxml->tag_page, wbxml->csp_version, wbxml->strtbl, &s)) >= 0) {
		    if (s)
			 octstr_append(elem->content, s);
		    if (elem->value_type < 0)
			 elem->value_type = tov;
		    else 
			 elem->value_type = WBXML_STRING_VALUE; /* if already set, then string. */
		    octstr_destroy(s);
	       }  else { /* we assume it is a node. */
		    *lastch = parse_wbxml_element(p, tok, wbxml);
		    if (*lastch)
			 lastch = &(*lastch)->next; /* point to next. */
	       }	  
     }
     
     if (elem->value_type < 0)
	  elem->value_type = WBXML_STRING_VALUE; /* Default is string. */ 
#if 0
     if (elem && octstr_len(elem->content)  > 0) {
	  info(0, "Tag %s, content [type=(%d) %s] dump: ",  elem->tag, 
	       elem->value_type, 
	       value_type2str(elem->value_type)); 
	  octstr_dump(elem->content,0);
     }
#endif
     octstr_destroy(tag);
     return elem;
}

int parse_wbxml_attributes(Dict *d, ParseContext *p, WBXML_t wbxml, char *tag) 
{
     long tok;

     while ((tok = parse_get_char(p)) != WBXML_END && tok >= 0) {
	  long tval;
	  Octstr *attr = NULL, *value = octstr_create("");
	  while (tok == WBXML_SWITCH_PAGE) {
	       wbxml->attr_page = parse_get_char(p);
	       tok = parse_get_char(p);
	  }
     
	  if (tok == WBXML_LITERAL) /* attr. name is a literal. */
	       attr = str_from_table(wbxml->strtbl, parse_get_uintvar(p));
	  else { /* must be attrstart token. */
#define WBVAL(x,y,z,w,min,max)
#define WBTAG(a,b,c)
#define WBPUBID(x,y)
#define WBATTR(a,b,c) else if (tok == c) {attr = octstr_imm(a); if (b) octstr_append_cstr(value,b);}
	       if (0)
		    (void)0;
#include "wbxml.def"
	       else 
		    warning(0, "unknown attr-start token %ld, skipped", tok);
#undef WBVAL
#undef WBTAG	       
#undef WBATTR
#undef WBPUBID	       
	  }

	  /* get rest of the value. */
	  while ((tval = parse_peek_char(p)) >= 0 &&
		 (tval >= 128 || is_STR(tval) || is_EXT(tval) || is_ENT(tval)) && /* .. attrvals are >= 128 */
		 tval != WBXML_END && 
		 tval != WBXML_LITERAL) { /* we are looking at a value. */
	       Octstr *s;
	       tval = parse_get_char(p);
	       
	       if (parse_value(p, tval, wbxml->attr_page, wbxml->csp_version, wbxml->strtbl, &s) >= 0) {
		    if (s)
			 octstr_append(value, s);
		    octstr_destroy(s);
	       } 
	       /* now look in the defined tag values. */
#define WBVAL(x,y,z,w,min,max)
#define WBPUBID(x,y)
#define WBTAG(a,b,c)
#define WBATTR(a,b,c) else if (a == NULL && tval == c) {octstr_append_cstr(value, b);}
#include "wbxml.def"
#undef WBVAL
#undef WBTAG	       
#undef WBATTR	       
#undef WBPUBID
	       else 
		    warning(0, "unknown token %ld in attrvalue, skipped!", tval);	       
	  }
	  
	  if (attr) {
#if 0
	       info(0, "Attr: %s=%s", octstr_get_cstr(attr), octstr_get_cstr(value));
#endif
	       /* Set the csp version as necessary. */
	       if (tag && attr && value && 
		   strcasecmp(tag, "WV_CSP_Message") == 0 && 
		   octstr_str_case_compare(attr, "xmlns") == 0) {
		    wbxml->csp_version = csp_version(octstr_get_cstr(value));

		    info(0, "wbxml.parser: Setting CSP version to %d.%d", wbxml->csp_version>>4, wbxml->csp_version & 0x0f);
	       }
	       if (d) 	      
		    dict_put(d, attr, value);
	       octstr_destroy(attr);
	  }

     }
     return 0;
}

WBXML_t parse_wbxml(Octstr *in)
{
     WBXML_t wbxml;
     ParseContext *p;
     long publicid, p_offset, len;
     
     
     if (in == NULL || octstr_len(in) == 0)
	  return NULL;

     p = parse_context_create(in);
     wbxml  = gw_malloc(sizeof *wbxml);
     memset(wbxml, 0, sizeof *wbxml);
     
     wbxml->csp_version = DEFAULT_CSP_VERSION; 
     wbxml->version = parse_get_char(p);
     if ((publicid = parse_get_uintvar(p)) == 0)
	  p_offset = parse_get_uintvar(p);
     else 
	  p_offset = 0;
     wbxml->charset = parse_get_uintvar(p);
     len = parse_get_uintvar(p);     

     wbxml->strtbl = (len > 0) ? parse_get_octets(p, len) : octstr_create("");
     if (publicid == 0) 
	  wbxml->publicid = str_from_table(wbxml->strtbl, p_offset);
     else if (publicid == 1)
	  wbxml->publicid = NULL;
     else 
	  switch (publicid) {

#define WBVAL(x,y,z,w,min,max)
#define WBPUBID(x,y) case x: wbxml->publicid = octstr_imm(y); break;
#define WBTAG(a,b,c)
#define WBATTR(a,b,c) 
#include "wbxml.def"
#undef WBVAL
#undef WBTAG	       
#undef WBATTR	       
#undef WBPUBID

	  default: wbxml->publicid = NULL; break;
	  }
     /* time now to parse the damn thing. First check for PI. */
     if (parse_peek_char(p) == WBXML_PI) {
	  parse_get_char(p);
	  parse_wbxml_attributes(NULL, p, wbxml, NULL); /* parse and discard attributes. */
	  parse_get_char(p); /* get end char. */
     }
     
     wbxml->body = parse_wbxml_element(p, -1, wbxml); /* parse the node. */
     
     parse_context_destroy(p);
     return wbxml;
}

/* stuff for generation of wbxml from message structure. */
struct WBXMLGen_t {     
     u_int8_t version;
     long publicid;
     long charset;

     int csp_version;
     struct WBStrTbl_t {
	  Dict *d;
	  Octstr *_str;
     } strtbl;
     long tag_page, attr_page;   
};

WBXMLGen_t *wbxml_pack_state(u_int8_t wbxml_version, Octstr *publicid, long charset, int csp_version)
{
     WBXMLGen_t *state = gw_malloc(sizeof *state);
     
     memset(state, 0, sizeof *state);

     state->strtbl.d = dict_create(11, NULL); 
     state->strtbl._str = octstr_create("");
     
     state->version = wbxml_version;
     state->charset = charset;

     state->csp_version = csp_version;

     /* set publicid. */
#define WBVAL(x,y,z,w,min,max)
#define WBPUBID(x,y) else if (octstr_str_case_compare(publicid,y) == 0) state->publicid = x;
#define WBTAG(a,b,c)
#define WBATTR(a,b,c) 
     if (0)
	  (void)0;
#include "wbxml.def"
     else 
	  state->publicid = 1; /* unknown ID. */
#undef WBVAL
#undef WBTAG	       
#undef WBATTR	       
#undef WBPUBID
     
     return state; 
}

void wbxml_pack_state_free(WBXMLGen_t *state)
{
     if (state == NULL) return;
     
     if (state->strtbl.d)
	  dict_destroy(state->strtbl.d);
     octstr_destroy(state->strtbl._str);
     
     gw_free(state);
}
/* put a string into the string table, return its offset. */
static long get_str_offset(struct WBStrTbl_t *tbl, Octstr *s, int add)
{
     long l;
     void *x;
     if ((x = dict_get(tbl->d, s)) != NULL) {
	  l = (unsigned long)x;
	  return l-1; /* offsets stored + 1 to avoid 0 == NULL. */
     } else if (add) {
	  
	  l = octstr_len(tbl->_str);
	  dict_put(tbl->d, s, (void *)(l + 1));
	  
	  octstr_append(tbl->_str, s); /* build table on fly. */
	  octstr_append_char(tbl->_str, 0); 
	  return l;
     } else 
	  return -1;
}

static int contains_nulls(Octstr *s)
{
     int i, l = octstr_len(s);

     for (i = 0; i<l; i++)
	  if (octstr_get_char(s, i) == 0)
	       return 1;
     return 0;
}

static int check_tag_value(Octstr *val, int offset, const char *v, int xlen, int *vlen)
{
     int n = octstr_search(val, octstr_imm(v), offset);
     int len = *vlen = xlen;
     
     /* we need to optimise a little. Use matches only if they are 'large enough' */

     if (n >= 0 && len <= 2) { /* we only care about strings < 2 in length, if it is a full match. */
	  if (n == 0 && octstr_len(val) == len)
	       return n;
	  else 
	       return -1; /* no match. */
     } else 
	  return n;
}

Octstr *pack_wbxml_value(Octstr *val, int is_opaque, WBXMLGen_t *state, int attr)
{

     Octstr *s = octstr_create("");     
     if (is_opaque) {	  
	  octstr_append_char(s, WBXML_OPAQUE);	  
	  octstr_append_uintvar(s, octstr_len(val));	  
	  octstr_append(s, val);
	  
	  return s;
     } else {
	  unsigned len = octstr_len(val);
	  int offset = 0;
	  int page = (attr) ? state->attr_page : state->tag_page;
	  /* append a sequence of inline strings, tablerefs, extensions. */
	  
	  while (offset < len) {
	       int n, plen;
	       int maxlen = -1, moffset = 0, mcode = -1, vlen = -1;	       
	       /* first look for extension - maximal length search. */

#define CSP_ALL 1
#define CSP_Access (page == 1 || page == 10 || page == 3)
#define CSP_Presence (page == 4 || page == 5 || page == 0)
#define WBTAG(a,b,c) 
#define WBATTR(a,b,c)
#define WBPUBID(x,y)
#define WBVAL(crit,v,oval,code,minver,maxver) if (CHECK_VERSION(state->csp_version,minver,maxver) && crit && (n = check_tag_value(val, offset, v, -1 + (sizeof v), &vlen)) >= 0 && vlen >= maxlen) { \
            maxlen = vlen; /* remember maximal one. */ \
            mcode = code; \
            moffset = n; \
     }
#include "wbxml.def"
#undef CSP_ALL
#undef CSP_Access
#undef CSP_Presence
#undef WBTAG
#undef WBATTR
#undef WBVAL
#undef WBPUBID		    
	       
	       if (maxlen <= 0) /* nothing found, copy whole string. */
		    plen = len; 
	       else 
		    plen = moffset - offset;

	       if (plen > 0) { /* there was a prefix, encode it. */
		    Octstr *x = octstr_copy(val, offset, plen);
		    int cn = contains_nulls(x);
		    if (attr && !cn) { /* for attributes we use string table. For others, we do not. */
			 long l = get_str_offset(&state->strtbl, x, 1);
			 octstr_append_char(s, WBXML_STR_T);
			 octstr_append_uintvar(s, l);
		    } else if (!cn) {
			 octstr_append_char(s, WBXML_STR_I);			      
			 octstr_append(s, x);
			 octstr_append_char(s, 0);
		    } else { /* has nulls, so put it in as OPAQUE */
			 octstr_append_char(s, WBXML_OPAQUE);	  
			 octstr_append_uintvar(s, octstr_len(x));	  
			 octstr_append(s, x);
		    }
		    octstr_destroy(x);			 
	       }
	       
	       if (maxlen > 0) { /* we found a maximal match. */
		    octstr_append_char(s, WBXML_EXT_T_0); /* extension. */
		    octstr_append_uintvar(s, mcode);

		    offset = moffset + maxlen; 
	       } else 
		    offset += len;
	  }

	  return s;
     }
}

static Octstr *pack_wbxml_attribute(Octstr *name, Octstr *value, WBXMLGen_t *state)
{
     long offset, len = octstr_len(value);
     long max_vallen = -1, mcode = -1, vlen = -1;
     Octstr *s = octstr_create(""), *x;
     
     /* first determine if we have a pre-defined attribute name and value, use it. 
      * Note: all attributes in CSP share same code page. Hence no page switching.
      */

#define STR_LEN(a) ((a) == NULL ? 0 : strlen(a))
#define WBVAL(x,y,z,w,min,max)
#define WBTAG(a,b,c)
#define WBPUBID(x,y)
#define WBATTR(a,b,c) if (octstr_str_compare(name,(a)) == 0 && \
                               ((b) == NULL || octstr_search(value, octstr_imm(b), 0) == 0) && \
                               (vlen = STR_LEN(b)) > max_vallen) {\
                               max_vallen = vlen; \
                               mcode = (c); \
                           }
#include "wbxml.def"
#undef WBTAG
#undef WBATTR
#undef WBVAL
#undef WBPUBID

     /* put in the ATTRSTART */
     if (max_vallen >= 0) {
	  octstr_append_char(s, mcode);
	  offset = max_vallen;
     } else {
	  long l = get_str_offset(&state->strtbl, name, 1);
	  octstr_append_char(s, WBXML_LITERAL);
	  octstr_append_uintvar(s, l);

	  offset = 0;
     }

     x = octstr_copy(value, offset, len);
     if (octstr_len(x) > 0) {
	  Octstr *y = pack_wbxml_value(x, 0, state, 1);

	  octstr_append(s, y);
	  octstr_destroy(y);
     }
     octstr_destroy(x);
     return s;
}

struct WBXMLHead_t {
     unsigned stag;
     long index; /* if stag is a literal... */
     
     Octstr *pre;
     Octstr *attributes;
     
};

WBXMLHead_t pack_wbxml_element_start(const char *name, Dict *attribs,  WBXMLGen_t *state)
{
     WBXMLHead_t hd = gw_malloc(sizeof *hd);
     unsigned  has_attrib = attribs &&  (dict_key_count(attribs) > 0) ? 0x80 : 0;
     
     hd->pre = octstr_create("");
     hd->attributes = octstr_create("");
     hd->index = -1;
          /* first we require the code and the page. */
     
#define WBTAG(nmtag,pg,code) else if (strcmp(#nmtag, name) == 0) {\
             if (pg != state->tag_page) { \
               octstr_append_char(hd->pre, WBXML_SWITCH_PAGE); \
               octstr_append_char(hd->pre, pg); \
               state->tag_page = pg; \
             } \
             hd->stag = code | has_attrib; \
         }
#define  WBATTR(wh,t,a)
#define  WBVAL(wh,t,a,x,min,max)
#define WBPUBID(x,y)
     if (0)
	  (void)0;
#include "wbxml.def"
#undef WBTAG
#undef WBATTR
#undef WBVAL
#undef WBPUBID
     else { /* just a literal, no code. */
	  Octstr *xname = octstr_create(name);
	  long l = get_str_offset(&state->strtbl, xname, 1);
	  hd->stag = WBXML_LITERAL | has_attrib;
	  hd->index = l;

	  octstr_destroy(xname);
     }
     
     if (has_attrib) {
	  List *k = dict_keys(attribs);
	  Octstr *y;
	  
	  while ((y = gwlist_extract_first(k)) != NULL) {
	       Octstr *v = dict_get(attribs, y);
	       Octstr *a = pack_wbxml_attribute(y, v, state);
	       
	       if (a)
		    octstr_append(hd->attributes, a);
	       octstr_destroy(a);
	       octstr_destroy(y);
	  }
	  octstr_append_char(hd->attributes, WBXML_END);
	  gwlist_destroy(k, NULL);
     }

     return hd;
}

Octstr *pack_wbxml_element_end(WBXMLHead_t hd, Octstr *content,   WBXMLGen_t *state)
{
     unsigned  has_content = content && (octstr_len(content) > 0) ? 0x40 : 0;     
     Octstr *s = octstr_duplicate(hd->pre);
          
     octstr_append_char(s, hd->stag | has_content);
     if ((hd->stag&TAG_MASK) == WBXML_LITERAL)
	  octstr_append_uintvar(s, hd->index);
     octstr_append(s, hd->attributes);
     if (has_content) {
	  octstr_append(s, content);
	  octstr_append_char(s, WBXML_END);
     }

     octstr_destroy(hd->pre);
     octstr_destroy(hd->attributes);
     gw_free(hd);
     
     return s;
}

#if 0
Octstr *pack_wbxml_element(const char *name, Dict *attribs, Octstr *content, WBXMLGen_t *state)
{
     Octstr *s = octstr_create("");
     unsigned  has_attrib = attribs &&  (dict_key_count(attribs) > 0) ? 0x80 : 0;
     unsigned  has_content = content && (octstr_len(content) > 0) ? 0x40 : 0;
     /* first we require the code and the page. */
     
#define WBTAG(nmtag,pg,code) else if (strcmp(#nmtag, name) == 0) {\
             if (pg != state->tag_page) { \
               octstr_append_char(s, WBXML_SWITCH_PAGE); \
               octstr_append_char(s, pg); \
               state->tag_page = pg; \
             } \
             octstr_append_char(s, code | has_attrib | has_content); \
         }
#define  WBATTR(wh,t,a)
#define  WBVAL(wh,t,a,x,min,max)
#define WBPUBID(x,y)
     if (0)
	  (void)0;
#include "wbxml.def"
#undef WBTAG
#undef WBATTR
#undef WBVAL
#undef WBPUBID
     else { /* just a literal, no code. */
	  Octstr *xname = octstr_create(name);
	  long l = get_str_offset(&state->strtbl, xname, 1);
	  octstr_append_char(s, WBXML_LITERAL | has_attrib | has_content);
	  octstr_append_uintvar(s, l);

	  octstr_destroy(xname);
     }
     
     if (has_attrib) {
	  List *k = dict_keys(attribs);
	  Octstr *y;
	  
	  while ((y = gwlist_extract_first(k)) != NULL) {
	       Octstr *v = dict_get(attribs, y);
	       Octstr *a = pack_wbxml_attribute(y, v, state);
	       
	       if (a)
		    octstr_append(s, a);
	       octstr_destroy(a);
	       octstr_destroy(y);
	  }
	  octstr_append_char(s, WBXML_END);
	  gwlist_destroy(k, NULL);
     }
     
     if (has_content) {
	  octstr_append(s, content);
	  octstr_append_char(s, WBXML_END);
     }
     return s;
}

#endif

static void free_nodes(Node_t node)
{
     Node_t children, next;

     if (node == NULL)
	  return;
     octstr_destroy(node->content);
     if (node->attr)
	  dict_destroy(node->attr);     

     children = node->children;
     next = node->next;
     gw_free(node);

     free_nodes(next); /* recursively destroy siblings and children. */
     free_nodes(children);     
}

void free_wbxml(WBXML_t wbxml)
{
     if (wbxml == NULL)
	  return;
  
     octstr_destroy(wbxml->publicid);
     octstr_destroy(wbxml->strtbl);
     
     free_nodes(wbxml->body);
     
     gw_free(wbxml);
}

Octstr *xml_make_preamble(char *dtdname, char *ext_id, char *sysid)
{
     return octstr_format("<?xml version='1.0'?>\n\t<!DOCTYPE %s \"%s\" \n\t\"%s\">\n",
			  dtdname ? dtdname : "IMPS-CSP", 
			  ext_id ? ext_id : "-//OMA//DTD WV-CSP 1.1//EN", 
			  sysid ? sysid : "http://www.openmobilealliance.org/DTD/WV-CSP.XML");    
}

Octstr *wbxml_make_preamble(WBXMLGen_t *state)
{
     Octstr *s = octstr_create("");
     long pid;
     
     gw_assert(state);
     octstr_append_char(s, state->version);
     if (state->publicid == 0) {
	  warning(0, "wbxml_make_preamble: called with 0 publicid -- forced to unknown");
	  pid = 1;
     } else 
	  pid = state->publicid; /* we assume it is not an index. It better not be! */
     octstr_append_uintvar(s, pid); 
     
     octstr_append_uintvar(s, state->charset);

     octstr_append_uintvar(s, octstr_len(state->strtbl._str));
     if (state->strtbl._str)
	  octstr_append(s, state->strtbl._str);

     return s;
}

struct XMLHead_t {
     Octstr *tag;
     Octstr *head;
};

/* take care of the XML tag formats. */
static Octstr *make_xml_tag(const char *name)
{
     Octstr *x = octstr_create("");
     char *y = (char *)name;
     while (*y) {
	  int ch = *y;
	  
	  if (ch == '_') /* fixup our internal format to this one. */ 
	       ch = '-';
	  octstr_append_char(x, ch);
	  y++;
     }
     return x;
}

XMLHead_t pack_xml_element_start(const char *name, Dict *attribs,  void *state)
{
     XMLHead_t hd = gw_malloc(sizeof *hd);
     List *l = attribs ? dict_keys(attribs) : NULL;
     Octstr *r;

     hd->tag = make_xml_tag(name);
     hd->head = octstr_format("<%S", hd->tag);
     
     if (l)
	  while ((r = gwlist_extract_first(l)) != NULL) {
	       Octstr *v = dict_get(attribs, r);

	       octstr_format_append(hd->head, " %S=\"%S\"", r, v);
	       
	       octstr_destroy(r);
	  }
     
     gwlist_destroy(l, NULL);
     return hd;
}

Octstr *pack_xml_value(Octstr *content)
{
     Octstr *x = octstr_duplicate(content);
     octstr_convert_to_html_entities(x); /* quote nasty characters. */

     
     return x;
}

Octstr *pack_xml_element_end(XMLHead_t hd, Octstr *content, void *state)
{
     Octstr *s = octstr_duplicate(hd->head);
     int has_content = content && octstr_len(content) > 0;


     if (has_content)
	  octstr_format_append(s, ">\n%S\n</%S>\n", content, hd->tag);
     else 
	  octstr_append_cstr(s, "/>\n");

     octstr_destroy(hd->tag);
     octstr_destroy(hd->head);
     gw_free(hd);
     
     return s;
}
#if 0
Octstr *pack_xml_element(const char *name, Dict *attribs, Octstr *content, void *state)
{
     List *l = attribs ? dict_keys(attribs) : NULL;
     Octstr *s = octstr_format("<%s", name), *r;
     int has_content = content && octstr_len(content) > 0;
     if (l)
	  while ((r = gwlist_extract_first(l)) != NULL) {
	       Octstr *v = dict_get(attribs, r);

	       octstr_format_append(s, " %S=\"%S\"", r, v);
	       
	       octstr_destroy(r);
	  }
     
     
     if (has_content)
	  octstr_format_append(s, ">\n%S\n</%s>\n", content, name);
     else 
	  octstr_append_cstr(s, "/>\n");
     
     gwlist_destroy(l, NULL);
     return s;
}

#endif 

static void pad_for_lev(Octstr *os, int lev)
{
    while (lev-- > 0)
	 octstr_append_char(os, ' '); /* spacing. */    
}

static void append_tag_name(Octstr *os, char *tag, char *prefix, char *postfix)
{
     if (prefix)
	  octstr_append_cstr(os, prefix);
     while (*tag) {
	  octstr_append_char(os, (*tag == '_') ? '-' : *tag);
	  tag++;
     }
     if (postfix)
	  octstr_append_cstr(os, postfix);
}

static void dump_wbxml_element(Node_t elem, Octstr *os, int lev)
{
     int  empty;

     if (elem == NULL)
	  return;
     
     pad_for_lev(os, lev);
#if 0
     octstr_format_append(os, "<%s", elem->tag);
#else
     append_tag_name(os, elem->tag, "<", NULL);
#endif

     if (elem->attr) { /* output the attributes. */
	  List *l = dict_keys(elem->attr);
	  Octstr *xkey;

	  while ((xkey = gwlist_extract_first(l)) != NULL) {
	       Octstr *xval = dict_get(elem->attr, xkey);
	       
	       octstr_format_append(os, " %S=\"%S\"", xkey, xval);
	              
	       octstr_destroy(xkey);
	  }
	  gwlist_destroy(l, NULL);
     }
     
     empty =  (elem->children == NULL && octstr_len(elem->content) == 0);  /* empty node. */
     
     if (empty)
	  octstr_append_cstr(os, "/>\n");	  
     else 
	  octstr_append_cstr(os, ">\n");
     
     dump_wbxml_element(elem->children, os, lev+1); /* print children, follow siblings */
     
     if (octstr_len(elem->content) > 0) {
	  pad_for_lev(os, lev+1);
	  if (octstr_check_range(elem->content, 0, octstr_len(elem->content), _x_isprint) != 1)
	       octstr_format_append(os, "HEX(%H)", elem->content);
	  else 
	       octstr_append(os, elem->content);
	  octstr_append_char(os, '\n');
     }
     
     if (!empty) {
	  pad_for_lev(os, lev);
#if 0
	  octstr_format_append(os, "</%s>\n", elem->tag);
#else
	  append_tag_name(os, elem->tag, "</", ">\n");
#endif
     }
     
     dump_wbxml_element(elem->next, os, lev); /* follow, print next item in list. */
}

Octstr *dump_wbxml(WBXML_t wbxml)
{
     Octstr *os = octstr_create("");
     
     if (wbxml == NULL)
	  return os;
     
     octstr_format_append(os, "WBXML version = %02x, pub id = \"%S\", charset=%ld, dump follows:\n ",
			  (int)wbxml->version, wbxml->publicid ? wbxml->publicid : octstr_imm("N/A"),
			  wbxml->charset);
     dump_wbxml_element(wbxml->body, os, 0);
     
     return os;
}
