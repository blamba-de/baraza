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
/* CSP XML parser and generator.  */

#include "cspmessages.h"
#include "wbxml.h"
#include "utils.h"

int parse_XXX(void *node, void **next, int binary, void **result); 

 
#define COMP_TAGS(a,b) (binary ? strcasecmp((a),(b)) : compare_tag((a),(b)))
#define STRFREE(s) (binary ? (void)0 : xmlFree(s))
#define NODE_TAG(n) (binary == 0 ? (char *)((xmlNodePtr)n)->name : (char *)((Node_t)n)->tag)
#define NODE_CONTENT(n) (binary == 0 ? _xmlNodeContent(n) : octstr_duplicate(((Node_t)n)->content))
#define NODE_CONTENT_TYPE(n) (binary == 0 ? WBXML_STRING_VALUE : ((Node_t)n)->value_type)
#define NODE_TYPE(n) (binary ? XML_ELEMENT_NODE : ((xmlNodePtr)n)->type)
#define NODE_NEXT(n) (binary ? (void *)((Node_t)n)->next : (void *)((xmlNodePtr)n)->next)
#define NODE_CHILDREN(n) (binary ? (void *)((Node_t)n)->children : (void *)((xmlNodePtr)n)->xmlChildrenNode)



#define str_to_Integer(x,none,b, vtype) ((b) ? get_uint_from_str(x, vtype) : strtoul(octstr_get_cstr(x), NULL, 10))
#define str_to_EmptyTag(x,none,b,v) 1
#define str_to_Boolean(x,none,b,v) (((x) != NULL) && (strcasestr(octstr_get_cstr(x), "t") != NULL))

#define String_to_str(xstr,bin) ((xstr) ? octstr_create_from_data((void *)(xstr)->str, (xstr)->len) : NULL)
#define EmptyTag_to_str(s,bin) ((s) ? octstr_imm("") : NULL)
#define Boolean_to_str(t,bin) ((t) ? octstr_imm("T") : octstr_imm("F"))


#define PACK_MSG_START(nm,bin) (bin ? (void *)pack_wbxml_element_start(nm, attrib, state) : (void *)pack_xml_element_start(nm, attrib, state))
#define PACK_MSG_END(dat,content,bin) (bin ? pack_wbxml_element_end(dat, content, state) : pack_xml_element_end(dat, content, state))
#define PACK_VALUE(bin,content,nm) (bin ? pack_wbxml_value(content, (Imps_##nm != Imps_String && Imps_##nm != Imps_Boolean), state, 0) : pack_xml_value(content)) 


static long get_uint_from_str(Octstr *s, int vtype)
{
     unsigned long l = 0;
     int i, n;
     
     if (vtype == WBXML_OPAQUE_VALUE)
	  for (i = 0, n = octstr_len(s); i<n; i++) {
	       unsigned ch = octstr_get_char(s, i);
	       
	       l = (l<<8) | (ch & 0xFF);
	  }
     else 
	  l = strtoul(octstr_get_cstr(s), NULL, 10); /* plain text. */
     return l;
}

#define pchar_to_String(s,len,typ) csp_String_from_data(s, len,typ)
#define str_to_String(s,typ,bin,v) csp_String_from_bstr(s,typ)


static time_t str_to_Date(Octstr *s, enum IMPsObjectType typ, int bin, int vtype)
{
     if (!s) 
	  return 0;
     else if (bin &&  
	      vtype == WBXML_OPAQUE_VALUE && 
	      octstr_len(s) == 6) { /* compact format: pg 31, WBXML spec.  */
	  struct tm _tm, *tm = &_tm;
	  char tzone[2];
	  unsigned long ch1, ch2;

	  memset(tm, 0, sizeof *tm);

	  ch1 = octstr_get_char(s, 0);
	  ch2 = octstr_get_char(s, 1);
	  
	  tm->tm_year = (ch2>>2) | (ch1<<6);
	  ch1 = octstr_get_char(s, 2);

	  tm->tm_mon = ((ch2&0x3)<<2 | (ch1>>6)) - 1;	  
	  tm->tm_mday = (ch1>>1) & 0x1F;

	  ch2 = octstr_get_char(s, 3);
	  tm->tm_hour = ((ch2>>4) & 0x0F) | (ch1&0x01)<<4;

	  ch1 = octstr_get_char(s, 4);

	  tm->tm_min = (ch1>>6) | ((ch2&0x0F)<<2);
	  
	  tm->tm_sec = ch1 & 0x3F;

	  tzone[0] = octstr_get_char(s, 5);	  
	  tzone[1] = 0;
	  tm->tm_zone = tzone;
	  
	  tm->tm_year -= 1900; /* year must be off by 1900. */

	  return gw_mktime(tm);
     } else {
	  struct universaltime ut;
	  
	  if (parse_iso_date(&ut, s) < 0)
	       return 0;
	  else 
	       return date_convert_universal(&ut);
     }
     
     return 0;
}

/* followed by utility functions */
#if 0
static int compare_tag(char *nodetag, char *tag)
{
     while (*nodetag && *tag) {
	  int ch = (*tag == '_') ? '-' : *tag; /* ... */
	  
	  if (ch != *nodetag)
	       return *nodetag - ch;
	  nodetag++;
	  tag++;
     }

     return *nodetag - *tag;
}

#endif

static int compare_tag(char *nodetag, char *tag)
{
    while (*nodetag && *tag) {
	int ch = (*nodetag == '-') ? '_' : *nodetag;
	if (ch != *tag)
	    return ch - *tag;
	nodetag++;
	tag++;
    }
    return *nodetag - *tag;
}

static char *GetProp(void *node, const char *attrname, int binary)
{
     if (node == NULL) 
	  return NULL;
     else if (binary) {
	Node_t n = node;
	Octstr *s = n
	    && n->attr ? dict_get(n->attr, octstr_imm(attrname)) : NULL;
	return s ? octstr_get_cstr(s) : NULL;
    } else {
	 xmlNodePtr xnode = node;
	 if (strcasecmp(attrname, "xmlns") == 0) { /* special handling */
	      unsigned char *s = xnode->ns ? (void *)xnode->ns->href : NULL; /* assume it is the first one. */
	      return s ? (void *)xmlStrdup(s) : NULL;
	 } else 
	      return (char *) xmlGetProp(node, (unsigned char *) attrname);
    }
}



#define ATTR(nm) if ((_s = GetProp(node,#nm,binary)) != NULL) {\
   dict_put(xres->attributes, octstr_imm(#nm), octstr_create(_s)); \
   STRFREE(_s); \
}

#define ATTRIBUTES(attr) \
{ \
 char *_s; \
 xres->attributes = dict_create(7, (void *)octstr_destroy); \
 attr \
}

#define Basic(nm,ver,attr,typ)					 \
     int parse_##nm(void *node,  void **next, int binary, void **res)	\
     {									\
	  gw_assert(node);						\
	  if (COMP_TAGS((char *)NODE_TAG(node), #nm) == 0) {		\
	       Octstr *s = NODE_CONTENT(node);				\
	       int vtype = NODE_CONTENT_TYPE(node);			\
	       nm##_t xres = (nm##_t)str_to_##typ(s,Imps_##nm,binary,vtype); \
	       *res = (void *)xres; /* set result as well. */		\
	       attr							\
		    octstr_destroy(s);					\
	       *next = NODE_NEXT(node);					\
	       vtype = 0;						\
	       return 0;						\
	  } else							\
	       *res = NULL;						\
	  return -1;							\
     }

#define Item(name,typ) \
   if (MSG_GET_BIT(xres,_fct) == 0 && \
        parse_##typ(start,&end,binary,&x) == 0) { \
      xres->name = (typ##_t)x; \
      MSG_SET_BIT(xres,_fct); \
      goto loop; \
   } \
   _fct++;

#define List(name,typ) {   \
    int _lfound = 0;       \
    void *_n = start; \
    while (_n && parse_##typ(_n,&end, binary,&x) == 0) { /* no need for bit check since is a list. */ \
        if (xres->name == NULL) xres->name = gwlist_create(); \
        gwlist_append(xres->name, x); \
        while (end && NODE_TYPE(end) != XML_ELEMENT_NODE) end = NODE_NEXT(end); \
        _n = end;    \
        _lfound = 1; \
    } \
    if (_lfound) {     \
      MSG_SET_BIT(xres,_fct); \
       goto loop;    \
    } \
    _fct++; \
 }

#define UELEM(type) \
      if (parse_##type(start, &end, binary,&_x) == 0) { \
           _found = 1; \
           _etyp = Imps_##type; \
           break; \
      }
#define Union(name, elems) \
  if (MSG_GET_BIT(xres,_fct) == 0)  { \
  void *_x = NULL; \
  int _found = 0, _etyp = -1; \
  do { elems } while (0); \
  if (_found) { \
     xres->name.val = _x; \
     xres->name.typ = _etyp; \
    MSG_SET_BIT(xres,_fct); \
    goto loop; \
  } \
} \
 _fct++;

#define Structure(xname,hastag,ver,attr, parms) \
int parse_##xname(void *node,  void **next, int binary, void **res) \
{ \
  xname##_t xres = NULL; \
  void *start, *end; \
  unsigned long _fct, tcount = csp_type_field_count(Imps_##xname); \
  gw_assert(node); \
  if (hastag && COMP_TAGS((char *)NODE_TAG(node), #xname) != 0) return -1; \
  start = (hastag) ? NODE_CHILDREN(node) : node; \
  end  =  (hastag) ? NODE_NEXT(node) : NULL; \
  if (hastag) *next = end; \
  xres = gw_malloc(sizeof *xres); \
  memset(xres, 0, sizeof *xres); \
  ((EmptyObject_t)xres)->typ = Imps_##xname; /* set object type. */ \
  /* if (NODE_CHILDREN(node) == NULL) xres->_content = NODE_CONTENT(node); */ \
  attr \
  while (start != NULL) { \
    void *x = NULL; \
    int found = 1; \
    _fct = 0; \
    if (NODE_TYPE(start) != XML_ELEMENT_NODE) {found = 0; goto loop;} \
   parms /* if we succeed, we will jump to 'loop:' label below, in here. */ \
   found = 0; \
   x = NULL; \
   if (hastag) warning(0, "unexpected node: %s within a [%s]", NODE_TAG(start), #xname); \
   else break; /* if there was not tag, one element must match, or we break out. */\
  loop: \
    start = (!found) ? NODE_NEXT(start) : end; \
    if (!hastag && bit_count(xres->_fieldset) == tcount) break; /* for ones with no tag, stop once all seen. */ \
  } \
  if (!hastag && \
      bit_count(xres->_fieldset) == 0) { /* nothing found. */ \
            gw_free(xres); /* XXXX we need to delete better. */ \
            xres = NULL; \
  } else if (!hastag) /* it is a valid structure but without a tag. */ \
       *next = end; \
   \
  *res = xres; /* next line: gives us node contents if no fields were set. moved here because of libxml2 semantics. */ \
   if (xres && xres->_fieldset == 0) xres->_content = NODE_CONTENT(node); \
  return (xres) ? 0 : -1; \
}
#define NONE
#include "cspmessages.def"

#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE

int csp_parse_msg_real(void *node, int type, int binary, void **res, 
			  const char *file, int line, const char *func)
{
     void *_next;
     int out;
     
     switch(type) {
     default:
	  error(0, "parse: unknown message type:  %d in %s() at %s:%d", type, func, file, line);
	  out = -1;
	  break;
#define NONE
#define ATTR(nm) 
#define ATTRIBUTES(attlist)
#define Basic(nm,ver,attr,typ) case Imps_##nm: \
               out = parse_##nm(node, &_next, binary, res); \
               break;

#define Item(name,typ)
#define List(name,typ)
#define UELEM(type) 
#define Union(name,elems)
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname: \
              out = parse_##xname(node, &_next, binary, res); \
              break;

#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     	  
     }
     return out;
}


/* Generationg functions. */

static Octstr *Integer_to_str(long l, int bin)
{
     if (!bin)
	  return octstr_format("%ld", l);
     else {
	  Octstr *s = octstr_create("");
	  unsigned long ul = l;
	  
	  do 	       
	       octstr_insert_char(s, 0, ul & 0xFF); 
	  while (ul >>= 8);
	  
	  return s;
     }
}


static Octstr *Date_to_str(time_t t, int bin)
{
     if (bin) {
	  struct tm _tm = gw_localtime(t), *tm = &_tm; 
	  Octstr *s = octstr_create("");
	  unsigned long n, m;
	  
	  n = tm->tm_year + 1900;

	  octstr_append_char(s, (n>>6)&0x3f);
	  m = tm->tm_min + 1;
	  
	  octstr_append_char(s, (m>>2&0x03) | ((n&0x3f)<<2));
	  octstr_append_char(s, ((m&0x03)<<6) | (tm->tm_mday<<1) | ((tm->tm_hour>>4)&0x01));
	  octstr_append_char(s, ((tm->tm_min>>2)&0x0F) | ((tm->tm_hour&0x0F)<<4));	  
	  octstr_append_char(s, (tm->tm_sec&0x3F) | ((tm->tm_min&0x03)<<6));
	  
	  octstr_append_char(s, tm->tm_zone ? tm->tm_zone[0] : 'Z');

	  return s;
     } else 
	  return date_create_iso(t);     

}


/* begin to define the thingies for generating content */
#define ATTR(nm)
#define ATTRIBUTES(a) attrib = (void *)msg->attributes;
#define Basic(nm,ver,attr,typ) \
Octstr *pack_##nm(nm##_t msg, int binary, void *state) \
{ \
   void *attrib = NULL; \
   Octstr *out; \
   Octstr *_content = typ##_to_str(msg,binary); \
   if (_content) { \
      void *_dat; \
      Octstr *content; \
      attr \
      _dat = PACK_MSG_START(#nm,binary);  /* do this only after attrib is set. */ \
      content = PACK_VALUE(binary,_content,typ); \
      out = PACK_MSG_END(_dat,content,binary); \
      octstr_destroy(content); \
   } else \
       out = NULL; \
    octstr_destroy(_content); \
   return out; \
}


/* now for the structure... */
#define Item(name,typ) \
 if (MSG_GET_BIT(msg,_fct) && (_x = pack_##typ(msg->name, binary, state)) != NULL) { \
     octstr_append(s, _x); \
     octstr_destroy(_x); \
 } \
_fct++;

#define List(name,typ) if (MSG_GET_BIT(msg,_fct)) { \
  int _i = 0, _n = gwlist_len(msg->name); \
  while (_i < _n) { \
     typ##_t _y = (typ##_t)gwlist_get(msg->name, _i); \
     if ((_x = pack_##typ(_y, binary,state)) != NULL) { \
        octstr_append(s, _x); \
        octstr_destroy(_x); \
     } \
     _i++; \
  } \
} \
  _fct++; 

#define UELEM(type) \
 if (_typ == Imps_##type) {\
   if ((_x = pack_##type((type##_t)_val, binary, state)) != NULL) { \
          octstr_append(s, _x); \
          octstr_destroy(_x); \
   } \
   break; \
}

#define Union(name, elems) \
{ \
  void *_val = (void *)msg->name.val; \
  int _typ = msg->name.typ; \
  if (MSG_GET_BIT(msg,_fct)) do { elems } while (0); \
  _fct++; \
}

#define Structure(xname,hastag,ver,attr, parms)				\
  Octstr *pack_##xname(xname##_t msg,  int binary, void *state)		\
  {									\
    Octstr *s, *res, *_x;						\
    void *attrib = NULL, *_dat;						\
    unsigned long _fct = 0;						\
    if (!msg) return NULL;						\
    gw_assert(CSP_MSG_TYPE(msg) == Imps_##xname);			\
    s = octstr_create("");						\
    attr								\
      _dat = hastag ? PACK_MSG_START(#xname,binary) : NULL;		\
    parms								\
	 if (msg->_fieldset == 0 && octstr_len(msg->_content) > 0) { /* add content element.*/ \
	      _x = PACK_VALUE(binary,msg->_content,String);		\
	      octstr_append(s, _x);					\
	      octstr_destroy(_x);					\
	 }								\
    res = hastag ? PACK_MSG_END(_dat, s, binary) : s;			\
    if (hastag) octstr_destroy(s);					\
    _x = NULL; _fct = 1; /* so compiler shuts up. */			\
    return res;								\
  }
  
#define NONE
#include "cspmessages.def"

#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE


/* Generalised message packing */
Octstr *csp_pack_msg_real(void *msg, int type, int binary, void *state, 
			  const char *file, int line, const char *func)
{
     Octstr *out;

     switch(type) {
     default:
	  error(0, "pack: unknown message type:  %d in %s() at %s:%d", type, func, file, line);
	  out = NULL;
	  break;
#define NONE
#define ATTR(nm) 
#define ATTRIBUTES(attlist)
#define Basic(nm,ver,attr,typ) case Imps_##nm: \
               out = pack_##nm((nm##_t)msg, binary, state); \
               break;

#define Item(name,typ)
#define List(name,typ)
#define UELEM(type) 
#define Union(name,elems)
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname: \
              out = pack_##xname(msg, binary, state); \
              break;

#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     	  
     }
     return out;
}

/* finally define function for manipulating fieldset. */
void csp_msg_set_fieldset_real(const char *func, const char *file, int line, void *msg, ...)
{
     va_list ap;
     char *fld;
     va_start(ap, msg);	  
     switch (((EmptyObject_t)msg)->typ) {
#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) 

#define Item(name,typ)  if (strcmp(#name, fld) == 0)  {MSG_SET_BIT(xmsg, _fct); break;} _fct++; /* no curly braces! */
#define List(name,typ)    Item(name,0)
#define Union(name,elems) Item(name,0)
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname : \
                     while ((fld = va_arg(ap, char *)) != NULL) { \
                         xname##_t xmsg = msg; unsigned long _fct = 0; do {parms \
                        panic(0, "set_fieldset: structure %s has no field %s!", #xname,fld);} while (0); _fct = 0; xmsg = NULL; \
                     } \
                          break;
#include "cspmessages.def"
     default: 
	  error(0, "csp_msg_set_fieldset: unknown object type code: %d in %s() at %s:%d", 
		((EmptyObject_t)msg)->typ, func, file, line);
	  break;
     }
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     

}

void csp_msg_unset_fieldset_real(const char *func, const char *file, int line, void *msg, ...)
{
     va_list ap;
     char *fld;
     va_start(ap, msg);	  
     switch (((EmptyObject_t)msg)->typ) {
#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) 

#define Item(name,typ)  if (strcmp(#name, fld) == 0)  {MSG_UNSET_BIT(xmsg, _fct); break;} _fct++; /* no curly braces! */
#define List(name,typ)    Item(name,0)
#define Union(name,elems) Item(name,0)
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname : \
                     while ((fld = va_arg(ap, char *)) != NULL) { \
                         xname##_t xmsg = msg; unsigned long _fct = 0; do {parms \
                        panic(0, "unset_fieldset: structure %s has no field %s!", #xname,fld); } while (0); _fct = 0; xmsg = NULL; \
                     } \
                          break;
#include "cspmessages.def"
     default: 
	  error(0, "csp_unset_fieldset: unknown object type code: %d in %s() at %s:%d", 
		((EmptyObject_t)msg)->typ, func, file, line);
	  break;
     }
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     

}

/* first we need an array to handle mapping of compound vs non-compound types. */
static const struct {
     unsigned char is_struct;
     unsigned char is_string;
     unsigned long size;
     char *name;
} csp_types[] = {
#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) [Imps_##nm] = {(Imps_##typ == Imps_String), (Imps_##typ == Imps_String), sizeof(typ##_t), #nm}, /* not used for Basic objects!*/

#define Item(name,typ)
#define List(name,typ)
#define Union(name,elems)
#define Structure(xname,hastag,ver,attr, parms) [Imps_##xname] = {1, 0, sizeof (struct xname##_t),#xname},
#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     

};

#define is_csp_struct(typ) (csp_types[Imps_##typ].is_struct)
#define is_csp_string(typ) (csp_types[Imps_##typ].is_string)
#define csp_struct_size(typ) (csp_types[typ].size)
#define is_valid_csp_type(typ) ((typ) >= 0 && (typ) < NELEMS(csp_types))

const char *csp_obj_name(int typ)
{
     if (typ < 0 || typ > NELEMS(csp_types))
	  return "unknown";
     else 
	  return csp_types[typ].name;     
}

int csp_name_to_type(char *name)
{
     int i;

     for (i = 0; i<NELEMS(csp_types); i++)
	  if (csp_types[i].name && 
	      strcmp(name, csp_types[i].name) == 0)
	       return i;
     return -1;
}

int csp_type_format(int typ, int *is_string, int *is_struct)
{
     if (typ < 0 || typ > NELEMS(csp_types))
	  return -1;
     *is_string = csp_types[typ].is_string;
     *is_struct = csp_types[typ].is_struct;

     return 0;
}

void *csp_msg_copy_real(void *msg, const char *func, const char *file, int line)
{
     int _typ;
     if (msg == NULL)
	  return NULL;
     _typ = ((EmptyObject_t)msg)->typ;
     switch (_typ) {
     default:
	  error(0, "copy: unknown message type: %d in %s() at %s:%d", _typ, func, file, line);
	  return NULL;
	  break;
#define NONE
#define ATTR(nm) if ((_aval = dict_get(_x->attributes, octstr_imm(#nm))) != NULL) \
                      dict_put(_y->attributes, octstr_imm(#nm), octstr_duplicate(_aval));  

#define ATTRIBUTES(attlist) if (_x->attributes != NULL) do {Octstr *_attr; _y->attributes =  dict_create(7, (void *)octstr_destroy); attlist} while(0);
#define Basic(nm,ver,attr,typ) case Imps_##nm: if (Imps_##typ == Imps_String)  \
           return pchar_to_String((void *)((String_t)msg)->str, ((String_t)msg)->len, Imps_##nm); \
    else \
      return msg; /* nothing to copy. Can't happen! */ \
   break;

#define Item(name,typ) if (MSG_GET_BIT(_x, _fct)) { \
          if (is_csp_struct(typ)) \
             _y->name = (typ##_t)csp_msg_copy((void *)_x->name); \
          else \
             _y->name = _x->name; \
      } \
      _fct++;

#define List(name,typ) if (MSG_GET_BIT(_x, _fct)) { \
         int _i, _n = gwlist_len(_x->name); \
         _y->name = gwlist_create(); \
         for (_i = 0; _i <_n; _i++) { \
             void *_z = gwlist_get(_x->name, _i); \
          if (is_csp_struct(typ)) \
             gwlist_append(_y->name,  csp_msg_copy(_z)); \
          else \
             gwlist_append(_y->name,_z); \
         } \
      } \
      _fct++;
#define UELEM(type) \
  else if (_utype == Imps_##type) { \
       if (is_csp_struct(type)) \
	  _oval = csp_msg_copy((void *)_val); \
       else \
          _oval = _val; \
  }
#define Union(name,elems)  if (MSG_GET_BIT(_x, _fct)) { \
  void *_val = (void *)_x->name.val, *_oval = NULL; \
  int _utype = _x->name.typ; \
  if (0) (void)0; \
    elems \
  _y->name.typ = _utype; \
   _y->name.val = _oval;\
   \
 } \
  ++_fct; 

#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname: do {\
    xname##_t _x = msg, _y; \
    unsigned long _fct = 0; \
    _y = gw_malloc(sizeof *_y); \
    memset(_y, 0, sizeof *_y); \
    _y->typ = Imps_##xname; \
    _y->_fieldset = _x->_fieldset; \
    if (_x->_content) _y->_content = octstr_duplicate(_x->_content); \
    do {parms} while (0); \
    _fct = 0; /*compiler shut up. */\
    return _y; \
    } while (0); \
    break;

#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
	  
     }    
}

static void _xcsp_msg_free(void *msg)
{
     csp_msg_free(msg);
}

static void free_String(String_t msg);
void csp_msg_free_real(void *msg, const char *file, const char *func, int line)
{
     int _typ;
     if (msg == NULL)
	  return;
     _typ = ((EmptyObject_t)msg)->typ;
     switch (_typ) {
     default:
	  error(0, "free: unknown message type: %d in %s() at %s:%d", _typ, func, file, line);
	  break;
#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) dict_destroy(_x->attributes);
#define Basic(nm,ver,attr,typ) case Imps_##nm: if (Imps_##typ == Imps_String)  \
           free_String(msg); /* else do nothing. */ \
   break;

#define Item(name,typ) if (MSG_GET_BIT(_x, _fct)) { \
          if (is_csp_struct(typ)) \
             csp_msg_free((void *)_x->name); \
      } \
      _fct++;

#define List(name,typ) if (MSG_GET_BIT(_x, _fct)) {			\
	    gwlist_destroy(_x->name,  is_csp_struct(typ) ? (void *)_xcsp_msg_free : NULL); \
	  }								\
      _fct++;
#define UELEM(type) \
  else if (_utype == Imps_##type) { \
       if (is_csp_struct(type)) \
	  csp_msg_free((void *)_val); \
  }
#define Union(name,elems)  if (MSG_GET_BIT(_x, _fct)) { \
  void *_val = (void *)_x->name.val; \
  int _utype = _x->name.typ; \
  if (0) (void)0; \
    elems \
 } \
  ++_fct; 

#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname: do {\
    xname##_t _x = msg; \
    unsigned long _fct = 0; \
    octstr_destroy(_x->_content); \
    attr \
    do {parms} while (0); \
    _fct = 0; /*compiler shut up. */ \
     gw_free(msg); \
    } while (0); \
    break;

#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
	  
     }    
}

int  csp_struct_clear_fields_real(void *msg, unsigned long mask, 
				  const char *file, const char *func, int line)
{
     int _typ;
     if (msg == NULL)
	  return -1;
     _typ = ((EmptyObject_t)msg)->typ;
     switch (_typ) {
     default:
	  error(0, "clear_children: unknown message type: %d in %s() at %s:%d", 
		_typ, func, file, line);
	  return -1;
	  break;

#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) dict_destroy(_x->attributes); _x->attributes = NULL; 
#define Basic(nm,ver,attr,typ) case Imps_##nm:   \
           panic(0, "struct_clear_children called with a non-struct type: %s at %s(), %s:%d", #nm, func, file, line);  \
   break;

#define Item(name,typ) if (MSG_GET_BIT(_x, _fct) && (_fmask & mask)) { \
          if (is_csp_struct(typ)) \
             csp_msg_free((void *)_x->name); \
      } \
      _fct++;  _fmask<<=1;

#define List(name,typ) if (MSG_GET_BIT(_x, _fct)  && (_fmask & mask)) { \
	       gwlist_destroy(_x->name,  is_csp_struct(typ) ? (void *)_xcsp_msg_free : NULL); \
	       _x->name = NULL;						\
      } \
      _fct++;  _fmask<<=1;
#define UELEM(type) \
  else if (_utype == Imps_##type) { \
       if (is_csp_struct(type)) \
	  csp_msg_free((void *)_val); \
  }
#define Union(name,elems)  if (MSG_GET_BIT(_x, _fct)  && (_fmask & mask)) { \
  void *_val = (void *)_x->name.val; \
  int _utype = _x->name.typ; \
  if (0) (void)0; \
    elems \
 } \
  ++_fct; _fmask<<=1;

#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname: do {\
    xname##_t _x = msg; \
    unsigned long _fct = 0, _fmask = 1; \
    octstr_destroy(_x->_content); _x->_content = NULL; \
    attr \
    do {parms} while (0); \
    _fct = 0; _fmask = 0; /*compiler shut up. */ \
     _x->_fieldset &= ~mask; /* We cleared all the ones that had to be cleared. */ \
    } while (0); \
    break;

#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
	  
     }    
     return 0;
}


int csp_struct_count_fields_real(void *msg, unsigned long *_fcount, unsigned long *_setcount,
				  const char *file, const char *func, int line)
{
     int _typ;
     
     if (msg == NULL)
	  return -1;
     _typ = ((EmptyObject_t)msg)->typ;
     
     *_fcount = csp_type_field_count(_typ);
     *_setcount = bit_count(((EmptyObject_t)msg)->typ);
     
     return 0;
}

static void free_String(String_t msg)
{
     if (msg == NULL)
	  return;
     dict_destroy(msg->attributes);
     gw_free(msg);     
}

String_t csp_String_from_data(char *s, int len, enum IMPsObjectType typ)
{
     String_t x = gw_malloc(len + sizeof *x);

     if (typ < 0 ||
	 typ > NELEMS(csp_types) ||
	 csp_types[typ].is_string == 0)
	  panic(0, "string_from_data: attempt to create a string object for something [%d:%s] that's not a string!",
		(int)typ, csp_obj_name(typ));
     
     x->typ = typ;
     x->len = len;
     x->attributes = NULL;    
     memcpy(x->str, s, len);
     
     x->str[len] = 0; /* add null byte. */
     
     return x;     
}

unsigned csp_type_field_count_real(int type, const char *file, const char *func, int line)
{
     switch(type) {
     default:
	  panic(0, "csp_type_field_count: unknown type: %d in %s() at %s:%d", 
		type, func, file, line);
	  break;
	  
#define NONE
#define Basic(nm,ver,attr,typ) case Imps_##nm: return 0; break;

#define Item(name,typ)  + 1 
#define List(name, typ) Item(name,typ) /* re-use above macro. */

#define UELEM(type) 
#define Union(name,elems) Item(name,1)
#define ATTR(nm)
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname: \
           return 0 parms + 0; break; 

#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     

     }
     gw_assert(0);
     return 0;
}

#define VERIFY_OBJ_TYPE(xobj,typ) do { \
        int _xtype = is_csp_struct(typ) && (xobj) ? CSP_MSG_TYPE(xobj) : -1; \
        if (is_csp_struct(typ) && (xobj) && _xtype != (Imps_##typ)) \
            panic(0, "%s: object [address=%d] has wrong type [%d:%s], should be: %s", __FUNCTION__, (int)(xobj), \
_xtype, csp_obj_name(_xtype), \
csp_obj_name(Imps_##typ)); \
  } while(0)
/* creates a new struct: Note that only one attribute is supported -- xmlns.  */
void *csp_msg_new_real(int type, Octstr *xmlns, ...)
{
     char *fname;
     unsigned long size = csp_struct_size(type);
     void *obj;
     va_list ap;
     
     gw_assert(size > 0);
     obj = gw_malloc(size);
     memset(obj, 0, size);
     ((EmptyObject_t)obj)->typ = type;     
     va_start(ap, xmlns);      
     switch (type) {
     default:
	  panic(0, "csp_msg_new: unknown type: %d", type);
	  break;
#define NONE
#define List_t List * /* so that we can re-use Item macro below */
#define Imps_List Imps_Boolean /* so that no check is done. */
#define Basic(nm,ver,attr,typ) case Imps_##nm: panic(0, "csp_msg_new can not be used to create a '%s' object!", #nm); break;

#define Item(name,typ) if (strcmp(fname,#name) == 0) { \
         xres->name = (typ##_t)va_arg(ap, typ##_t); \
         VERIFY_OBJ_TYPE(xres->name, typ); \
         MSG_SET_BIT(xres, _fct); \
         continue; \
       } \
      _fct++;
#define List(name, typ) Item(name,List) /* re-use above macro. */

#define UELEM(type) else if (utype == Imps_##type) {*_val = (void *)va_arg(ap, type##_t); \
         VERIFY_OBJ_TYPE(*_val, type); \
 } 
#define Union(name,elems) if (strcmp(fname,#name) == 0) { \
         void **_val = &xres->name.val; \
         int utype = va_arg(ap, int); \
         xres->name.typ =  utype; \
         do {if (0) (void)0; elems} while (0); \
         MSG_SET_BIT(xres, _fct); \
         continue; \
       } \
      _fct++;

#define ATTR(nm)
/* next one is severely kludged, but in practice will be ok. */
#define ATTRIBUTES(a) if (xmlns) {xres->attributes = dict_create(7, (void *)octstr_destroy); \
                     dict_put(xres->attributes, octstr_imm("xmlns"), octstr_duplicate(xmlns)); \
                    }
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname: do {	\
	       xname##_t xres = obj;					\
	       attr							\
	       while ((fname = va_arg(ap, char *))!= NULL) {		\
		    unsigned long _fct = 0;				\
		    if (strcasecmp(fname, "_content") == 0) {/*support these.*/	\
			 xres->_content = va_arg(ap, Octstr *);		\
			 continue;					\
		    }							\
		    parms						\
		    if (_fct > 0) {va_arg(ap, void *); panic(0, "structure [%s] has no field '%s'!", #xname, fname);} /* should not be reached. */ \
           } \
          xres = obj; /* so compiler shuts up. */ \
         } while (0); \
	 break; 

#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
#undef Imps_List
     }
     va_end(ap);
     return obj;
}

#undef List_t

int csp_version(char *xmlns)
{
     const char *endmarker = "CSP";
     char *p;
     int major = 1, minor = 0;
     
     if (xmlns == NULL)
       return 0x10;
     else if ((p = strstr(xmlns, endmarker)) != NULL)
	  p += strlen(endmarker);
     else 
	  return 0x10; /* assume version 1.0 */
     
     sscanf(p, "%d.%d", &major, &minor);
     return CSP_VERSION(major, minor);
}

/* works for structures only. */
int csp_empty_struct(void *obj)
{ 
     return (obj == NULL) || ((EmptyObject_t)obj)->_fieldset == 0;     
}

unsigned long csp_msgtype_get_field_bitmask_real(const char *func, const char *file, int line, 
					     int msgtype, const char *field)
{
     switch (msgtype) {
#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) 
	  
#define Item(name,typ)  if (strcmp(#name, field) == 0)  return _fct; _fct<<=1; 
#define List(name,typ)    Item(name,0)
#define Union(name,elems) Item(name,0)
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname :	\
	  do { unsigned long _fct = 1;					\
	       parms							\
		    panic(0, "get_field_bitmask: structure %s has no field %s: called from %s(), at %s:%d!", \
			  #xname,field,  func, file, line);		\
	       _fct = 0;						\
	  } while (0);							\
	  break;
#include "cspmessages.def"
     default: 
	  error(0, "csp_get_field_bitmask_real: unknown object type code: %d in %s() at %s:%d", 
		msgtype, func, file, line);
	  break;
     }
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
     
     return 0; 
}

unsigned long csp_msg_get_field_bitmask_real(const char *func, const char *file, int line, 
					     void *msg, const char *field)
{
     return csp_msgtype_get_field_bitmask_real(func,file,line,CSP_MSG_TYPE(msg), field);
}

int csp_msg_field_isset_real(const char *func, const char *file, int line, 
			     void *msg, const char *field)
{
     unsigned mask = csp_msg_get_field_bitmask_real(func,file,line,msg, field);
     
     return (((EmptyObject_t)msg)->_fieldset & mask) != 0;
}

int csp_get_nth_field_isset_real(void *msg, unsigned fnum, const char *func, const char *file, int line)
{
     unsigned long mask;
     
     gw_assert(fnum<8*sizeof mask); 
     
     mask = 1<<fnum;     
     if (msg == NULL)
	  return 0;
     else 
	  return (((EmptyObject_t)msg)->_fieldset & mask) != 0;
}

static void *empty_value_for_type(int typ)
{
     if (csp_types[typ].is_string) 
	  return (void *)csp_String_from_cstr("",typ);
     else if (csp_types[typ].is_struct)
	  return csp_msg_new_real(typ, NULL,NULL);
     else 
	  return NULL;
}

void csp_msg_init_fields_real(const char *func, const char *file, int line, 
			      void *msg, unsigned long mask)
{

     gw_assert(csp_empty_struct(msg) == 1);
     
     switch (((EmptyObject_t)msg)->typ) {
#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) 
	  
#define Item(name,typ)  if (mask & _fmask) {\
                               xmsg->name = (typ##_t)empty_value_for_type(Imps_##typ); \
                               MSG_SET_BIT(xmsg,_fct); \
                         } \
                       _fmask<<=1; _fct++;
#define List(name,typ) if (mask & _fmask) {\
                    typ##_t _x = (typ##_t)empty_value_for_type(Imps_##typ); \
                    xmsg->name = gwlist_create_ex(_x); \
                    MSG_SET_BIT(xmsg,_fct); \
                   } \
                   _fmask<<=1; _fct++;

#define UELEM(type) *_utype = Imps_##type; *_val = empty_value_for_type(Imps_##type); break;
#define Union(name,elems) if (mask & _fmask) {\
                        enum IMPsObjectType *_utype =  &xmsg->name.typ; \
                        void **_val = &xmsg->name.val; \
                        do { elems} while(0); \
                        MSG_SET_BIT(xmsg,_fct); \
              }    _fmask<<=1; _fct++;
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname : \
                         do { xname##_t xmsg = msg; unsigned long _fct = 0; unsigned long _fmask = 1; \
                             parms \
                           _fct = 0; _fmask = 0; xmsg = NULL; \
			} while (0); \
                          break;
#include "cspmessages.def"
     default: 
	  error(0, "init_fields: unknown object type code: %d in %s() at %s:%d", 
		((EmptyObject_t)msg)->typ, func, file, line);
	  break;
     }
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
     
}

/* structures and arrays for number to field mappings. */



static struct imps_struct_fields_t _empty_objects_a[] = {
     {NULL, -1, INone}
};

#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) 
	  
#define Item(name,typ) {#name, Imps_##typ, ISingleton},                        
#define List(name,typ)  {#name, Imps_##typ, IList},  
#define UELEM(type) 
#define Union(name,elems) {#name, -1, IUnion}, 
#define Structure(xname,hastag,ver,attr, parms) static struct imps_struct_fields_t _##xname##_type_array[] = {parms};
#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     

/* the array itself. */
const struct imps_struct_fields_t *struct_types[] = {

#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) [Imps_##nm] = _empty_objects_a,

#define Item(name,typ)
#define List(name,typ)
#define Union(name,elems)
#define Structure(xname,hastag,ver,attr, parms) [Imps_##xname] = _##xname##_type_array,
#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
};

void *csp_msg_get_field_value_real(const char *func, const char *file, int line, void *msg, int field_num)
{
     switch (((EmptyObject_t)msg)->typ) {
#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) 

#define Item(name,typ)  if (_fct == field_num)  {if (MSG_GET_BIT(xmsg,_fct) == 0) \
	   panic(0, "get_field_value [%s:%d]: field #%d (%s) of object[%s] is not set!", file, line, field_num, #name,_msg_name); \
                        return (void*)(xmsg)->name;} _fct++; /* no curly braces! */
#define List(name,typ)    Item(name,0) /* same thing. */
#define Union(name,elems) if (_fct == field_num) {			\
	 panic(0, "get_field_value[%s:%d]: field %s [#%d] is a union. use get_union_value!", file,line,#name, field_num); \
                          } _fct++;
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname : \
                     do { \
                         xname##_t xmsg = msg; unsigned long _fct = 0; \
			 char *_msg_name = #xname;			\
                         parms						\
			   panic(0, "get_field_value[%s:%d]: structure %s has no field number %d!", file,line,_msg_name,field_num); \
                        _fct = 0; xmsg = NULL; \
                     } while (0); \
                     break;
#include "cspmessages.def"
     default: 
	  error(0, "csp_get_field_value: unknown object type code: %d in %s() at %s:%d", 
		((EmptyObject_t)msg)->typ, func, file, line);
	  break;
     }
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
     return NULL;
}

void *csp_msg_get_union_field_value_real(const char *func, const char *file, int line, void *msg, int field_num, int *type)
{

     gw_assert(type);
     

     switch (((EmptyObject_t)msg)->typ) {
#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) 

#define Item(name,typ)  if (_fct == field_num)  { \
                        panic(0, "get_union_value: field #%d (%s) is not a union!", field_num, #name); \
                        } _fct++; /* no curly braces! */
#define List(name,typ)    Item(name,0) /* same thing. */
#define Union(name,elems) if (_fct == field_num) {\
                        if (MSG_GET_BIT(xmsg,_fct) == 0) \
                            panic(0, "get_field_value: field #%d (%s) is not set!", field_num, #name); \
                         *type = xmsg->name.typ; \
                         return xmsg->name.val; \
                          } _fct++;
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname : \
                     do { \
                         xname##_t xmsg = msg; unsigned long _fct = 0; \
                         parms \
                        panic(0, "get_union_value: structure %s has no field number %d!", #xname,field_num); \
                        _fct = 0; xmsg = NULL; \
                     } while (0); \
                     break;
#include "cspmessages.def"
     default: 
	  error(0, "csp_get_field_value: unknown object type code: %d in %s() at %s:%d", 
		((EmptyObject_t)msg)->typ, func, file, line);
	  break;
     }
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
     *type = -1;
     return NULL;
}

void *csp_msg_copy_field_value_real(void *msg, int field_num, const char *func, const char *file, int line)
{
     int type, ftype, isstruct;
     void *val;
     
     gw_assert(msg);

     type = ((EmptyObject_t)msg)->typ;

     val = csp_msg_get_field_value(msg,field_num); /* will crash on error. */
     
     ftype = struct_types[type][field_num].type;
     isstruct  = csp_types[ftype].is_struct;
     
     if (struct_types[type][field_num].nature == IList && val) { /* make a copy of the list */
	  List *l = gwlist_create();
	  int i, n = gwlist_len(val);
	  
	  for (i = 0; i<n; i++) {
	       void *x = gwlist_get(val, i);
	       gwlist_append(l, isstruct ? csp_msg_copy(x) : x);
	  }
	  return l;
     } else if (isstruct)
	  return csp_msg_copy(val);
     else 
	  return val;
}

void *csp_msg_copy_union_field_value_real(void *msg, int field_num, int *utype, const char *func, const char *file, int line)
{
     int type, ftype, isstruct;
     void *val;
     
     gw_assert(msg);

     type = ((EmptyObject_t)msg)->typ;

     val = csp_msg_get_union_field_value(msg,field_num,utype); /* will crash on error. */
     
     ftype = *utype;
     isstruct  = csp_types[ftype].is_struct;
     
     if (struct_types[type][field_num].nature == IList && val) { /* make a copy of the list: Can't (yet) happen for a Union element. */
	  List *l = gwlist_create();
	  int i, n = gwlist_len(val);
	  
	  for (i = 0; i<n; i++) {
	       void *x = gwlist_get(val, i);
	       gwlist_append(l, isstruct ? csp_msg_copy(x) : x);
	  }
	  return l;
     } else if (isstruct)
	  return csp_msg_copy(val);
     else 
	  return val;
}


#define List_t List*

int csp_msg_set_field_value_real(void *msg, int field_num, void *value, const char *func, const char *file, int line)
{
     switch (((EmptyObject_t)msg)->typ) {
#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) 

#define Item(name,typ)  if (_fct == field_num)  {if (MSG_GET_BIT(xmsg,_fct)) \
                        panic(0, "set_field_value: field #%d (%s) is already set!", field_num, #name); \
                        (xmsg)->name = (typ##_t)value; MSG_SET_BIT(xmsg,_fct); return 0;} _fct++; /* no curly braces! */
#define List(name,typ)    Item(name,List) /* same thing. */
#define Union(name,elems) if (_fct == field_num) {\
                               panic(0, "set_field_value: field %s [#%d] is a union. use set_union_value!", #name, field_num); \
                          } _fct++;
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname : \
                     do { \
                         xname##_t xmsg = msg; unsigned long _fct = 0; \
                         parms \
                        panic(0, "set_field_value: structure %s has no field number %d!", #xname,field_num); \
                        _fct = 0; xmsg = NULL; \
                     } while (0); \
                     break;
#include "cspmessages.def"
     default: 
	  error(0, "csp_set_field_value: unknown object type code: %d in %s() at %s:%d", 
		((EmptyObject_t)msg)->typ, func, file, line);
	  break;
     }
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
#undef List_t
     return -1;
}

int csp_msg_set_union_field_value_real(void *msg, int field_num, int utype, void *value, const char *func, const char *file, int line)
{
 
     switch (((EmptyObject_t)msg)->typ) {
#define NONE
#define ATTR(nm)
#define ATTRIBUTES(a) 
#define Basic(nm,ver,attr,typ) 

#define Item(name,typ)  if (_fct == field_num)  { \
                        panic(0, "set_union_value: field #%d (%s) is not a union!", field_num, #name); \
                        } _fct++; /* no curly braces! */
#define List(name,typ)    Item(name,0) /* same thing. */
#define Union(name,elems) if (_fct == field_num) {\
                        if (MSG_GET_BIT(xmsg,_fct)) \
                            panic(0, "set_field_value: field #%d (%s) is already set!", field_num, #name); \
                         xmsg->name.typ = utype; \
                         xmsg->name.val = value; \
                         MSG_SET_BIT(xmsg,_fct); \
                         return 0; \
                          } _fct++;
#define Structure(xname,hastag,ver,attr, parms) case Imps_##xname : \
                     do { \
                         xname##_t xmsg = msg; unsigned long _fct = 0; \
                         parms \
                        panic(0, "set_union_value: structure %s has no field number %d!", #xname,field_num); \
                        _fct = 0; xmsg = NULL; \
                     } while (0); \
                     break;
#include "cspmessages.def"
     default: 
	  error(0, "csp_set_union_field_value: unknown object type code: %d in %s() at %s:%d", 
		((EmptyObject_t)msg)->typ, func, file, line);
	  break;
     }
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTR
#undef ATTRIBUTES
#undef UELEM
#undef NONE     
     return -1;
}


int csp_get_field_num_from_type_real(int type, const char *field_name, const char *func, const char *file, int line)
{
     int i, n;
          
     n = csp_type_field_count(type);
     
     for (i = 0; i<n; i++)
	  if (strcmp(struct_types[type][i].field_name, field_name) == 0)
	       return i;
     
     return -1;
}

void csp_update_xmlns(void *obj, char *xmlns)
{
     EmptyObject_t msg = obj;

     if (msg == NULL)
	  return;

     if (msg->attributes == NULL) 
	  msg->attributes = dict_create(7, (void *)octstr_destroy);
     dict_put(msg->attributes, octstr_imm("xmlns"), octstr_create(xmlns));
}
