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
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include "json.h"
#include "utils.h"

#define SKIP_SPACE() do {					\
	  while (*pos <octstr_len(in) &&			\
		 (ch = octstr_get_char(in, *pos)) != -1 &&	\
		 isspace(ch))					\
	       ++*pos;						\
     } while (0)


#define DEFAULT_NAME_LEN 64
/* JSON parsing and generation. */

typedef struct JValue_t *JValue_t;

/* NOTE: Strings must be URL-encoded, e.g. using javascript escape() function.
 * lib will also encode them as such
 */
static JValue_t parse_json_value(Octstr *val);
static void free_json_value(JValue_t);

enum JTypes_t {
     JSON_TYPE_EMPTY=0, 
     JSON_TYPE_INT = 1, 
     JSON_TYPE_STRING = 2, 
     JSON_TYPE_BOOL = 4,
     JSON_TYPE_RECORD=8, 
     JSON_TYPE_LIST=16
};

struct JValue_t {
     enum JTypes_t type;
  
     union {
	  long ival;
	  Octstr *sval;
	  Dict *rval; /* field values, indexed by field name -- for record values*/
	  List *lval; /* List of JValue_t -- for list values */
	  int bval;   /* for boolean. */
     } u;
};


static JValue_t parse_json_value_real(Octstr *in, long *pos);
static int getword(char *str, char buf[], int lim)
{
     char *p = buf;
     
     while (isalnum(*str) && 
	    p-buf < lim)
	  *p++ = *str++;

     *p = 0; /* null terminate. */

     while (*str && isalnum(*str)) /* skip over rest of it, if we stopped above for len.*/
	  str++; 
     return p - buf;
}

static JValue_t parse_field(Octstr *in, long *pos, char fname[], int lim)
{

     int ch, len, has_quote;
     
     SKIP_SPACE();

     if ((ch = octstr_get_char(in, *pos)) == '"' || 
	 ch == '\'') { /* name starts with quote. */
	  has_quote = ch;
	  ++*pos;
     } else 
	  has_quote = 0;
     
     len = getword(octstr_get_cstr(in) + *pos, fname, lim);
     
     if (len == 0)  /* field name is required. */
	  return NULL; 
     else 
	  (*pos) += len;

     if (has_quote)
	  ++*pos;  /* skip over quote. */

     SKIP_SPACE();     
     if ((ch = octstr_get_char(in, *pos)) != ':')  /* marks start of value. */
	  return NULL;
     else 
	  ++*pos;
          
     return parse_json_value_real(in, pos);
}

static JValue_t make_value(int type, void *value)
{
     JValue_t val = gw_malloc(sizeof *val);

     val->type = type;
     val->u.rval = value;

     return val;
}


static struct { 
	  int ch, esc;	  
} esc_codes[] = {
     {'\n', 'n'},
     {'\t', 't'},
     {'\r', 'r'},
     {'\v', 'v'},
     {'\v', 'v'},
     {'\b', 'b'},
     {'\f', 'f'},
     {'\'', '\''},
     {'\"', '\"'},
     {'\\', '\\'}     
};

static Octstr *parse_str(Octstr *in, long *pos, int quote_char)
{
     Octstr *out;
     int ch = -1;
     
     if (in == NULL || pos == NULL) 
	  return NULL;

     out = octstr_create("");
     
     while (++(*pos) < octstr_len(in) && 
	    (ch = octstr_get_char(in, *pos)) != quote_char) {
	  if (ch == '\\') { /* escape sequence. */
	       int j, ch2 = octstr_get_char(in, ++(*pos));
	       
	       /* we have a couple of options:
		* - x ==> hex format
		* - octal digit ==> octal number
		* - u ==> unicode format.
		* - anything else is potentially an escape sequence. 
		*/
	       if (ch2 == 'x') {
		    char *p = octstr_get_cstr(in) + *pos + 1;
		    sscanf(p, "%2x", &ch);
		    *pos += 2;
	       } else if (ch2 == 'u') {
		    Octstr *x = octstr_copy(in, *pos + 1, 4), *y = NULL;
		    char *enc = (void *)xmlGetCharEncodingName(XML_CHAR_ENCODING_UCS2);

		    octstr_hex_to_binary(x);		    
		    if (charset_to_utf8(x, &y, octstr_imm(enc)) < 0) 
			 error(0, "json_from: failed to convert UCS sequence in [%.4s]", 
			       octstr_get_cstr(x));
		    else {
			 ch = -1;
			 octstr_append(out, y);
		    }
		    octstr_destroy(x);
		    octstr_destroy(y);
		    *pos += 4;
	       } else if (ch2 >= '0' && ch2 <= '8') { /* octal */
		    char *p = octstr_get_cstr(in) + (*pos);
		    
		    sscanf(p, "%3o", &ch);
		    *pos += 2;
	       } else {	/* ordinary escape sequence. */	    
		    for (j = 0; j<NELEMS(esc_codes); j++)
			 if (esc_codes[j].esc == ch2) {
			      ch = esc_codes[j].ch;
			      break;
			 }
		    if (j >= NELEMS(esc_codes))  {
			 error(0, "json_from: invalid escape sequence: \\%cin string", ch2);
			 ch = -1;
		    }
		    
	       }
	  }
	  if (ch >= 0) 
	       octstr_append_char(out, ch);
     }

     if (ch == quote_char) /* remove string quote */
	  ++*pos;  
     /* URL decode */
     if (out)
	  octstr_url_decode(out);
     return out;
}

static JValue_t parse_json_value_real(Octstr *in, long *pos)
{
     JValue_t val = NULL;
     int ch;


     SKIP_SPACE();
         
     /* first char tells you what you have. */

     ch = octstr_get_char(in, *pos);     
     if (ch < 0) 
	  return NULL;
     
     ch = tolower(ch);

     if (ch == '{') { /* record. */
	  JValue_t fld;
	  char fname[DEFAULT_NAME_LEN];
	  Dict *d = dict_create(7, (void *)free_json_value);

	  ++*pos; 
	  while ((fld = parse_field(in, pos, fname, sizeof fname)) != NULL) {
	       Octstr *x = octstr_create(fname);
	       
	       dict_put(d, x, fld);
	       
	       octstr_destroy(x);
	       SKIP_SPACE();
	       
	       /* look for a comma. */	       
	       if ((ch = octstr_get_char(in, *pos)) != ',')
		    break; /* done. */
	       ++*pos;	       
	  }
	  
	  SKIP_SPACE();
	  /* at this point we must have the closing brace. */
	  ++*pos;
	  val = make_value(JSON_TYPE_RECORD, d);
     } else if (ch == '[') { /* list. */
	  List *l = gwlist_create();
	  JValue_t item;

	  ++*pos; 
	  
	  while ((item = parse_json_value_real(in, pos)) != NULL) {
	       gwlist_append(l, item);
	       
	       SKIP_SPACE();

	       /* look for a comma. */	       
	       if ((ch = octstr_get_char(in, *pos)) != ',')
		    break; /* done. */
	       ++*pos;
	  }
	  /* at this point we must have the closing brace. */
	  ++*pos;
	  val = make_value(JSON_TYPE_LIST, l);
     } else if (isdigit(ch)) { /* an integer */
	  char *p = octstr_get_cstr(in) + *pos, *q = p;
	  long lval = strtoul(p, &q, 10);
	  
	  val = make_value(JSON_TYPE_INT, (void *)lval);
	  *pos += q-p;	  	  
     } else if (ch == '"' || ch == '\'') { /* a string literal. */
	  Octstr *sval = parse_str(in, pos, ch);
	  val = make_value(JSON_TYPE_STRING, sval);
     } else if (ch == 'f' || ch == 't') { /* boolean, I hope. */
	  char buf[64], *p;
	  int bval;
	  
	  for (p = buf; (ch = octstr_get_char(in, *pos)) > 0 && isalpha(ch); ++*pos) 
	       if (p < buf + sizeof buf)
		    *p++ = ch;
	  *p = 0;

	  bval = (strcasecmp(buf, "true") == 0);
	  val = make_value(JSON_TYPE_BOOL, (void *)bval);
     } else    /* other values (e.g. null) */
	  for (; (ch = octstr_get_char(in, *pos)) > 0 && isalnum(ch); ++*pos) 
	       ;
     

     return val;
}

static JValue_t parse_json_value(Octstr *in)
{
     long pos = 0;
     
     octstr_strip_blanks(in);
     
     return parse_json_value_real(in, &pos);
}

static void free_json_value(JValue_t jval)
{
     if (jval == NULL)
	  return;
     
     switch(jval->type) {
     case JSON_TYPE_LIST:
	  gwlist_destroy(jval->u.lval, (void *)free_json_value);
	  break;
     case JSON_TYPE_RECORD:
	  dict_destroy(jval->u.rval);
	  break;
     case JSON_TYPE_STRING:
	  octstr_destroy(jval->u.sval);
	  break;
     default:
	  
	  break;
     }
     gw_free(jval);
}


static void escape_str(Octstr *in)
{
     int i, len;
     Octstr *out;
     if (in == NULL) 
	  return;
     out = octstr_create("");
     for (i = 0, len = octstr_len(in); i<len; i++) {
	  int ch = octstr_get_char(in, i);
	  int j;
	  
	  for (j = 0; j <NELEMS(esc_codes); j++) 
	       if (ch == esc_codes[j].ch) {
		    octstr_format_append(out, "\\%c", esc_codes[j].esc);		    
		    goto loop;
	       }	  	 
	  if (isprint(ch)) /* no escape sequence. */
	       octstr_append_char(out, ch);
	  else 
	       octstr_format_append(out, "\\x%02x", ch);	  
     loop:
	  (void)0;
     }
     octstr_delete(in, 0, len);
     octstr_append(in, out);
     
     octstr_destroy(out);
}

#define xstr_pad(xos, xlev) do {					\
	  int _pcount = xlev;						\
	  while (--_pcount > 0) octstr_append_char((xos), '\t');	\
     } while (0)


#define xadd_fname(xos, xlev, xfname, add_comma) do {	\
	  xstr_pad(xos, xlev); \
	  octstr_format_append(os, "%s\"%s\": ", (add_comma) ? ", " : "", (xfname)); \
     } while (0)


/* Generate JSON value from a CSP message. Note how we ignore attributes: 
 * they convey no information apart from version, which we assume anyway.
 */
static Octstr *generate_json_value(void *msg, int objtype, int lev)
{
     Octstr *os = NULL;
     
     switch(objtype) {
#define Basic(name,ver,a,type) case Imps_##name:			\
	  if (Imps_##type == Imps_String && msg) {			\
	       if (msg) {						\
		    os = csp_String_to_bstr((String_t)msg);		\
		    escape_str(os);					\
		    octstr_url_encode(os);				\
		    octstr_append_char(os, '"');			\
		    octstr_insert_char(os, 0, '"');			\
	       }							\
	  } else if (Imps_##type == Imps_Integer)			\
	       os = octstr_format("%ld", (long)msg);			\
	  else if (Imps_##type == Imps_Boolean)				\
	       os = octstr_create((msg) ? "true" : "false");		\
	  else if (Imps_##type == Imps_Date) {				\
	       os = date_create_iso((time_t)msg);			\
	       octstr_append_char(os, '"');				\
	       octstr_insert_char(os, 0, '"');				\
	  } else if (Imps_##type == Imps_EmptyTag)			\
	       os = octstr_create("1");					\
	  else /* unknown value */					\
	       os = octstr_create("null");				\
	  break;
	  
#define Item(name,typ)							\
	  if (MSG_GET_BIT(xmsg,_fct) &&					\
	      (_x = generate_json_value((void *)xmsg->name, Imps_##typ, lev+1)) != NULL) { \
	       xadd_fname(os, lev, #name,fcount>0);				\
	       octstr_append(os, _x);			\
	       octstr_destroy(_x);					\
	       fcount++;						\
	  }								\
	  _fct++;

#define List(name,typ) if (MSG_GET_BIT(xmsg,_fct)) {			\
	       int _i = 0, _n = gwlist_len(xmsg->name);			\
	       xadd_fname(os, lev, #name,fcount>0);				\
	       octstr_append_cstr(os, "[\n");				\
	       while (_i < _n) {					\
		    void *_y = gwlist_get(xmsg->name, _i);		\
		    if ((_x = generate_json_value(_y, Imps_##typ,lev+1)) != NULL) { \
			 octstr_format_append(os, "%s%S ",(_i>0) ? ", " : "", _x); \
			 octstr_destroy(_x);				\
		    }							\
		    _i++;						\
	       }							\
	       octstr_format_append(os, " ]");				\
	       fcount++;						\
	  }								\
	  _fct++; 

#define UELEM(type) else if (_typ == Imps_##type) {			\
	       if ((_x = generate_json_value(_val, _typ, lev+1)) != NULL) { \
		    octstr_append(os, _x);				\
		    octstr_destroy(_x);					\
	       }							\
	  }

#define Union(name, elems)  do {					\
	       void *_val = (void *)xmsg->name.val;			\
	       int _typ = xmsg->name.typ;				\
	       if (MSG_GET_BIT(xmsg,_fct)) {				\
		 xadd_fname(os, lev, #name,fcount>0);				\
		    octstr_format_append(os, "{\"type\": \"%s\", \"value\": ", \
					 csp_obj_name(_typ));		\
		    do {if (0)						\
			      (void)0;					\
			 elems	/* enumerate elements. */		\
			 else						\
			      octstr_append_cstr(os, "null");		\
		    } while (0);					\
		    octstr_append_cstr(os, "}");			\
		    fcount++;						\
	       }							\
	       _fct++;							\
	  } while (0);

#define NONE  /* nothing. */
#define Structure(name,hastag,v,a,parms) case Imps_##name:		\
	  if (msg) {							\
	       Octstr *_x = NULL;					\
	       name##_t xmsg = msg;					\
	       unsigned long _fct = 0, fcount = 0;			\
	       os = octstr_create("{\n");				\
	       do {parms} while (0);					\
	       octstr_append_char(os,'\n');				\
	       if (xmsg->_fieldset == 0 && octstr_len(xmsg->_content) > 0) { \
		    _x = octstr_duplicate(xmsg->_content);		\
		    octstr_url_encode(_x);				\
		    octstr_format_append(os, " \"_content\": \"%S\"\n", _x); \
		    octstr_destroy(_x);					\
	       }							\
	       xstr_pad(os, lev-1);					\
	       octstr_append_cstr(os, "\n}\n");				\
	       _fct = 0;	/* so compiler shuts up. */		\
	       xmsg = NULL;						\
	       _x = NULL;						\
	       fcount = 0;						\
	  }								\
	  break;
#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef UELEM
#undef NONE

     default:
	  break;
     }
     return os;
}

Octstr *make_json_packet(WV_CSP_Message_t msg)
{     
     return generate_json_value(msg, Imps_WV_CSP_Message, 0);
}

int check_type_compat(int msgtype, enum JTypes_t jval_type)
{
     if ((msgtype == Imps_String || msgtype == Imps_Date) && 
	 jval_type != JSON_TYPE_STRING)
	  return -1;
     else if (msgtype == Imps_Integer && jval_type != JSON_TYPE_INT)
	  return -1;
     else if (msgtype == Imps_Boolean && jval_type != JSON_TYPE_BOOL)
	  return -1;
     else 
	  return 0; /* all other conditions are ok: implies that Empty can be any value. */
}


static int csp_msg_from_jvalue(JValue_t val, int msgtype, void **res)
{

     *res = NULL; 
     if (val == NULL) 
	  return -1;
     
     switch(msgtype) {
#define Basic(name,ver,a,typ) case Imps_##name:			\
	  if (check_type_compat(Imps_##typ, val->type) != 0)		\
	       return -1;						\
	  else if (Imps_##typ == Imps_String) 			\
	       *res = csp_String_from_bstr(val->u.sval, Imps_##name);	\
	  else if (Imps_##typ == Imps_Integer)				\
	       *res = (void *)val->u.lval;				\
	  else if (Imps_##typ == Imps_Boolean)				\
	       *res = (void *)val->u.bval;				\
	  else if (Imps_##typ == Imps_Date) {				\
	       struct universaltime ut;					\
	       if (date_parse_iso(&ut, val->u.sval) < 0)		\
		    return -1;						\
	       else							\
		    *res = (void *)date_convert_universal(&ut);		\
	  }  else if (Imps_##typ == Imps_EmptyTag)			\
	       *res = (void *)1;					\
	  else /* unknown value */					\
	       *res = NULL;						\
	  break;

#define Item(name,typ)							\
	  if ((_x = dict_get(val->u.rval, octstr_imm(#name))) != NULL && \
	      csp_msg_from_jvalue(_x, Imps_##typ, &xres) == 0) {	\
	       xmsg->name = (typ##_t)xres;				\
	       MSG_SET_BIT(xmsg, _fct);					\
	  }								\
	  _fct++;
	  
#define List(name,xtyp) if ((_x = dict_get(val->u.rval, octstr_imm(#name))) != NULL && \
			   _x->type == JSON_TYPE_LIST) {		\
	       int _i = 0, _n = gwlist_len(_x->u.lval);			\
	       while (_i < _n) {					\
		    JValue_t _y = gwlist_get(_x->u.lval, _i);		\
		    if (csp_msg_from_jvalue(_y, Imps_##xtyp,&xres) == 0) { \
			 if (xmsg->name == NULL) xmsg->name = gwlist_create(); \
			 gwlist_append(xmsg->name, xres);		\
		    }							\
		    _i++;						\
	       }							\
	       if (xmsg->name) MSG_SET_BIT(xmsg,_fct);			\
	  } else if (_x) /* we parsed. */ 				\
	       error(0, "parse[object=%s, field=%s] got wrong jvalue object type [%d], expected list", \
		     csp_obj_name(xmsg->typ), #name, _x->type);		\
	  _fct++; 

#define UELEM(type) else if (xtype_val == Imps_##type) {		\
	  if (csp_msg_from_jvalue(xvalue, Imps_##type, &_uval) == 0) 	\
	       _lfound = 1;						\
     }
	  
#define Union(name, elems)  if ((_x = dict_get(val->u.rval, octstr_imm(#name))) != NULL && \
				_x->type == JSON_TYPE_RECORD &&		\
				_x->u.rval != NULL )  {		\
		    JValue_t xtype = dict_get(_x->u.rval, octstr_imm("type")); \
		    JValue_t xvalue =  dict_get(_x->u.rval, octstr_imm("value")); \
		    Octstr *xtype_str = (xtype && xtype->type == JSON_TYPE_STRING) ? xtype->u.sval : NULL; \
		    int xtype_val = xtype_str ? csp_name_to_type(octstr_get_cstr(xtype_str)) : -1; \
		    void *_uval = NULL;					\
		    int _lfound = 0;					\
		    do {						\
			 if (0)						\
			      (void)0;					\
		    elems	/* enumerate elements. */		\
			 else						\
			      _lfound = 0;				\
		    } while (0);					\
		    if (_lfound) {					\
			 xmsg->name.typ = xtype_val;			\
			 xmsg->name.val = _uval;			\
			 MSG_SET_BIT(xmsg,_fct);			\
		    }							\
		    _fct++;						\
	  } else if (_x) /* we parsed. */				\
	       error(0, "parse[object=%s, field=%s] got wrong jvalue object type [%d], expected record", \
		     csp_obj_name(xmsg->typ), #name, _x->type);		\

#define NONE  /* nothing. */
#define Structure(name,hastag,v,a,parms) case Imps_##name:		\
	  if (val->type != JSON_TYPE_RECORD) {				\
	       error(0, "parse[%s] called with something [%d] not a record jvalue!", \
		     #name, val->type);					\
	       return -1;						\
	  } else if (val->u.rval == NULL)				\
	       return -1;						\
	  else {							\
	       JValue_t _x = NULL;					\
	       void *xres = NULL;					\
	       name##_t xmsg = (*res) = csp_msg_new(name, NULL, NULL);	\
	       unsigned long _fct = 0;					\
	       do {parms} while (0);					\
	       if ((_x = dict_get(val->u.rval, octstr_imm("_content"))) != NULL) { \
		    if (_x->type == JSON_TYPE_STRING)			\
			 xmsg->_content = octstr_duplicate(_x->u.sval); \
		    else						\
			 warning(0, "parse[%s]: _content element has unexpected type [%d]", \
				 #name, _x->type);			\
	       }							\
	       _fct = 0;	/* so compiler shuts up. */		\
	       xmsg = NULL;						\
	       _x = NULL;						\
	       xres = NULL;						\
	  } while (0);							\
	  break;
#include "cspmessages.def"
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef UELEM
#undef NONE


     default:
	  return -1;
	  break;
     }

     return 0;
}

WV_CSP_Message_t parse_json_packet(Octstr *in)
{
     void *msg = NULL;
     JValue_t jval = parse_json_value(in);
     
     if (jval) {
	  int x = csp_msg_from_jvalue(jval, Imps_WV_CSP_Message, &msg);

	  if (x != 0) {
	       csp_msg_free(msg);
	       msg = NULL;
	  }
	  free_json_value(jval);
     }
     return msg;
}
