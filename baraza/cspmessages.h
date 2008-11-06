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
#ifndef __CSP_MESSAGES__INCLUDED__
#define __CSP_MESSAGES__INCLUDED__
#define _GNU_SOURCE /* so we get strcasestr */
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <gwlib/gwlib.h>

enum IMPsObjectType {
  Imps_None = -1,
  Imps_String,
  Imps_Date,
  Imps_Integer,
  Imps_EmptyTag,
  Imps_Boolean,
#define NONE
#define Basic(name,ver,a,type) Imps_##name,
#define Structure(name,hastag,v,a,p) Imps_##name,
#define List(name,type) 
#define Union(name,type) 
#include "cspmessages.def"

  Imps_LastOne // mark end of messages
};
#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item

#define EmptyTag_t EmptyTag /* because this is the real type name. */
typedef long Integer_t;
typedef struct String_t *String_t;
typedef int EmptyTag;
typedef int Boolean_t;
typedef time_t Date_t;

/* generate general protoypes. */
#define Basic(name,version,a,type) typedef  type##_t name##_t;
#define Structure(type,hastag,version,attr, parms) typedef struct type##_t *type##_t;

#include "cspmessages.def"

#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item

/* now generate structure definitions */
#define Item(name,type) type##_t name;
#define List(name,type) List *name;
#define Union(name,types) struct {enum IMPsObjectType typ; void *val;} name;
#define ATTRIBUTES(attr) Dict *attributes;
#define Basic(name,version,a,type) 
#define Structure(type,hastag,version,attr, parms) struct type##_t {\
            enum IMPsObjectType typ; \
            Octstr *_content; \
            unsigned long _fieldset; /* bit field of fields that are set. */ \
            attr \
            parms \
            };

#include "cspmessages.def"

#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item
#undef ATTRIBUTES
#undef NONE

struct  String_t {
     enum IMPsObjectType typ;  /* must be first field. */
     Dict *attributes;
     unsigned long len;
     unsigned char str[1]; 
     /* hidden space here. Please beware! */
};



/* Function prototypes. */
#define Basic(nm,ver,attr,typ) \
int parse_##nm(void *node,  void **next, int binary, void **res);
#define Structure(xname,hastag,ver,attr, parms) \
int parse_##xname(void *node,  void **next, int binary, void **res);

#define NONE
#include "cspmessages.def"

#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item

#undef NONE

int csp_parse_msg_real(void *node, int type, int binary, void **res, const char *file, int line, const char *func);

#define csp_parse_msg(node,type,bin,res) csp_parse_msg_real(node,type,bin,res,__FILE__,__LINE__,__FUNCTION__)
/* more prototypes. */
#define Basic(nm,ver,attr,typ) \
Octstr *pack_##nm(nm##_t msg, int binary, void *state);
#define Structure(xname,hastag,ver,attr, parms) \
Octstr *pack_##xname(xname##_t msg,  int binary, void *state);
#define NONE
#include "cspmessages.def"

#undef Basic
#undef Structure
#undef List
#undef Union
#undef Item

#undef NONE

/* pack a message into a string, using type as your basis. */
Octstr *csp_pack_msg_real(void *msg, int type, int binary, void *state, 
			  const char *file, int line, const char *func);

#define csp_pack_msg(msg,typ,bin,state) csp_pack_msg_real(msg,typ,bin,state,__FILE__, __LINE__,__FUNCTION__)

/* for version numbers */
#define CSP_VERSION(major,minor) (((major&0x0F)<<4) | (minor&0x0F))
#define CSP_MAJOR_VERSION(ver) (((ver)>>4)&0x0F)
#define CSP_MINOR_VERSION(ver) ((ver)&0x0F)

/* for checking and setting bits. */
#define MSG_SET_BIT(m,bit_no) ((m)->_fieldset |= (1U<<(bit_no)))
#define MSG_UNSET_BIT(m,bit_no) ((m)->_fieldset &= ~(1U<<(bit_no)))
#define MSG_GET_BIT(m,bit_no) ((m)->_fieldset & (1U<<(bit_no)))
#define MSG_GET_BITS(m) ((unsigned long)(m)->_fieldset)
#define MSG_SET_BITS(m,val) ((m)->_fieldset = (val)) /* XXX a kludge, to be used with caution! */

#define BIT_MASK(bit_no) (1U<<(bit_no))

/* macros for setting vararg field values and union field values */
#define FV(fname,fvalue) (#fname),(fvalue)                       /* field, value pair. */
#define UFV(fname,ftype,fvalue) (#fname),(ftype),(fvalue) /* union field, value pair. */
/* #define FV_END NULL  end of field values. */

/* imps versions. */
enum {IMPS_1_1 = CSP_VERSION(1,1), IMPS_1_2 = CSP_VERSION(1,2), IMPS_1_3 = CSP_VERSION(1,3)};

String_t csp_String_from_data(char *s, int len, enum IMPsObjectType typ);
#define  csp_String_from_bstr(s,typ) csp_String_from_data((void *)octstr_get_cstr(s), octstr_len(s), typ)
#define  csp_String_from_cstr(s,typ) csp_String_from_data((void *)(s), strlen((void *)(s)), typ)
#define  csp_String_from_cstr_ex(s,typ) csp_String_from_data((void *)(s), strlen((void *)(s)), Imps_##typ)

#define csp_String_to_bstr(xstr) ((xstr) ? octstr_create_from_data((void *)(xstr)->str, (xstr)->len) : NULL)
#define csp_String_to_cstr(xstr) ((xstr) ? (void *)(xstr)->str : NULL)
#define csp_String_len(xstr) ((xstr) ? (xstr)->len : 0)

/* set the fieldset parameter from the passed string list (null terminated) */
void csp_msg_set_fieldset_real(const char *func, const char *file, int line, void *msg, ...);

#define csp_msg_set_fieldset(msg,...) csp_msg_set_fieldset_real(__FUNCTION__, __FILE__, __LINE__, msg,__VA_ARGS__,NULL)
/* unset the fieldset parameter from the passed string list (null terminated) */
void csp_msg_unset_fieldset_real(const char *func, const char *file, int line, void *msg, ...);

#define csp_msg_unset_fieldset(msg,...) csp_msg_unset_fieldset_real(__FUNCTION__, __FILE__, __LINE__, msg,__VA_ARGS__,NULL)


/* create a new object, passing any field values (using FV/UFV and finally FV_END macros). */
void *csp_msg_new_real(int type, Octstr *xmlns, ...);

#define csp_msg_new(typ, xmlns,...) (typ##_t)csp_msg_new_real(Imps_##typ, xmlns, __VA_ARGS__, NULL)
/* Copy a (structure-format) msg and return it. */
void *csp_msg_copy_real(void *msg, const char *file, const char *func, int line); 
#define csp_msg_copy(msg) csp_msg_copy_real(msg, __FILE__, __FUNCTION__, __LINE__)

/* free a (structure-format) msg. */
void csp_msg_free_real(void *msg, const char *file, const char *func, int line); 
#define csp_msg_free(msg) csp_msg_free_real(msg, __FILE__, __FUNCTION__, __LINE__)
int csp_version(char *xmlns);
/* return a string, given a type code. */
const char *csp_obj_name(int typ);

/* give the type from the name */
int csp_name_to_type(char *name);

/* tell us if the type is a string or a struct (which includes strings) */
int csp_type_format(int typ, int *is_string, int *is_struct);

/* return true if all fields of this object are not set. */
int csp_empty_struct(void *obj);

/* Count number of fields in type. */
#define csp_type_field_count(typ) csp_type_field_count_real(typ, __FILE__, __FUNCTION__, __LINE__)
unsigned csp_type_field_count_real(int type, const char *file, const char *func, int line);

#define csp_struct_count_fields(msg, fcount, setcount) csp_struct_count_fields_real(msg, fcount, setcount, __FILE__, __FUNCTION__, __LINE__)
#define csp_struct_clear_fields(msg,mask) csp_struct_clear_fields_real(msg,mask, __FILE__, __FUNCTION__, __LINE__)									       
/* return number of fields and how many are set in the structure object. Crashes for non-structs*/
int csp_struct_count_fields_real(void *msg, unsigned long *fcount, unsigned long *setcount,
				  const char *file, const char *func, int line);

/* Clear (and free) all children/fields of the struct whose bit is set in 'mask'  */
int csp_struct_clear_fields_real(void *msg, unsigned long mask, const char *file, const char *func, int line);



#define CSP_MSG_SET_FIELD(_msg,_fld, _val) do {(_msg)->_fld = _val; csp_msg_set_fieldset((_msg), #_fld); } while (0)

#define CSP_MSG_SET_UFIELD(_msg,_fld,_typ, _val) do {(_msg)->_fld.typ = (_typ); (_msg)->_fld.val = _val; csp_msg_set_fieldset((_msg), #_fld); } while (0)

#define CSP_MSG_CLEAR_FIELD(_obj, _fld) do {(_obj)->_fld = 0; csp_msg_unset_fieldset(_obj, #_fld); } while (0)
#define CSP_MSG_CLEAR_SFIELD(_obj, _fld) do {csp_msg_free((_obj)->_fld); (_obj)->_fld = NULL; csp_msg_unset_fieldset(_obj, #_fld); } while (0)

#define CSP_MSG_TYPE(_obj) (((EmptyObject_t)(_obj))->typ)
int csp_msg_field_isset_real(const char *func, const char *file, int line, 
			     void *msg, const char *field);
unsigned long csp_msg_get_field_bitmask_real(const char *func, const char *file, int line, 
					     void *msg, const char *field);

unsigned long csp_msgtype_get_field_bitmask_real(const char *func, const char *file, int line, 
						 int msgtype, const char *field);

int csp_get_nth_field_isset_real(void *msg, unsigned fnum, const char *func, const char *file, int line);

#define csp_get_nth_field_isset(msg,fnum) csp_get_nth_field_isset_real((msg), (fnum), __FUNCTION__, __FILE__, __LINE__)

#define csp_msg_field_isset(_msg,_fld) csp_msg_field_isset_real(__FUNCTION__, __FILE__,__LINE__,_msg,#_fld)
#define csp_msg_get_field_bitmask(_msg,_fld) csp_msg_get_field_bitmask_real(__FUNCTION__, __FILE__,__LINE__,_msg,#_fld)

#define csp_msgtype_get_field_bitmask(_msg,_fld) csp_msgtype_get_field_bitmask_real(__FUNCTION__, __FILE__,__LINE__,_msg,#_fld)
void csp_msg_init_fields_real(const char *func, const char *file, int line, 
			      void *msg, unsigned long mask);

#define csp_msg_init_fields(_msg,_mask) csp_msg_init_fields_real(__FUNCTION__, __FILE__,__LINE__,_msg,_mask)


/* Return the value for a particular field. */
void *csp_msg_get_field_value_real(const char *func, const char *file, int line, void *msg, int field_num);
#define csp_msg_get_field_value(msg,field_num) csp_msg_get_field_value_real(__FUNCTION__, __FILE__,__LINE__,msg,field_num)

									    
void *csp_msg_get_union_field_value_real(const char *func, const char *file, int line, void *msg, int field_num, int *type);
#define csp_msg_get_union_field_value(msg,field_num,_type)  csp_msg_get_union_field_value_real(__FUNCTION__, __FILE__,__LINE__,msg,field_num,_type)


void *csp_msg_copy_field_value_real(void *msg, int field_num, const char *func, const char *file, int line);
void *csp_msg_copy_union_field_value_real(void *msg, int field_num, int *utype, const char *func, const char *file, int line);

int csp_msg_set_field_value_real(void *msg, int field_num, void *value, const char *func, const char *file, int line);
int csp_msg_set_union_field_value_real(void *msg, int field_num, int utype, void *value, const char *func, const char *file, int line);

int csp_get_field_num_real(void *msg, const char *field_name, const char *func, const char *file, int line);


#define csp_msg_copy_field_value(msg,field_num) csp_msg_copy_field_value_real(msg,field_num,__FUNCTION__, __FILE__,__LINE__)
#define csp_msg_copy_union_field_value(msg,field_num,utype) csp_msg_copy_union_field_value_real(msg,field_num,utype,__FUNCTION__, __FILE__,__LINE__)

#define csp_msg_set_field_value(msg,field_num,value) csp_msg_set_field_value_real(msg,field_num,value,__FUNCTION__, __FILE__,__LINE__)
#define csp_msg_set_union_field_value(msg,field_num,utype,value) csp_msg_set_union_field_value_real(msg,field_num,utype,value,__FUNCTION__, __FILE__,__LINE__)

#define csp_get_field_num(msg,field_name) csp_get_field_num_from_type_real(((EmptyObject_t)(msg))->typ,field_name,__FUNCTION__, __FILE__,__LINE__)

int csp_get_field_num_from_type_real(int type, const char *field_name, const char *func, const char *file, int line);

#define csp_get_field_num_from_type(type, fname) \
  csp_get_field_num_from_type_real((type), #fname,			\
				   __FUNCTION__, __FILE__, __LINE__)

/* array, indexed by type name, gives each field, its type and so on. 
 * not to be changed. 
 */

void csp_update_xmlns(void *obj, char *xmlns);
 
extern const struct imps_struct_fields_t {
     char *field_name;
     int type;
     enum {INone, ISingleton, IList, IUnion} nature;
} *struct_types[];

#define CSP_COPY_FIELD(msg_from,msg_to,_nature, fld_num) do { \
			 void *_val; \
			 if (_nature == IUnion) { \
			      int utype; \
			      _val = csp_msg_copy_union_field_value(msg_from,fld_num, &utype); \
			      csp_msg_set_union_field_value(msg_to, fld_num, utype, _val); \
			 }  else { \
			      _val = csp_msg_copy_field_value(msg_from, fld_num); \
			      csp_msg_set_field_value(msg_to,fld_num,_val); \
			 }  \
                      } while (0)

#endif
