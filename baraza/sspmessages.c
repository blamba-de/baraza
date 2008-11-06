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
/* SSP message convertors */
#include "sspmessages.h"

#include "utils.h"

static Octstr *pack_user_type(void *obj)
{
     int typ;
     Octstr *out = NULL;
     
     if (obj == NULL)
	  return octstr_imm("");
     
     typ  = CSP_MSG_TYPE(obj); /* can be one of User, UserID, Group, ScreenName */
     if (typ == Imps_User  || typ == Imps_UserID) {
	  User_t u = (typ == Imps_User) ? obj : NULL;
	  UserID_t ux = (typ == Imps_UserID) ? obj : (u ? u->user : NULL);
	  ClientID_t cl = (u && u->u.typ == Imps_ClientID) ? u->u.val : NULL; 
	  ApplicationID_t ap = (u && u->u.typ == Imps_ApplicationID) ? u->u.val : NULL;  
	  
	  out = octstr_create("");
	  if (ux) {
	       octstr_format_append(out, "<User userID=\"%s\"", csp_String_to_cstr(ux));
	       if (cl) {
		    URL_t url = cl->url;
		    char *p = url ? csp_String_to_cstr(url) : "";
		    if (cl->_content == NULL)
			 octstr_format_append(out, ">\n<ClientID url=\"%s\"/>\n</User>\n", p);
		    else 
			 octstr_format_append(out, ">\n<ClientID url=\"%s\">%S</ClientID>\n</User>\n",
					      p, cl->_content);
	       } else if (ap) 
		    octstr_format_append(out, ">\n<ClientID url=\"\"><ApplicationID applicationID=\"%s\"/>"
					 "</ClientID>\n</User>\n",
					 csp_String_to_cstr(ap));
	       else 
		    octstr_append_cstr(out, "/>\n");
	  }
     } else if (typ == Imps_Group)
	  return pack_user_type(((Group_t)obj)->u.val);
     else if (typ == Imps_GroupID) 
	  out = octstr_format("<GroupID groupID=\"%s\"/>", csp_String_to_cstr((GroupID_t)obj));
     else if (typ == Imps_ScreenName) {
	  ScreenName_t sn = obj;
	  if (sn)
	       out = octstr_format("<ScreenName groupID=\"%s\">%s</ScreenName>", 
			     csp_String_to_cstr(sn->gid), 
			     csp_String_to_cstr(sn->sname));
     }
     
     return out;
}

void *parse_user_type(xmlNodePtr node)
{
     void *msg;
     char *s;
     if (node == NULL) 
	  return NULL;     
     else if (NMATCH(node, "User")) {
	  char *x = NATTR(node, "userID");

	  if (x != NULL) {
	       char *fname = NATTR(node, "friendlyName");
	       xmlNodePtr cnode = find_node(node->xmlChildrenNode, "ClientID",  3);
	       xmlNodePtr anode = find_node(node->xmlChildrenNode, "ApplicationID",  3);
	       int typ;
	       void *val;
	       
	       if (cnode) {
		    char *u = NATTR(cnode, "url");
		    URL_t url = u ? csp_String_from_cstr(u, Imps_URL) : NULL;
		    Octstr *contents = _xmlNodeContent(cnode);
		    
		    typ = Imps_ClientID;
		    val = csp_msg_new(ClientID, NULL, 
				      FV(url, url));
		  
		    if (octstr_len(contents) > 0)
			 ((ClientID_t)val)->_content = contents;
		    else 
			 octstr_destroy(contents);
		    if (u) xmlFree(u);
	       } else if (anode) {
		    char *a = NATTR(cnode, "applicationID");
		    
		    typ = Imps_ApplicationID;
		    val = a ? csp_String_from_cstr(a, Imps_ApplicationID) : NULL;
		    if (a) xmlFree(a);
	       } else {
		    typ = 0;
		    val = NULL;
	       }

	       s = (strstr(x, "wv:") == x) ? x + 3 : x;
	       msg = csp_msg_new(User, NULL, 
				  FV(user, csp_String_from_cstr(s, Imps_UserID)),
				  FV(fname, 
				     fname ? csp_String_from_cstr(fname, Imps_FriendlyName) : NULL),
				  UFV(u, typ, val));
	       xmlFree(x);
	       if (fname) xmlFree(fname);
	  } else 
	       msg = NULL;	  
     } else  if (NMATCH(node, "GroupID")) {
	  char *gid = NATTR(node, "groupID");

	  if (gid) {
	       s = (strstr(gid, "wv:") == gid) ? gid + 3 : gid;
	       msg = csp_String_from_cstr(s, Imps_GroupID);
	       xmlFree(gid);
	  } else 
	       msg = NULL;	       
     } else  if (NMATCH(node, "ScreenName")) {
	  Octstr *sn = _xmlNodeContent(node);
	  char *gid = NATTR(node, "groupID");

	  if (sn && gid)  {
	       s = (strstr(gid, "wv:") == gid) ? gid + 3 : gid;
	       msg = csp_msg_new(ScreenName, NULL,
				 FV(sname, csp_String_from_bstr(sn, Imps_SName)),
				 FV(gid, csp_String_from_cstr(s, Imps_GroupID)));
	  } else 
	       msg = NULL;
	  if (sn)  octstr_destroy(sn);
	  if (gid) xmlFree(gid);
     } else {
	  error(0, "parse_user_type: Unexpected node type [%s] for user type!", node->name);
	  msg = NULL;
     }
     return msg;
}


Sender_t make_ssp_sender(void *msg)
{
     int typ;
     if (msg == NULL)
	  return NULL;
     typ =  CSP_MSG_TYPE(msg);

     if (typ == Imps_GroupID ||
	 typ == Imps_ScreenName)
	  msg = csp_msg_new(Group, NULL, UFV(u, typ, msg));
     else if (typ != Imps_User) 
	  error(0, "make_ssp_sender called with unexpected message type %d [%s]!", typ, csp_obj_name(typ));
     
     return csp_msg_new(Sender, NULL, UFV(u,  CSP_MSG_TYPE(msg), msg));
}

static void append_user_types(Octstr *out, List *l)
{
     int i, n;
     void *u;
     
     for (i = 0, n = gwlist_len(l); i<n; i++) 
	  if ((u = gwlist_get(l, i)) != NULL) {
	       Octstr *x = pack_user_type(u);
	       octstr_append(out, x);
	       octstr_destroy(x);
	  }     
}

static Octstr *pack_metainfo(Sender_t sender)
{
     Octstr *domain = get_sender_domain(sender);
     int is_user = (sender->u.typ == Imps_User);
     Octstr *x = octstr_format("<MetaInfo clientOriginated=\"%s\">\n"
			       "<Requestor serviceID=\"wv:@%S\"",is_user ? "Yes" : "No",  domain);

     if (is_user) {
	  Octstr *y = pack_user_type(sender->u.val);
	  octstr_format_append(x, ">\n%S", y);
	  
	  octstr_append_cstr(x, "</Requestor>");	  
	  octstr_destroy(y);
     } else 
	  octstr_append(x, octstr_imm("/>\n"));
     
     octstr_append(x, octstr_imm("</MetaInfo>\n"));

     octstr_destroy(domain);
     return x;
}

static User_t parse_metainfo(xmlNodePtr node)
{
     User_t user;     
     char *orig;
     xmlNodePtr unode;

     
     if ((orig = NATTR(node, "clientOriginated")) != NULL
	 && strcasecmp(orig, "yes") != 0)
	  user = NULL;
     else if ((unode = find_node(node->xmlChildrenNode, "User",  3)) != NULL)
	  user = parse_user_type(unode);
     else 
	  user = NULL;
     
     if (orig) xmlFree(orig);
     return user;
}

static void append_message_info_struct(Octstr *out, MessageInfo_t minfo, Sender_t sender)
{
     time_t tdate;
     void *u;
     int i, n;
     Recipient_t r = minfo ? minfo->rcpt : NULL;
     Octstr *x;
     /* build messageInfo struct */
     octstr_append_cstr(out, "<MessageInfo");
     if (minfo->msgid)
	  octstr_format_append(out, " messageID=\"%s\"", csp_String_to_cstr(minfo->msgid));
     if (minfo->uri)
	  octstr_format_append(out, " messageURI=\"%s\"", csp_String_to_cstr(minfo->uri));
     if (minfo->ctype)
	  octstr_format_append(out, " contentType=\"%s\"", csp_String_to_cstr(minfo->ctype));
     
     if (minfo->cname)
	  octstr_format_append(out, " contentName=\"%s\"", csp_String_to_cstr(minfo->cname));
     if (csp_msg_field_isset(minfo, size)) 	     
	  octstr_format_append(out, " contentSize=\"%ld\"", minfo->size);
     if (csp_msg_field_isset(minfo, valid)) 	     
	  octstr_format_append(out, " validity=\"%ld\"", minfo->valid);
     
     octstr_append_cstr(out, ">\n");
     
     for (i = 0, n = r ? gwlist_len(r->ulist) : 0; i<n; i++)
	  if ((u = gwlist_get(r->ulist, i)) != NULL) {
	       Octstr *x = pack_user_type(u);
	       
	       octstr_format_append(out, "<Recipient>\n%S\n</Recipient>\n", x);
	       octstr_destroy(x);
	  }
     for (i = 0, n = r ? gwlist_len(r->glist) : 0; i<n; i++)
	  if ((u = gwlist_get(r->glist, i)) != NULL) {
	       Octstr *x = pack_user_type(u);
	       
	       octstr_format_append(out, "<Recipient>\n%S\n</Recipient>\n", x);
	       octstr_destroy(x);
	  }
     /* Make the sender element. */
     octstr_append_cstr(out, "<Sender>\n");
     if (sender->u.typ == Imps_User) {
	  Octstr *x = pack_user_type(sender->u.val);
	  octstr_append(out, x);
	  octstr_destroy(x);
     } else { /* screen name/group! */
	  Group_t g = sender->u.val;
	  ScreenName_t s = (g && g->u.typ == Imps_ScreenName) ? g->u.val : NULL;
	  GroupID_t gid = (g && g->u.typ == Imps_GroupID) ? g->u.val :
	       (s ? s->gid : NULL);
	  Octstr *y = pack_user_type(gid);
	  Octstr *x = pack_user_type(g);
	  if (y)
	       octstr_append(out, y);
	  octstr_format_append(out, "\n<SenderDisplay>%S</SenderDisplay>\n", x);
	  octstr_destroy(y);
	  octstr_destroy(x);
     }
     octstr_append_cstr(out, "\n</Sender>\n");
     
     /* Add datetime */
     if (csp_msg_field_isset(minfo, tdate))
	  tdate = minfo->tdate;
     else 
	  tdate = time(NULL);
     x = date_create_iso(minfo->tdate);

     octstr_format_append(out, "\n<DateTime format=\"iso8601\">%S</DateTime>\n", x);
     octstr_destroy(x);
     
     /* end message info */
     octstr_append_cstr(out, "\n</MessageInfo>\n");
     
}

static Octstr *make_result_xml(Result_t res)
{
     Octstr *x = octstr_format("<Status code=\"%ld\">\n", res->code);
     char *y = res->descr ? csp_String_to_cstr(res->descr) : NULL;
     DetailedResult_t d;

     int i, n;
     
     /* XXX we need to HTML encode. */
     if (y) 
	  octstr_format_append(x, "<StatusDescription>%s</StatusDescription>\n", y);
     
     for (i = 0, n = gwlist_len(res->drlist); i<n; i++) 
	  if ((d = gwlist_get(res->drlist, i)) != NULL) {
	       char *y = d->descr ? csp_String_to_cstr(d->descr) : NULL;
	       octstr_format_append(x, "<DetailedResult code=\"%ld\">\n", d->code);
	       
	       if (y) 
		    octstr_format_append(x, "<StatusDescription>%s</StatusDescription>\n", y);
	       if (d->details.typ == Imps__UserResult && d->details.val) {
		    _UserResult_t ur = d->details.val;
		    UserID_t ux;
		    GroupID_t gid;
		    ScreenName_t sn;

		    Domain_t dm;
		    int j, m;

		    /* Ignore MessageID, ContactList -- they can't happen here. */
		    for (j = 0, m = gwlist_len(ur->users); j<m; j++) 
			 if ((ux = gwlist_get(ur->users, j)) != NULL) 
			      octstr_format_append(x, "<UserID userID=\"%s\"/>\n", csp_String_to_cstr(ux));	       	       

		    for (j = 0, m = gwlist_len(ur->grps); j<m; j++) 
			 if ((gid = gwlist_get(ur->grps, j)) != NULL) 
			      octstr_format_append(x, "<GroupID groupID=\"%s\"/>\n", csp_String_to_cstr(gid));	       	       
		    
		    /* add screen names. */
		    for (j = 0, m = gwlist_len(ur->snames); j<m; j++) 
			 if ((sn = gwlist_get(ur->snames, j)) != NULL) {
			      Octstr *y = pack_user_type(sn);
			      octstr_append(x, y);
			      octstr_destroy(y);
			 }
		    
		    for (j = 0, m = gwlist_len(ur->domains); j<m; j++) 
			 if ((dm = gwlist_get(ur->domains, j)) != NULL) 
			      octstr_format_append(x, "<Domain>%s</Domain>\n", csp_String_to_cstr(dm));	       	       
		    
		    
	       }
	       octstr_append_cstr(x, "</DetailedResult>\n");
	  }
     if (csp_msg_field_isset(res, tatimeout)) 
	  octstr_format_append(x, "<TryAgainTimeout>%ld</TryAgainTimeout>\n", res->tatimeout);
     octstr_append_cstr(x, "</Status>\n");
     return x;
}

static void append_userid_list(Octstr *out, List *ul, char *pre)
{
     int i, n;
     void *u;
     for (i = 0, n = gwlist_len(ul); i<n; i++)
	  if ((u = gwlist_get(ul, i)) != NULL) {
	       UserID_t ux;
	       
	       if (CSP_MSG_TYPE(u) == Imps_UserID)
		    ux =  u;
	       else if (CSP_MSG_TYPE(u) == Imps_User)
		    ux = ((User_t)u)->user;
	       else 
		    continue;
	       octstr_format_append(out, "<%sUserID userID=\"%s\"/>\n", 
				    pre,
				    csp_String_to_cstr(ux));
	  }		         
}
static List *parse_userid_list(xmlNodePtr xnode, char *xmltag, int ret_type)
{
     List *ul = gwlist_create();
     char *x;
     
     for (; xnode; xnode = xnode->next)
	  if (NMATCH(xnode, xmltag) && 
	      (x = NATTR(xnode, "userID")) != NULL) {
	       UserID_t u = csp_String_from_cstr(x, Imps_UserID);
	       void *val;
	       if (ret_type == Imps_User)
		    val = csp_msg_new(User, NULL, FV(user, u));
	       else 
		    val = u;
	       gwlist_append(ul, val);
	       xmlFree(x);
	  }
     return ul;
}

static void append_welcome_note(Octstr *out, WelcomeNote_t w)
{

     Octstr *cdata = csp_String_to_bstr(w->data);
     
     if (w->enc == NULL || strcasecmp(csp_String_to_cstr(w->enc), "base64") != 0)
	  octstr_binary_to_base64(cdata);
     
     octstr_append_cstr(out, "<WelcomeNote>\n");
     octstr_format_append(out, "<ContentData contentType=\"%s\" encoding=\"base64\">\n"
			  "%S\n</ContentData>\n", 
			  csp_String_to_cstr(w->ctype), cdata);
     octstr_append_cstr(out, "\n</WelcomeNote>\n");
     octstr_destroy(cdata);
}

static WelcomeNote_t parse_welcome_note(xmlNodePtr node)
{
     WelcomeNote_t wnote = csp_msg_new(WelcomeNote, NULL, NULL);
     xmlNodePtr xnode;

     if  ((xnode = find_node(node->children, "ContentData", 1)) != NULL) {
	  Octstr *x = _xmlNodeContent(xnode);
	  char *enc = NATTR(xnode, "encoding");
	  char *ctype = NATTR(xnode, "contentType");

	  if (enc) { /* base64 only. */
	       if (x) octstr_base64_to_binary(x);	  
	       xmlFree(enc);
	  }
	  if (ctype) {
	       CSP_MSG_SET_FIELD(wnote, ctype, csp_String_from_cstr(ctype, Imps_ContentType));
	       xmlFree(ctype);
	  }
	  if (x) {
	       CSP_MSG_SET_FIELD(wnote, data, csp_String_from_bstr(x, Imps_ContentData));
	       octstr_destroy(x);
	  }
     }
     return wnote;
}

static void append_gprop(Octstr *out, GroupProperties_t gp)
{
     int i, n;
     
     Property_t p;
     octstr_append_cstr(out, "<GroupProperties>\n");
     for (i = 0, n = gwlist_len(gp->plist); i<n; i++)
	  if ((p = gwlist_get(gp->plist, i)) != NULL) {
	       Octstr *x = pack_Property(p, 0, NULL);
	       octstr_append(out, x);
	       octstr_destroy(x);
	  }
     if (gp->wnote)
	  append_welcome_note(out, gp->wnote);
     octstr_append_cstr(out, "\n</GroupProperties>\n");
}

static GroupProperties_t parse_gprop(xmlNodePtr node)
{
     xmlNodePtr wnode = find_node(node->children, "WelcomeNote", 1), xnode;
     GroupProperties_t gp = csp_msg_new(GroupProperties, NULL,
					FV(plist, gwlist_create()));
     
     for (xnode = node->children; xnode; xnode = xnode->next)
	  if (NMATCH(xnode, "Property")) {
	       Property_t p = NULL;
	       void *x1;
	       parse_Property(xnode, (void *)&x1, 0, (void *)&p); 
	       if (p)
		    gwlist_append(gp->plist, p);
	  }
     if (wnode) 
	  CSP_MSG_SET_FIELD(gp, wnote, parse_welcome_note(wnode));
     return gp;
}

#define APPEND_GROUP_USER_LIST(str, ulist, xmltag) do { \
	  octstr_append_cstr((str), "<" xmltag ">\n");	\
	  append_userid_list((str), (ulist), "");	\
	  octstr_append_cstr((str), "</" xmltag ">\n");	\
     } while (0)

#define APPEND_MAPPING_LIST(str, mlist, xmltag) do {			\
	  int i, n;							\
	  void *x;							\
	  octstr_append_cstr((str), "<" xmltag ">\n<UserMapList><UserMapping>"); \
	  for (i = 0, n = gwlist_len(mlist); i<n; i++)			\
	       if ((x = gwlist_get((mlist), i)) != NULL) {		\
		    octstr_append_cstr((str), "<Mapping>");		\
		    if (CSP_MSG_TYPE(x) == Imps_ScreenName &&		\
			((ScreenName_t)x)->sname != NULL)			\
			 octstr_format_append((str),			\
					      "<SName>%s</SName>\n",	\
					      csp_String_to_cstr(((ScreenName_t)x)->sname)); \
		    else if (CSP_MSG_TYPE(x) == Imps_Mapping) {		\
			 Mapping_t m = x;				\
			 if (m->sname)					\
			      octstr_format_append((str), "<SName>%s</SName>\n", \
						   csp_String_to_cstr(m->sname)); \
			 if (m->userid)					\
			      octstr_format_append((str), "<UserID userid=\"%s\"/>\n", \
						   csp_String_to_cstr(m->userid)); \
		    }							\
		    octstr_append_cstr((str), "</Mapping>\n");		\
	       }							\
	  octstr_append_cstr((str), "</UserMapping></UserMapList></" xmltag ">\n"); \
     } while (0)

static List *parse_mapping_list(xmlNodePtr node, int target_type, GroupID_t gid)
{
     xmlNodePtr xnode = find_node(node->children, "Mapping", 3);
     List *l = gwlist_create();
     
     while (xnode) {
	  xmlNodePtr snode = find_node(xnode->children, "SName",1);
	  xmlNodePtr unode = find_node(xnode->children, "UserID",1);
	  Octstr *x;
	  SName_t s;
	  void *obj;
	  
	  if (snode == NULL) 
	       goto loop;
	  x = _xmlNodeContent(snode);
	  s = csp_String_from_bstr(x, Imps_SName);
	  if (target_type == Imps_ScreenName) 
	       obj = csp_msg_new(ScreenName, NULL, FV(sname, s), 
				 FV(gid, csp_msg_copy(gid)));
	  else if (target_type == Imps_Mapping) {
	       char *x = unode ? NATTR(unode, "userID") : NULL;
	       UserID_t userid = x ? csp_String_from_cstr(x, Imps_UserID) : NULL;
	       
	       obj = csp_msg_new(Mapping, NULL, 
				 FV(sname, s), 
				 FV(userid, userid));
	       if (x) xmlFree(x);
	  } else 
	       obj = NULL;
	  
	  if (obj)
	       gwlist_append(l, obj);	  
	  octstr_destroy(x);
     loop:
	  do
	       xnode = xnode->next;
	  while (xnode && NMATCH(xnode, "Mapping") != 0);
     }
     return l;
}

List *csp2ssp_msg(void *msg, void *orig_msg, Sender_t sender, List *rcptlist)
{
     List *l = NULL;
     Octstr *meta_info;
         
     gw_assert(msg);
     
     if (sender) 
	  meta_info = pack_metainfo(sender);
     else 
	  meta_info = octstr_imm("");

     switch (CSP_MSG_TYPE(msg)) {

     default:
     case Imps_GetPublicProfile_Request: /* we don't handle */
     case Imps_Search_Request:   /* we don't pass on searches, ditto stopsearch */
	  break;
	  

	  /* now the ones we support. */
     case Imps_Status:
	  msg = ((Status_t)msg)->res;
	  /* fall through. */
     case Imps_Result:

	  l = gwlist_create_ex(make_result_xml(msg));
     break;
     case Imps_Invite_Request:
	  if (((Invite_Request_t)msg)->rcpt != NULL) {
	       int i, n;
	       Invite_Request_t iv = msg;
	       Octstr *inviting = pack_user_type(sender->u.val);
	       Octstr *part1 = octstr_format("<InviteRequest inviteID=\"%s\" inviteType=\"%s\" validity=\"%ld\">\n"
					     "%S\n<Inviting>%S</Inviting>\n"
					     "<Invited>", 
					     csp_String_to_cstr(iv->invid),
					     csp_String_to_cstr(iv->invtype),
					     iv->valid,
					     meta_info, inviting);
	       Octstr *part2 = octstr_create("</Invited>\n");

	       if (iv->gid) {
		    Octstr *x = pack_user_type(iv->gid);
		    octstr_append(part2, x);
		    octstr_destroy(x);
	       }
	       if (iv->appid) 
		    octstr_format_append(part2, "<ApplicationID applicationID=\"%s\"/>\n", csp_String_to_cstr(iv->appid));
	       if (iv->pslist) {
		    Octstr *x = pack_PresenceSubList(iv->pslist, 0, NULL);
		    octstr_format_append(part2, "<AttributeList>%S</AttributeList>\n", x);
		    octstr_destroy(x);
	       }
	       
	       if (iv->url_list) {
		    List *l = iv->url_list->ulist;
		    octstr_append_cstr(part2, "<ContentIDList>\n");
		    
		    for (i = 0, n = gwlist_len(l); i<n; i++) {
			 URL_t url = gwlist_get(l, i);
			 octstr_format_append(part2, "<ContentID url=\"%s\"/>\n", 
					      csp_String_to_cstr(url));
		    }
		    octstr_append_cstr(part2, "</ContentIDList>\n");
	       }
	       if (iv->inote)
		    octstr_format_append(part2, "<InviteNote>%s</InviteNote>\n", 
					 csp_String_to_cstr(iv->inote));
	       if (iv->sname) {
		    Octstr *x = pack_user_type(iv->sname);
		    octstr_append(part2, x);
		    octstr_destroy(x);
	       }
	       
	       octstr_append_cstr(part2, "</InviteRequest>\n"); /* done. */
	       
	       /* Now build one for each recipient. */
	       l = gwlist_create();
	       for (i = 0, n = gwlist_len(iv->rcpt->ulist); i<n; i++) {
		    User_t u = gwlist_get(iv->rcpt->ulist, i);
		    Octstr *x = pack_user_type(u);
		    Octstr *y = octstr_format("%S%S%S", part1, x, part2);
		    
		    gwlist_append(l, y);
		    octstr_destroy(x);
	       }
	       for (i = 0, n = gwlist_len(iv->rcpt->glist); i<n; i++) {
		    Group_t g = gwlist_get(iv->rcpt->glist, i);
		    Octstr *x = pack_user_type(g);
		    Octstr *y = octstr_format("%S%S%S", part1, x, part2);
		    
		    gwlist_append(l, y);
		    octstr_destroy(x);
	       }	       
	       
	       octstr_destroy(inviting);
	  }
     break;
     case Imps_Invite_Response:
	  if (((Invite_Response_t)msg)->rcpt != NULL) {
	       int i, n;
	       Invite_Response_t ir = msg;
	       Octstr *inviting = pack_user_type(sender->u.val);
	       Octstr *part1 = octstr_format("<InviteResponse inviteID=\"%s\" "
					     " acceptance=\"%s\">\n"
					     "<Status code=\"%d\"/>\n"
					     "<Inviting>%S</Inviting>\n"					    
					     "<Responding>", 
					     csp_String_to_cstr(ir->invid),
					     ir->accept ? "Yes" : "No",
					     ir->accept ? 200 : 404,
					     inviting);
	       Octstr *part2 = octstr_create("</Responding>\n");
	       
	       if (ir->rnote) /* XXX watch out for v1.3 difference. */ 
		    octstr_format_append(part2, "<ResponseNote>%s</ResponseNote>", 
					 csp_String_to_cstr(ir->rnote));
	       if (ir->sname) {
		    Octstr *x = pack_user_type(ir->sname);
		    octstr_append(part2, x);
		    octstr_destroy(x);
	       }
	       
	       octstr_append_cstr(part2, "</InviteResponse>\n"); /* done. */
	       
	       /* Now build one for each recipient. */
	       l = gwlist_create();
	       for (i = 0, n = gwlist_len(ir->rcpt->ulist); i<n; i++) {
		    User_t u = gwlist_get(ir->rcpt->ulist, i);
		    Octstr *x = pack_user_type(u);
		    Octstr *y = octstr_format("%S%S%S", part1, x, part2);
		    
		    gwlist_append(l, y);
		    octstr_destroy(x);
	       }
	       for (i = 0, n = gwlist_len(ir->rcpt->glist); i<n; i++) {
		    Group_t g = gwlist_get(ir->rcpt->glist, i);
		    Octstr *x = pack_user_type(g);
		    Octstr *y = octstr_format("%S%S%S", part1, x, part2);
		    
		    gwlist_append(l, y);
		    octstr_destroy(x);
	       }	       
	       
	       octstr_destroy(inviting);
	  }
     break;
     case Imps_CancelInvite_Request:
	  if (((CancelInvite_Request_t)msg)->rcpt != NULL) {
	       int i, n;
	       CancelInvite_Request_t cr = msg;
	       Octstr *canceling = pack_user_type(sender->u.val);
	       Octstr *part1 = octstr_format("<CancelInviteRequest inviteID=\"%s\">\n"
					     "%S\n<Canceling>%S</Canceling>\n"
					     "<Canceled>", 
					     csp_String_to_cstr(cr->invid),
					     meta_info, canceling);
	       Octstr *part2 = octstr_create("<Canceled/>\n");

	       if (cr->gid) {
		    Octstr *x = pack_user_type(cr->gid);
		    octstr_append(part2, x);
		    octstr_destroy(x);
	       }
	       if (cr->appid) 
		    octstr_format_append(part2, "<ApplicationID applicationID=\"%s\"/>\n",
					 csp_String_to_cstr(cr->appid));
	       if (cr->pslist) {
		    Octstr *x = pack_PresenceSubList(cr->pslist, 0, NULL);
		    octstr_format_append(part2, "<AttributeList>%S</AttributeList>\n", x);
		    octstr_destroy(x);
	       }
	       
	       if (cr->ulist) {
		    List *l = cr->ulist->ulist;
		    octstr_append_cstr(part2, "<ContentIDList>\n");
		    
		    for (i = 0, n = gwlist_len(l); i<n; i++) {
			 URL_t url = gwlist_get(l, i);
			 octstr_format_append(part2, "<ContentID url=\"%s\"/>\n", 
					      csp_String_to_cstr(url));
		    }
		    octstr_append_cstr(part2, "</ContentIDList>\n");
	       }
	       if (cr->inote)
		    octstr_format_append(part2, "<CancelNote>%s</CancelNote>\n", 
					 csp_String_to_cstr(cr->inote));
	       if (cr->sname) {
		    Octstr *x = pack_user_type(cr->sname);
		    octstr_append(part2, x);
		    octstr_destroy(x);
	       }
	       
	       octstr_append_cstr(part2, "</CancelInviteRequest>\n"); /* done. */
	       
	       /* Now build one for each recipient. */
	       l = gwlist_create();
	       for (i = 0, n = gwlist_len(cr->rcpt->ulist); i<n; i++) {
		    User_t u = gwlist_get(cr->rcpt->ulist, i);
		    Octstr *x = pack_user_type(u);
		    Octstr *y = octstr_format("%S%S%S", part1, x, part2);
		    
		    gwlist_append(l, y);
		    octstr_destroy(x);
	       }
	       for (i = 0, n = gwlist_len(cr->rcpt->glist); i<n; i++) {
		    Group_t g = gwlist_get(cr->rcpt->glist, i);
		    Octstr *x = pack_user_type(g);
		    Octstr *y = octstr_format("%S%S%S", part1, x, part2);
		    
		    gwlist_append(l, y);
		    octstr_destroy(x);
	       }	       
	       
	       octstr_destroy(canceling);
	  }
     break;
     case Imps_SubscribePresence_Request:
     {
	  SubscribePresence_Request_t sp = msg;
	  List *ul = sp->uidlist ? sp->uidlist->ulist : sp->ulist;
	  Octstr *x = octstr_format("<SubscribeRequest>%S", meta_info);
	  int i, n;

	  for (i = 0, n = gwlist_len(ul); i<n; i++) {
	       void *u = gwlist_get(ul, i);
	       Octstr *y;
	       UserID_t userid;
	       
	       if (u == NULL) 
		    continue;

	       userid = CSP_MSG_TYPE(u) == Imps_UserID ? u : ((User_t)u)->user;	       
	       y = octstr_format("<UserID userID=\"%s\"/>", csp_String_to_cstr(userid));	       	       
	       octstr_append(x, y);	       	       
	       octstr_destroy(y);
	  }
	  
	  if (sp->plist) {
	       Octstr *y = pack_PresenceSubList(sp->plist, 0, NULL);
	       octstr_format_append(x, "<AttributeList>%S</AttributeList>\n", y);
	       octstr_destroy(y);
	  }
	  octstr_append_cstr(x, "</SubscribeRequest>\n");
	  l = gwlist_create_ex(x); /* single element list. */	  
     }     
     break;

     case Imps_UnsubscribePresence_Request:
     {
	  UnsubscribePresence_Request_t sp = msg;
	  List *ul = sp->uidlist ? sp->uidlist->ulist : sp->ulist;
	  Octstr *x = octstr_format("<UnsubscribeRequest>%S", meta_info);

	  append_userid_list(x, ul, "");
	  
	  octstr_append_cstr(x, "</UnsubscribeRequest>\n");
	  l = gwlist_create_ex(x); /* single element list. */	  
     }     
     break;
     case Imps_PresenceNotification_Request:
     {
	  Octstr *out = octstr_format("<PresenceNotification>\n%S\n", meta_info);
	  PresenceNotification_Request_t pr = msg;
	  PresenceSubList_t pslist;
	  SSPRecipient_t *r;
	  Presence_t p;
	  int i, n;

	  for (i = 0, n = gwlist_len(rcptlist); i<n; i++) 
	       if ((r = gwlist_get(rcptlist, i)) != NULL) {
		    Octstr *x = pack_user_type(r->to);
		    octstr_append(out, x);
		    octstr_destroy(x);
	       }
	  
	  for (i = 0, n = gwlist_len(pr->plist); i<n; i++) 
	       if ((p = gwlist_get(pr->plist, i)) != NULL && 
		   p->pres.typ == Imps__User_Presence  &&  /* only user presence supported.*/
		   p->pres.val && 
		   gwlist_len(p->pslist) > 0 && 
		   (pslist = gwlist_get(p->pslist, 0)) != NULL) { /* send only first one XXX */
		    Octstr *y =  pack_PresenceSubList(pslist, 0, NULL);
		    UserID_t ux = ((_User_Presence_t)p->pres.val)->user;
		    
		    octstr_format_append(out, "<PresenceValue userID=\"%s\">\n"
					 "%S</PresenceValue>\n", 
					 csp_String_to_cstr(ux), y);
		    octstr_destroy(y);
	       }
	  octstr_append_cstr(out, "</PresenceNotification>\n");
	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_GetPresence_Request:
     {
	  Octstr *out = octstr_format("<GetPresenceRequest>\n%S\n", meta_info);
	  GetPresence_Request_t gp = msg;
	  List *ul;

	  Octstr *y =  pack_PresenceSubList(gp->pslist, 0, NULL);

	  if (gp->u.typ == Imps_UserIDList)
	       ul = ((UserIDList_t)gp->u.val) ? ((UserIDList_t)gp->u.val)->ulist : NULL;
	  else if (gp->u.typ == Imps__User_List) 
	       ul = ((_User_List_t)gp->u.val) ? ((_User_List_t)gp->u.val)->ulist : NULL;
	  else 
	       ul = NULL;
	  
	  append_userid_list(out, ul, "Ver");

	  octstr_format_append(out, "<AttributeList>\n%S\n</AttributeList>\n", y);
	  octstr_destroy(y);
	  
	  octstr_append_cstr(out, "</GetPresenceRequest>\n");
	  l = gwlist_create_ex(out);	  
     }
     break;
     case Imps_GetPresence_Response:
     {
	  Octstr *out = octstr_create("<GetPresenceResponse>\n");
	  GetPresence_Response_t pr = msg;
	  PresenceSubList_t pslist;

	  Presence_t p;
	  int i, n;
	  
	  for (i = 0, n = gwlist_len(pr->plist); i<n; i++) 
	       if ((p = gwlist_get(pr->plist, i)) != NULL && 
		   p->pres.typ == Imps__User_Presence  &&  /* only user presence supported.*/
		   p->pres.val && 
		   (pslist = gwlist_get(p->pslist, 0)) != NULL) { /* send only first one XXX */
		    Octstr *y =  pack_PresenceSubList(pslist, 0, NULL);
		    UserID_t ux = ((_User_Presence_t)p->pres.val)->user;
		    
		    octstr_format_append(out, "<PresenceValue userID=\"%s\">\n"
					 "%S</PresenceValue>\n", 
					 csp_String_to_cstr(ux), y);
		    octstr_destroy(y);
	       }
	  octstr_append_cstr(out, "</GetPresenceResponse>\n");
	  l = gwlist_create_ex(out);
     }
     break;

     case Imps_SendMessage_Request:
	  if (msg && ((SendMessage_Request_t)msg)->msginfo) {
	       SendMessage_Request_t sm = msg;
	       MessageInfo_t minfo = sm->msginfo;

	       Octstr *x, *out = octstr_format("<SendMessageRequest deliveryReport=\"%s\">\n%S\n", 
					       sm->dreport ? "Yes" : "No", meta_info);	       

	       append_message_info_struct(out, sm->msginfo, sender);
	       
	       x = csp_String_to_bstr(sm->data);
	       if (minfo->enc == NULL || strcasecmp(csp_String_to_cstr(minfo->enc),"base64") != 0) /* not encoded, encode it. */
		    octstr_binary_to_base64(x);
	       octstr_format_append(out, "<ContentData contentType=\"%s\" encoding=\"base64\">\n"
				    "%S\n</ContentData>\n", 
				    minfo->ctype ? csp_String_to_cstr(minfo->ctype) : "text/plain", x);
	       octstr_destroy(x);
	       
	       octstr_append_cstr(out, "\n</SendMessageRequest>\n");
	       l = gwlist_create_ex(out);
	  }
	  break;
     case Imps_SendMessage_Response:
     {
	  SendMessage_Response_t sm = msg;
	  char *msgid = sm->msgid ? csp_String_to_cstr(sm->msgid) : "";
	  Octstr *out = octstr_format("<SendMessageResponse messageID=\"%s\">\n", msgid);
	  Octstr *y = make_result_xml(sm->res);
	  
	  octstr_append(out, y);
	  octstr_append_cstr(out, "\n</SendMessageResponse>\n");
	  octstr_destroy(y);
	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_DeliveryReport_Request:
	  if (msg && ((DeliveryReport_Request_t)msg)->minfo) {
	       DeliveryReport_Request_t dlr = msg;

	       Octstr *out = octstr_format("<DeliveryStatusReport>\n%S\n", 
					       meta_info);	       
	       Octstr *y = make_result_xml(dlr->res);
	       octstr_format_append(out, "<DeliveryResult>%S</DeliveryResult>\n", y);
	       
	       if (csp_msg_field_isset(dlr, dtime)) {
		    Octstr *x = date_create_iso(dlr->dtime);
		    octstr_format_append(out, "<DeliveryTime>%S</DeliveryTime>\n", x);
		    octstr_destroy(x);
	       }
	       
	       append_message_info_struct(out, dlr->minfo, sender);
	       
	       
	       octstr_destroy(y);
	       
	       octstr_append_cstr(out, "\n</DeliveryStatusReport>\n");
	       l = gwlist_create_ex(out);
	  }
	  break;
	  
	  /* The group management ones. */
     case Imps_CreateGroup_Request: break; /* Remote group creating unsupported. */

     case Imps_DeleteGroup_Request:
     {
	  DeleteGroup_Request_t dg = msg;
	  GroupID_t gid = dg->gid;
	  
	  Octstr *out = octstr_format("<DeleteGroupRequest groupID=\"%s\">\n%S\n"
				      "</DeleteGroupRequest>\n", 
				      csp_String_to_cstr(gid),
				      meta_info);	       
	  
	  l = gwlist_create_ex(out);
     }
     break;

     case Imps_JoinGroup_Request:
     {
	  JoinGroup_Request_t jg = msg;
	  GroupID_t gid = jg->gid;
	  Octstr *sn = pack_user_type(jg->sname);
	  Octstr *oprop = jg->oprop? pack_OwnProperties(jg->oprop, 0, NULL) : octstr_imm("");
	  Octstr *out = octstr_format("<JoinGroupRequest groupID=\"%s\" joinedListRequest=\"%s\" "
				      "subscribeNotif=\"%s\">\n%S\n",
				      csp_String_to_cstr(gid),
				      jg->jreq ? "Yes" : "No", 
				      jg->snotify ? "Yes" : "No",
				      meta_info);	       
	  if (sn)
	       octstr_append(out, sn);
	  if (oprop)
	       octstr_append(out, oprop);

	  octstr_append_cstr(out, "\n</JoinGroupRequest>\n");

	  octstr_destroy(oprop);
	  octstr_destroy(sn);

	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_JoinGroup_Response:
     {
	  JoinGroup_Response_t jg = msg;
	  Octstr *out = octstr_create("<JoinGroupResponse>\n<Status code=\"200\"/>\n");
	  
	  if (jg->joined || jg->ulist || jg->umlist) {
	       List *sl;
	       int i, n;
	       void *x;

	       if (jg->joined) {
		    if (jg->joined->umlist)
			 sl = jg->joined->umlist->umap ? jg->joined->umlist->umap->mlist :
			   NULL;
		    else if (jg->joined->ulist)
			 sl = jg->joined->ulist->slist;
		    else 
			 sl = NULL;
	       } else if (jg->ulist) 
		    sl = jg->ulist->slist;
	       else if (jg->umlist)
		    sl = jg->umlist->umap ? jg->umlist->umap->mlist : NULL;
	       else 
		    sl = NULL;
	       
	       octstr_append_cstr(out, "<JoinedList>");
	       for (i = 0, n = gwlist_len(sl); i<n; i++) 
		    if ((x = gwlist_get(sl, i)) != NULL) {
			 SName_t sn;
			 
			 if (CSP_MSG_TYPE(x) == Imps_Mapping)
			      sn = ((Mapping_t)x)->sname;
			 else if (CSP_MSG_TYPE(x) == Imps_ScreenName)
			      sn = ((ScreenName_t)x)->sname;
			 else 
			      sn = NULL;
			 if (sn)
			      octstr_format_append(out, "<Name>%s</Name>\n", 
						   csp_String_to_cstr(sn));
		    }
	       
	       octstr_append_cstr(out, "</JoinedList>");
	  }

	  if (jg->wnote) 	  /* welcome note. */
	       append_welcome_note(out, jg->wnote);
	  octstr_append_cstr(out, "\n</JoinGroupResponse>\n");
	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_LeaveGroup_Request:
     {
	  LeaveGroup_Request_t dg = msg;
	  GroupID_t gid = dg->gid;
	  
	  Octstr *out = octstr_format("<LeaveGroupRequest groupID=\"%s\">\n%S\n"
				      "</LeaveGroupRequest>\n", 
				      csp_String_to_cstr(gid),
				      meta_info);	       
	  
	  l = gwlist_create_ex(out);
     }
     break;
     
     case Imps_LeaveGroup_Response: /* This one can occur on this interface. */
     {
	  LeaveGroup_Response_t lg = msg;
	  GroupID_t gid = lg->gid;
	  Octstr *r = make_result_xml(lg->res);
	  Octstr *out = octstr_format("<LeaveGroupIndication groupID=\"%s\">\n%S\n<ReasonText/>"
				      "</LeaveGroupIndication>\n", 
				      csp_String_to_cstr(gid),r);	       	  
	  octstr_destroy(r);
	  l = gwlist_create_ex(out);	  
     }
     break;

     case Imps_GetGroupMembers_Request:
     {
	  GetGroupMembers_Request_t dg = msg;
	  GroupID_t gid = dg->gid;
	  
	  Octstr *out = octstr_format("<GetGroupMemberRequest groupID=\"%s\">\n%S\n"
				      "</GetGroupMemberRequest>\n", 
				      csp_String_to_cstr(gid),
				      meta_info);	       
	  
	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_GetGroupMembers_Response:
     {
	  GetGroupMembers_Response_t gm = msg;
	  Octstr *out = octstr_create("<GetGroupMemberResponse>\n<Status code=\"200\"/>\n");
	  
	  if (gm->admin && gm->admin->ulist)
	       APPEND_GROUP_USER_LIST(out, gm->admin->ulist->ulist, "Admins");
	  if (gm->mod && gm->mod->ulist)
	       APPEND_GROUP_USER_LIST(out, gm->mod->ulist->ulist, "Moderators");
	  if (gm->ulist)
	       APPEND_GROUP_USER_LIST(out, gm->ulist->ulist, "OrdinaryUsers");

	  octstr_append_cstr(out, "</GetGroupMemberResponse>\n");
	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_GetJoinedUsers_Request:
     {
	  GetJoinedUsers_Request_t dg = msg;
	  GroupID_t gid = dg->gid;
	  
	  Octstr *out = octstr_format("<GetJoinedUsersRequest groupID=\"%s\">\n%S\n"
				      "</GetJoinedUsersRequest>\n", 
				      csp_String_to_cstr(gid),
				      meta_info);	       
	  
	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_GetJoinedUsers_Response:
     {
	  GetJoinedUsers_Response_t gj = msg;
	  List *alist,  *ulist; /* of Mapping */
	  Octstr *out = octstr_create("<GetJoinedUsersResponse>\n<Status code=\"200\"/>\n");
	  
	  if (gj->u.typ == Imps_AdminMapList) {
	       AdminMapList_t am = gj->u.val;

	       alist = (am && am->amap) ? am->amap->mlist : NULL;
	       ulist = (am && am->umap) ? am->umap->mlist : NULL;
	  } else if (gj->u.typ == Imps_UserMapList) {
	       UserMapList_t um = gj->u.val;
	       ulist = (um && um->umap) ? um->umap->mlist : NULL;
	       alist = NULL;
	  } else 
	       alist = ulist = NULL;

	  if (alist)
	       APPEND_MAPPING_LIST(out, alist, "JoinedAdmin");
	  if (ulist)
	       APPEND_MAPPING_LIST(out, ulist, "JoinedUser");
	  
	  if (gj->jb && gj->jb->ulist && gj->jb->ulist)
	       APPEND_MAPPING_LIST(out, gj->jb->ulist->slist, "JoinedBlocked");
	  octstr_append_cstr(out, "</GetJoinedUsersResponse>\n");

	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_AddGroupMembers_Request:
	  if (((AddGroupMembers_Request_t)msg)->ulist.val) {
	       AddGroupMembers_Request_t dg = msg;
	       GroupID_t gid = dg->gid;
	       List *ul;
	       Octstr *out = octstr_format("<AddGroupMemberRequest groupID=\"%s\">\n%S\n",
					   
					   csp_String_to_cstr(gid),
					   meta_info);	       
	       
	       if (dg->ulist.typ == Imps_UserIDList)
		    ul = ((UserIDList_t)dg->ulist.val)->ulist;
	       else 
		    ul = ((UserList_t)dg->ulist.val)->ulist; 

	       append_userid_list(out, ul, "");
	       octstr_append_cstr(out, "\n</AddGroupMemberRequest>\n");
	       l = gwlist_create_ex(out);
	  }
     break;

     case Imps_RemoveGroupMembers_Request:
	  if (((RemoveGroupMembers_Request_t)msg)->ulist.val) {
	       RemoveGroupMembers_Request_t dg = msg;
	       GroupID_t gid = dg->gid;
	       List *ul;
	       Octstr *out = octstr_format("<RemoveGroupMemberRequest groupID=\"%s\">\n%S\n",					   
					   csp_String_to_cstr(gid),
					   meta_info);	       
	       
	       if (dg->ulist.typ == Imps_UserIDList)
		    ul = ((UserIDList_t)dg->ulist.val)->ulist;
	       else 
		    ul = ((UserList_t)dg->ulist.val)->ulist; 

	       append_userid_list(out, ul, "");

	       octstr_append_cstr(out, "\n</RemoveGroupMemberRequest>\n");
	       l = gwlist_create_ex(out);
	  }
     break;
     case Imps_MemberAccess_Request:
     {
	  MemberAccess_Request_t m = msg;
	  GroupID_t gid = m->gid;
	  Octstr *out = octstr_format("<MemberAccessRequest groupID=\"%s\">\n%S\n",
				      csp_String_to_cstr(gid),
				      meta_info);	       	  
 	  if (m->admin && m->admin->ulist)
	       APPEND_GROUP_USER_LIST(out, m->admin->ulist->ulist, "Admins");
	  if (m->mod && m->mod->ulist)
	       APPEND_GROUP_USER_LIST(out, m->mod->ulist->ulist, "Moderators");
	  if (m->ulist)
	       APPEND_GROUP_USER_LIST(out, m->ulist->ulist, "OrdinaryUsers");

	  octstr_append_cstr(out, "\n</MemberAccessRequest>\n");
	  l = gwlist_create_ex(out);	       
     }
     break;

     case Imps_GetGroupProps_Request:
     {
	  GetGroupProps_Request_t dg = msg;
	  GroupID_t gid = dg->gid;
	  
	  Octstr *out = octstr_format("<GetGroupPropsRequest groupID=\"%s\">\n%S\n"
				      "</GetGroupPropsRequest>\n", 
				      csp_String_to_cstr(gid),
				      meta_info);	       
	  
	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_GetGroupProps_Response:
     {
	  GetGroupProps_Response_t gp = msg;
	  Octstr *out = octstr_create("<GetGroupPropsResponse>\n<Status code=\"200\"/>\n");
	  Octstr *oprop = gp->oprop ? pack_OwnProperties(gp->oprop, 0, NULL) : octstr_imm("");
	  
	  if (gp->gprop)
	       append_gprop(out, gp->gprop);
	  octstr_append(out, oprop);
	  octstr_destroy(oprop);

	  octstr_append_cstr(out, "\n</GetGroupPropsResponse>\n");
	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_SetGroupProps_Request:
     {
	  SetGroupProps_Request_t sg = msg;
	  GroupID_t gid = sg->gid;
	  Octstr *oprop = pack_OwnProperties(sg->oprop, 0, NULL);
	  Octstr *out = octstr_format("<SetGroupPropsRequest groupID=\"%s\">\n%S\n",
				      csp_String_to_cstr(gid),
				      meta_info);	       
	  
	  if (sg->gprop) 
	       append_gprop(out, sg->gprop);
	  
	  if (oprop)
	       octstr_append(out, oprop);
	  octstr_append_cstr(out, 
			     "</SetGroupPropsRequest>\n");
	  octstr_destroy(oprop);
	  l = gwlist_create_ex(out);
     }
     break;

     case Imps_RejectList_Request:
     {
	  RejectList_Request_t m = msg;
	  GroupID_t gid = m->gid;
	  Octstr *out = octstr_format("<RejectListRequest groupID=\"%s\">\n%S\n",					   
					   csp_String_to_cstr(gid),
					   meta_info);	       
	  
	  if (m->alist && m->alist->users) {
	       octstr_append_cstr(out, "<AddUsers>\n");
	       append_userid_list(out, m->alist->users, "");
	       octstr_append_cstr(out, "</AddUsers>\n");
	  }

	  if (m->rlist && m->rlist->users) {
	       octstr_append_cstr(out, "<RemoveUsers>\n");
	       append_userid_list(out, m->rlist->users, "");
	       octstr_append_cstr(out, "</RemoveUsers>\n");
	  }

	  octstr_append_cstr(out, "\n</RejectListRequest>\n");
	  l = gwlist_create_ex(out);	       
     }
     break;
     case Imps_RejectList_Response:
     {
	  RejectList_Response_t m = msg;
	  Octstr *out = octstr_create("<RejectListResponse>\n<Status code=\"200\"/>\n");

	  
	  if (m->ulist && m->ulist->ulist) {
	       octstr_append_cstr(out, "<RejectList>\n");
	       append_userid_list(out, m->ulist->ulist, "");
	       octstr_append_cstr(out, "</RejectList>\n");	       
	  }
	  octstr_append_cstr(out, "</RejectListResponse>\n");
	  l = gwlist_create_ex(out);	       
     }
     break;
     case Imps_SubscribeGroupNotice_Request:
     {
	  SubscribeGroupNotice_Request_t dg = msg;
	  GroupID_t gid = dg->gid;
	  char stype  = dg->stype ? toupper(dg->stype->str[0]) : 'G';
	  char *xtag;
	  Octstr *out; 
	  
	  if (stype == 'S')
	       xtag = "SubscribeGroupChangeRequest";
	  else if (stype == 'U')
	       xtag = "UnsubscribeGroupChangeRequest";
	  else 
	       xtag = "GetGroupSubStatusRequest";
	  out = octstr_format("<%s groupID=\"%s\">\n%S\n"
			      "</%s>\n", 
			      xtag,
			      csp_String_to_cstr(gid),
			      meta_info, xtag);	       
	  
	  l = gwlist_create_ex(out);
     }
     break;
     case Imps_SubscribeGroupNotice_Response:  
     {
	  SubscribeGroupNotice_Response_t sr = msg;
	  SubscribeGroupNotice_Request_t dg = orig_msg;
	  GroupID_t gid = dg ? dg->gid : NULL;
	  char *status = (sr->value && tolower(sr->value->str[0]) == 't') ? "Yes" : "No";
	  Octstr *out = octstr_format("<GetGroupSubStatusResponse groupID=\"%s\" subscribed=\"%s\"> \n"
				      "<Status code=\"200\"/>\n"
				      "</GetGroupSubStatusResponse>\n",
				      gid ? csp_String_to_cstr(gid) : "",
				      status);
	  
	  
	  l = gwlist_create_ex(out);	  	  
     }
     break;
     case Imps_GroupChangeNotice:
     {
	  GroupChangeNotice_t gc = msg;
	  GroupID_t gid = gc->gid;
	  SSPRecipient_t *r;
	  int i, n;
	  ScreenName_t sn;	  
	  Octstr *oprop = pack_OwnProperties(gc->oprop, 0, NULL);
	  Octstr *out = octstr_format("<GroupChangeNotice groupID=\"%s\">\n%S\n",
				      csp_String_to_cstr(gid),
				      meta_info);	       

	  for (i = 0, n = gwlist_len(rcptlist); i<n; i++) 
	       if ((r = gwlist_get(rcptlist, i)) != NULL) {
		    Octstr *x = pack_user_type(r->to);
		    octstr_append(out, x);
		    octstr_destroy(x);
	       }
	  
	  if (gc->joined && gc->joined->umlist && 
	       gc->joined->umlist->umap) {
	       List *ml = gc->joined->umlist->umap->mlist;
	       int i, n;
	       Mapping_t m;
	       
	       octstr_append_cstr(out, "<Joined>\n");
	       for (i = 0, n = gwlist_len(ml); i<n; i++)
		    if ((m = gwlist_get(ml, i)) != NULL && m->sname) 
			 octstr_format_append(out, "<Name>%s</Name>\n", 
					      csp_String_to_cstr(m->sname));	       
	       octstr_append_cstr(out, "</Joined>\n");
	  }

	  if (gc->left && gc->left->ulist) {
	       List *sl = gc->left->ulist->slist;
	       
	       octstr_append_cstr(out, "<Left>\n");
	       for (i = 0, n = gwlist_len(sl); i<n; i++)
		    if ((sn = gwlist_get(sl, i)) != NULL && sn->sname)
			 octstr_format_append(out, "<Name>%s</Name>\n", 
					      csp_String_to_cstr(sn->sname));	       
	       
	       octstr_append_cstr(out, "</Left>\n");
	  }
	  
	  if (gc->jblock && gc->jblock && gc->jblock->ulist) { /* XXX this one looks odd. Semantics not quite right. */
	       List *sl = gc->jblock->ulist->slist;

	       APPEND_MAPPING_LIST(out, sl, "JoinedBlocked");
	  }
	  
	  if (gc->lblock && gc->lblock->ulist) {
	       List *ul = gc->lblock->ulist->ulist;
	       List *sl = gc->lblock->ulist->slist;
	       
	       octstr_append_cstr(out, "<LeftBlocked><UserList>\n");
	       
	       append_user_types(out, ul);
	       append_user_types(out, sl);

	       octstr_append_cstr(out, "</UserList></LeftBlocked>\n");
	  }

	  
	  if (gc->gprop)
	       append_gprop(out, gc->gprop);
	  if (oprop)
	       octstr_append(out, oprop);
	  octstr_append_cstr(out, "</GroupChangeNotice>\n");

	  octstr_destroy(oprop);

	  l = gwlist_create_ex(out);	  
     }
     break;
     }

     if (l == NULL)
	  warning(0, "csp2ssp: Unhandled message [%s]", msg ? csp_obj_name(CSP_MSG_TYPE(msg)) : "NULL");
     octstr_destroy(meta_info);
     return l;
}


#define CHECK_USERS(ul) do {						\
	  for (i = 0, n = gwlist_len(ul); i<n; i++)		\
	       if ((u = gwlist_get(ul, i)) != NULL &&		\
		   (ux = csp_String_to_cstr(u->user)) != NULL) {	\
		    int64_t uid;					\
		    int islocal;					\
		    							\
		    extract_id_and_domain(ux, xid, xdomain);		\
		    PQ_ESCAPE_STR(c, xid,tmp1);				\
		    PQ_ESCAPE_STR(c, xdomain,tmp2);			\
									\
		    if ((uid = get_userid(c, xid, xdomain, &islocal)) < 0 || \
			islocal == 0) {					\
			 Octstr *x = octstr_format("No such user: %s", ux); \
			 DetailedResult_t d;				\
			 d = csp_msg_new(DetailedResult, NULL,		\
					 FV(code, 427),			\
					 FV(descr,			\
					    csp_String_from_bstr(x,	\
								 Imps_Description))); \
			 gwlist_append(drlist, d);			\
			 octstr_destroy(x);				\
		    }							\
	       }							\
	  								\
     } while (0)

#if 0
static Result_t verify_ssp_recipients(PGconn *c, List *rcpt_users, Recipient_t r)
{
     int i, n, code;
     User_t u;
     List *drlist = gwlist_create();
     char xid[DEFAULT_BUF_LEN], xdomain[DEFAULT_BUF_LEN];
     char tmp1[DEFAULT_BUF_LEN*2], tmp2[DEFAULT_BUF_LEN*2], *ux;
     Group_t grp;
     
     CHECK_USERS(rcpt_users);
     
     if (r) {
	  CHECK_USERS(r->ulist);

	  /* Now check the groups. */

	  
	  for (i = 0, n = gwlist_len(r->glist); i<n; i++)		
	       if ((grp = gwlist_get(r->glist, i)) != NULL) {	
		    int64_t uid;					
		    int islocal;					
		    ScreenName_t sn = (grp->u.typ == Imps_ScreenName) ? grp->u.val : NULL;
		    GroupID_t gid = (sn) ? sn->gid : grp->u.val;
		    char *gx = csp_String_to_cstr(gid);
		    
		    if (gx == NULL)
			 continue;
		    
		    extract_id_and_domain(gx, xid, xdomain);		
		    PQ_ESCAPE_STR(c, xid,tmp1);				
		    PQ_ESCAPE_STR(c, xdomain,tmp2);			
		    
		    if ((uid = get_groupid(c, xid, xdomain, &islocal)) < 0 || 
			islocal == 0) {					
			 Octstr *x = octstr_format("No such group: %s", gx); 
			 DetailedResult_t d;				
			 d = csp_msg_new(DetailedResult, NULL,		
					 FV(code, 800),			
					 FV(descr,			
					    csp_String_from_bstr(x,	
								 Imps_Description))); 
			 gwlist_append(drlist, d);			
			 octstr_destroy(x);				
		    }							
	       }							
	  	 	  /* contacts can't appear on this interface, so no check. */
	  
     }

     code = gwlist_len(drlist) > 0 ? 201 : 200;
     return  csp_msg_new(Result, NULL,
			 FV(code, code),
			 FV(descr, csp_String_from_cstr("Complete", Imps_Description)),
			 FV(drlist, drlist));     
}
#endif

static DetailedResult_t parse_detailed_result(xmlNodePtr node)
{
     xmlNodePtr xnode;
     DetailedResult_t dr;
     char *x;
     List *ulist = gwlist_create();
     List *glist = gwlist_create();
     List *dlist = gwlist_create();
     List *slist = gwlist_create();     
     
     if ((x = NATTR(node, "code")) != NULL) {
	  dr = csp_msg_new(DetailedResult, NULL,
			   FV(code, atoi(x)));	  
	  xmlFree(x);
     } else 
	  return NULL;

     if ((xnode = find_node(node->children, "StatusDescription", 1)) != NULL) {
	  Octstr *x = _xmlNodeContent(xnode);
	  CSP_MSG_SET_FIELD(dr, descr, csp_String_from_bstr(x, Imps_Description));
	  octstr_destroy(x);
     }
     /* try for result body. */
     for (xnode = node->children; xnode; xnode = xnode->next) 
	  if (xnode->type == XML_ELEMENT_NODE) {
	       void *y;
	       if (NMATCH(xnode, "UserID") && 
		   (x = NATTR(xnode, "userID")) != NULL) { 
		    gwlist_append(ulist, csp_String_from_cstr(x, Imps_UserID));
		    xmlFree(x);
	       } else if (NMATCH(xnode, "GroupID")  && 
			  (x = NATTR(xnode, "groupID")) != NULL) { 
		    gwlist_append(glist, csp_String_from_cstr(x, Imps_GroupID));
		    xmlFree(x);		    
	       } else if (NMATCH(xnode, "Domain")  && 
			  (y = _xmlNodeContent(xnode)) != NULL) { 
		    gwlist_append(dlist, csp_String_from_bstr(y, Imps_Domain));
		    octstr_destroy(y);
	       } else if (NMATCH(xnode, "ScreenNames") && 
			  (y = parse_user_type(xnode)) != NULL) {
		    if (CSP_MSG_TYPE(y) == Imps_ScreenName)
			 gwlist_append(slist, y);
		    else 
			 csp_msg_free(y);
	       }
	  }
     
     if (gwlist_len(ulist) > 0 || gwlist_len(glist) > 0 || 
	 gwlist_len(dlist) > 0 || gwlist_len(slist) > 0) {
	  _UserResult_t ur = csp_msg_new(_UserResult, NULL,
					 FV(users, ulist),
					 FV(grps, glist),
					 FV(snames, slist),
					 FV(domains, dlist));
	  
	  CSP_MSG_SET_UFIELD(dr, details, Imps__UserResult, ur);
     } else {
	  gwlist_destroy(ulist, _csp_msg_free);
	  gwlist_destroy(glist, _csp_msg_free);
	  gwlist_destroy(dlist, _csp_msg_free);
	  gwlist_destroy(slist, _csp_msg_free);
     }
     return dr;
}

MessageInfo_t parse_message_info(xmlNodePtr node, int csize)
{
     Recipient_t r = csp_msg_new(Recipient, NULL, 
				 FV(ulist, gwlist_create()),
				 FV(glist, gwlist_create()));
     MessageInfo_t minfo = csp_msg_new(MessageInfo, NULL,
				       FV(rcpt, r));
     char *x; 
     xmlNodePtr xnode, xnode2;
     void *y;
     
     if ((x = NATTR(node, "messageID")) != NULL) {
	  CSP_MSG_SET_FIELD(minfo, msgid, csp_String_from_cstr(x, Imps_MessageID));
	  xmlFree(x);
     }

     if ((x = NATTR(node, "MessageURI")) != NULL) {
	  CSP_MSG_SET_FIELD(minfo, uri, csp_String_from_cstr(x, Imps_MessageURI));
	  xmlFree(x);
     }

     if ((x = NATTR(node, "contentType")) != NULL) {
	  CSP_MSG_SET_FIELD(minfo, ctype, csp_String_from_cstr(x, Imps_ContentType));
	  xmlFree(x);
     }

     if ((x = NATTR(node, "ContentName")) != NULL) {
	  CSP_MSG_SET_FIELD(minfo, cname, csp_String_from_cstr(x, Imps_ContentName));
	  xmlFree(x);
     }
     
     if (csize == 0 &&  /* i.e. no content data or size could not be determined by ourselves */
	 (x = NATTR(node, "contentSize")) != NULL) {
	  csize = atoi(x);
	  xmlFree(x);
     }
     CSP_MSG_SET_FIELD(minfo, size, csize); /* always set it. */
     
     if ((x = NATTR(node, "validlity")) != NULL) {
	  CSP_MSG_SET_FIELD(minfo, valid, strtoul(x, NULL, 10));
	  xmlFree(x);
     }
     
     if ((xnode = find_node(node->children, "DateTime", 2)) != NULL) {
	  struct universaltime ut;
	  Octstr *x = _xmlNodeContent(xnode);

	  if (date_parse_iso(&ut, x) >= 0) 
	       CSP_MSG_SET_FIELD(minfo, tdate, date_convert_universal(&ut));
	  octstr_destroy(x);
     }
     /* find recipients: We ignore the RecipientDisplay entity. Should we care about it? XXX */
     for (xnode = node->children; xnode; xnode = xnode->next) 
	  if (NMATCH(xnode, "Recipient") && 
	      (xnode2 = find_nodebytype(xnode->children, XML_ELEMENT_NODE, 1)) != NULL && 
	      (y = parse_user_type(xnode2)) != NULL) {
	       int typ = CSP_MSG_TYPE(y);
	       if (typ == Imps_GroupID || typ == Imps_ScreenName)
		    gwlist_append(r->glist, 
				  csp_msg_new(Group,NULL, UFV(u, typ, y)));
	       else if (typ != Imps_User) 
		    error(0, "parse_messageinfo: recipient of type [%s] not supported here!", 
			  xnode2->name);
	       else 
		    gwlist_append(r->ulist, y);
	  }
     /* find the sender and deal with SenderDisplay issues. */
     if ((xnode = find_node(node->children, "Sender", 1)) != NULL && 
	 ((xnode2 = find_node(xnode->children, "User", 1)) != NULL ||
	  (xnode2 = find_node(xnode->children, "GroupID", 1)) != NULL  )) {
	  void *xsender = make_ssp_sender(parse_user_type(xnode2));
	  void *x;
	  
	  if ((xnode2 = find_node(xnode->children, "SenderDisplay", 1)) != NULL && 
	      ((xnode = find_node(xnode2->children, "UserID", 1)) != NULL ||
	       (xnode = find_node(xnode2->children, "GroupID", 1)) != NULL || 
	       (xnode = find_node(xnode2->children, "ScreenName", 1)) != NULL) && /* we ignore Name. */
	      (x = make_ssp_sender(parse_user_type(xnode))) != NULL) {
	       csp_msg_free(xsender);
	       xsender = x;
	  }
	  CSP_MSG_SET_FIELD(minfo, sender, xsender);
     }
     
     return minfo;
}

#define FILL_RECIPIENT(robj, node, node_name) do {				\
	  xmlNodePtr xnode;						\
	  void *y;							\
	  if ((xnode = find_node(node->children, (node_name), 3)) != NULL && \
	      (xnode = find_nodebytype(xnode->children, XML_ELEMENT_NODE,3)) != NULL && \
	      (y = parse_user_type(xnode)) != NULL) {			\
	       int typ = CSP_MSG_TYPE(y);				\
	       if (typ == Imps_GroupID || typ == Imps_ScreenName) /* a group. */ \
		    CSP_MSG_SET_FIELD((robj), glist,			\
				      gwlist_create_ex(csp_msg_new(Group, NULL, UFV(u, typ, y)))); \
	       else							\
		    CSP_MSG_SET_FIELD((robj), ulist, gwlist_create_ex(y)); /* a user. */ \
	  }								\
	  								\
     } while (0)

#define FILL_SENDER(obj, fld, node, node_name) do {			\
	  xmlNodePtr xnode; \
	  if ((xnode = find_node((node)->children, (node_name), 3)) != NULL && \
	      (xnode = find_nodebytype(xnode->children, XML_ELEMENT_NODE,3)) != NULL) \
	       CSP_MSG_SET_FIELD((obj), fld, make_ssp_sender(parse_user_type(xnode))); \
     } while (0)


#define FILL_PRESENCE_VALUE(node, obj, fld) do {			\
	  char *y;							\
	  if ((y = NATTR((node), "userID")) != NULL) {			\
	       char *s = (strstr(y, "wv:") == y) ? y + 3 : y;		\
	       _User_Presence_t up = csp_msg_new(_User_Presence, NULL,	\
						 FV(user, csp_String_from_cstr(s, Imps_UserID))); \
	       PresenceSubList_t pslist = NULL;				\
	       xmlNodePtr z = find_node((node)->children, "PresenceSubList", 1); \
	       void *zz = NULL; /* dummy var. */				\
	       Presence_t p = csp_msg_new(Presence, NULL, UFV(pres, Imps__User_Presence, up)); \
	       if (z) parse_PresenceSubList(z, &zz, 0, (void *)&pslist);	\
	       if (pslist)						\
		    CSP_MSG_SET_FIELD(p, pslist, gwlist_create_ex(pslist)); \
	       gwlist_append((obj)->fld, p);				\
	       xmlFree(y);						\
	  }								\
     } while(0)

void FILL_PRESENCE_VALUE_X(xmlNodePtr node, void *obj_fld) 
{									
     char *y;							
     if ((y = NATTR((node), "userID")) != NULL) {
	  char *s = (strstr(y, "wv:") == y) ? y + 3 : y;
	  _User_Presence_t up = csp_msg_new(_User_Presence, NULL,	
					    FV(user, csp_String_from_cstr(s, Imps_UserID))); 
	  PresenceSubList_t pslist = NULL;				
	  xmlNodePtr z = find_node((node)->children, "PresenceSubList", 1); 
	  void *zz = NULL; /* dummy var. */				
	  Presence_t p = csp_msg_new(Presence, NULL, UFV(pres, Imps__User_Presence, up)); 
	  if (z) parse_PresenceSubList(z, &zz, 0, (void *)&pslist);	
	  if (pslist)						
	       CSP_MSG_SET_FIELD(p, pslist, gwlist_create_ex(pslist)); 
	  gwlist_append(obj_fld, p);				
	  xmlFree(y);						
     }								
}


#define PARSE_GROUP_MEMBER_LISTS(gm) do {				\
	  xmlNodePtr xnode;						\
	  if ((xnode = find_node(node->children, "Admins", 1)) != NULL) { \
	       List *ul = parse_userid_list(xnode->children, "UserID", Imps_User); \
	       UserList_t ulist = csp_msg_new(UserList, NULL, FV(ulist, ul)); \
									\
	       CSP_MSG_SET_FIELD(gm, admin,				\
				 csp_msg_new(Admin, NULL, FV(ulist, ulist))); \
	  }								\
	  if ((xnode = find_node(node->children, "Moderators", 1)) != NULL) { \
	       List *ul = parse_userid_list(xnode->children, "UserID", Imps_User); \
	       UserList_t ulist = csp_msg_new(UserList, NULL, FV(ulist, ul)); \
									\
	       CSP_MSG_SET_FIELD(gm, mod,				\
				 csp_msg_new(Mod, NULL, FV(ulist, ulist))); \
	  }								\
									\
	  if ((xnode = find_node(node->children, "OrdinaryUsers", 1)) != NULL) { \
	       List *ul = parse_userid_list(xnode->children, "UserID", Imps_User); \
	       UserList_t ulist = csp_msg_new(UserList, NULL, FV(ulist, ul)); \
									\
	       CSP_MSG_SET_FIELD(gm, ulist, ulist);			\
	  }								\
     } while(0)

void *ssp2csp_msg(xmlNodePtr node, List **rcptlist, User_t *sending_user, 
		  int csp_ver, 
		  void *orig_msg)
{
     void *msg;
     char *x;
     void *y;
     xmlNodePtr xnode;
     
     User_t user;
     xmlNodePtr meta_info;
     
     gw_assert(node);
     gw_assert(rcptlist);
     
     if ((meta_info = find_node(node->children, "MetaInfo",  3)) != NULL)
	  user = parse_metainfo(meta_info);
     else 
	  user = NULL;    
     *sending_user = user;
     *rcptlist = NULL;
     
     if (NMATCH(node, "InviteRequest")) {
	  Recipient_t r = csp_msg_new(Recipient, NULL, NULL);
	  Invite_Request_t inv = msg = csp_msg_new(Invite_Request, NULL, FV(rcpt, r));
	  
	  if ((x = NATTR(node, "inviteID")) != NULL) {
	       CSP_MSG_SET_FIELD(inv, invid, csp_String_from_cstr(x, Imps_InviteID));
	       xmlFree(x);
	  }
	  if ((x = NATTR(node, "inviteType")) != NULL) {
	       CSP_MSG_SET_FIELD(inv, invtype, csp_String_from_cstr(x, Imps_InviteType));
	       xmlFree(x);
	  }

	  if ((x = NATTR(node, "validity")) != NULL) {
	       CSP_MSG_SET_FIELD(inv, valid, atoi(x));
	       xmlFree(x);
	  }


	  FILL_SENDER(inv, sender, node, "Inviting");

	  FILL_RECIPIENT(r, node, "Invited");
	  
	  if ((xnode = find_node(node->children, "GroupID", 3)) != NULL)
	       CSP_MSG_SET_FIELD(inv, gid, parse_user_type(xnode));

	  if ((xnode = find_node(node->children, "ApplicationID", 3)) != NULL && 
	      (x = NATTR(xnode, "applicationID")) != NULL) {
	       CSP_MSG_SET_FIELD(inv, appid, csp_String_from_cstr(x, Imps_ApplicationID));
	       xmlFree(x);
	  } 
	  
	  if ((xnode = find_node(node->children, "AttributeList", 3)) != NULL && 
	      (xnode = find_node(xnode->children, "PresenceSubList", 3)) != NULL) {
	       PresenceSubList_t pslist  = NULL;
	       parse_PresenceSubList(xnode, &y, 0, (void *)&pslist);
	       CSP_MSG_SET_FIELD(inv, pslist, pslist);
	  }
	  
	  if ((xnode = find_node(node->children, "ContentID", 3)) != NULL) {
	       URLList_t url_list = csp_msg_new(URLList, NULL, 
				      FV(ulist, gwlist_create()));
	       while (xnode) {
		    char *x;
		    
		    if (NMATCH(xnode, "ContentID") &&
			(x = NATTR(xnode, "url")) != NULL) {
			 gwlist_append(url_list->ulist, csp_String_from_cstr(x, Imps_URL));
			 xmlFree(x);
		    }
		    xnode = xnode->next;
	       }
	       CSP_MSG_SET_FIELD(inv, url_list, url_list);
	  } 
	  
	  if ((xnode = find_node(node->children, "InviteNote", 3)) != NULL) {
	       Octstr *x = _xmlNodeContent(xnode);
	       CSP_MSG_SET_FIELD(inv,  inote, csp_String_from_bstr(x, Imps_InviteNote));
	       octstr_destroy(x);
	  } 
	  
	  if ((xnode = find_node(node->children, "ScreenName", 1)) != NULL) 
	       CSP_MSG_SET_FIELD(inv, sname, parse_user_type(xnode));
     } else if (NMATCH(node, "InviteResponse")) {
	  /* we turn it into an inviteuser_response so handler treats it as client originated.
	   */

	  Recipient_t r = csp_msg_new(Recipient, NULL, NULL);
	  InviteUser_Response_t iv = msg = csp_msg_new(InviteUser_Response, NULL, FV(rcpt, r));

	  if ((x = NATTR(node, "inviteID")) != NULL) {
	       CSP_MSG_SET_FIELD(iv, invid, csp_String_from_cstr(x, Imps_InviteID));
	       xmlFree(x);
	  }
	  
	  if ((x = NATTR(node, "acceptance")) != NULL) {	       
	       CSP_MSG_SET_FIELD(iv, accept, strcasecmp(x, "yes") == 0);
	       xmlFree(x);
	  }
	  
	  FILL_SENDER(iv,sender,node,"Responding");
	  FILL_RECIPIENT(r,node,"Inviting");

	  if ((xnode = find_node(node->children, "ResponseNote", 3)) != NULL) {
	       Octstr *x = _xmlNodeContent(xnode);
	       CSP_MSG_SET_FIELD(iv, rnote, csp_String_from_bstr(x, Imps_ResponseNote));
	       octstr_destroy(x);
	  }
	  
	  if ((xnode = find_node(node->children, "ScreenName", 1)) != NULL) {
	       void *x = parse_user_type(xnode);
	       if (x && CSP_MSG_TYPE(x) == Imps_ScreenName) 
		    CSP_MSG_SET_FIELD(iv, sname, x);
	       else
		    csp_msg_free(x);
	  }
     } else if (NMATCH(node, "Status")) { /* Turn into a status thingie. */
	  char *code = NATTR(node, "code");
	  Result_t r = msg = csp_msg_new(Result, NULL,
				 FV(code, code ? atoi(code) : 404),
				 FV(drlist, gwlist_create()));
	  DetailedResult_t dr;

	  if ((xnode = find_node(node->children, "StatusDescription", 1)) != NULL) {
	       Octstr *x = _xmlNodeContent(xnode);
	       CSP_MSG_SET_FIELD(r, descr, csp_String_from_bstr(x, Imps_Description));
	       octstr_destroy(x);
	  }


	  if ((xnode = find_node(node->children, "TryAgainTimeout", 1)) != NULL) {
	       Octstr *x = _xmlNodeContent(xnode);
	       CSP_MSG_SET_FIELD(r, tatimeout, atoi(octstr_get_cstr(x)));
	       octstr_destroy(x);
	  }
	  
	  /* look for detailedresult nodes. */
	  for (xnode = node->children; xnode; xnode = xnode->next) 
	       if (NMATCH(xnode, "DetailedResult")) 
		    if ((dr = parse_detailed_result(xnode)) != NULL) 
			 gwlist_append(r->drlist, dr);
	  
	  if (code) xmlFree(code);
     } else if (NMATCH(node, "CancelInviteRequest")) {
	  Recipient_t r = csp_msg_new(Recipient, NULL, NULL);
	  CancelInvite_Request_t cr = msg = csp_msg_new(CancelInvite_Request, NULL, FV(rcpt, r));
	  
	  if ((x = NATTR(node, "inviteID")) != NULL) {
	       CSP_MSG_SET_FIELD(cr, invid, csp_String_from_cstr(x, Imps_InviteID));
	       xmlFree(x);
	  }

	  FILL_SENDER(cr, sender, node, "Canceling");

	  FILL_RECIPIENT(r, node, "Canceled");
	  
	  if ((xnode = find_node(node->children, "GroupID", 3)) != NULL)
	       CSP_MSG_SET_FIELD(cr, gid, parse_user_type(xnode));

	  if ((xnode = find_node(node->children, "ApplicationID", 3)) != NULL && 
	      (x = NATTR(xnode, "applicationID")) != NULL) {
	       CSP_MSG_SET_FIELD(cr, appid, csp_String_from_cstr(x, Imps_ApplicationID));
	       xmlFree(x);
	  } 
	  
	  if ((xnode = find_node(node->children, "AttributeList", 3)) != NULL && 
	      (xnode = find_node(xnode->children, "PresenceSubList", 1)) != NULL) {
	       PresenceSubList_t pslist  = NULL;
	       parse_PresenceSubList(xnode, &y, 0, (void *)&pslist);
	       CSP_MSG_SET_FIELD(cr, pslist, pslist);
	  }
	  
	  if ((xnode = find_node(node->children, "ContentID", 3)) != NULL) {
	       URLList_t url_list = csp_msg_new(URLList, NULL, 
				      FV(ulist, gwlist_create()));
	       while (xnode) {
		    char *x;
		    
		    if (NMATCH(xnode, "ContentID") &&
			(x = NATTR(xnode, "url")) != NULL) {
			 gwlist_append(url_list->ulist, csp_String_from_cstr(x, Imps_URL));
			 xmlFree(x);
		    }
		    xnode = xnode->next;
	       }
	       CSP_MSG_SET_FIELD(cr, ulist, url_list);
	  } 
	  
	  if ((xnode = find_node(node->children, "CancelNote", 3)) != NULL) {
	       Octstr *x = _xmlNodeContent(xnode);
	       CSP_MSG_SET_FIELD(cr,  inote, csp_String_from_bstr(x, Imps_InviteNote));
	       octstr_destroy(x);
	  } 
	  
	  if ((xnode = find_node(node->children, "ScreenName", 1)) != NULL) 
	       CSP_MSG_SET_FIELD(cr, sname, parse_user_type(xnode));
     } else if (NMATCH(node, "SubscribeRequest")) {
	  char *x;
	  UserIDList_t ul = csp_msg_new(UserIDList, NULL, /* we use 1.3 style. */
					FV(ulist, gwlist_create()));
	  SubscribePresence_Request_t sp = msg = csp_msg_new(SubscribePresence_Request, NULL,
						       FV(uidlist, ul));
	  /* first handle attributes. */
	  
	  if ((xnode = find_node(node->children, "AttributeList", 3)) != NULL && 
	      (xnode = find_node(xnode->children, "PresenceSubList", 1)) != NULL) {
	       PresenceSubList_t pslist  = NULL;
	       parse_PresenceSubList(xnode, &y, 0, (void *)&pslist);
	       CSP_MSG_SET_FIELD(sp, plist, pslist);
	  }
	  /* now handle user list. */
	  for (xnode = node->children; xnode; xnode = xnode->next) 
	       if (NMATCH(xnode, "UserID") && 
		   (x = NATTR(xnode, "userID")) != NULL) {
		    gwlist_append(ul->ulist, 
				  csp_String_from_cstr(x, Imps_UserID));		    
		    xmlFree(x);
	       }
     } else if (NMATCH(node, "UnsubscribeRequest")) {
	  char *x;
	  UserIDList_t ul = csp_msg_new(UserIDList, NULL, /* we use 1.3 style. */
					FV(ulist, gwlist_create()));
	  msg = csp_msg_new(UnsubscribePresence_Request, NULL,
			    FV(uidlist, ul));
	  
	  /* now handle user list. */
	  for (xnode = node->children; xnode; xnode = xnode->next) 
	       if (NMATCH(xnode, "UserID") && 
		   (x = NATTR(xnode, "userID")) != NULL) {
		    gwlist_append(ul->ulist, 
				  csp_String_from_cstr(x, Imps_UserID));		    
		    xmlFree(x);
	       }
     } else if (NMATCH(node, "PresenceNotification")) {
	  PresenceNotification_Request_t pr =  msg = csp_msg_new(PresenceNotification_Request, NULL,
							  FV(plist, gwlist_create()));
	  List *rlist = *rcptlist = gwlist_create(); /* we need to return the list of recipients. */
	  void *y;
	  
	  /* handle recipients. and presence values in one go. */
	  for (xnode = node->children; xnode; xnode = xnode->next) 
	       if (NMATCH(xnode, "User") && 
		   (y = parse_user_type(xnode)) != NULL)
		    gwlist_append(rlist, y);
	       else if (NMATCH(xnode, "PresenceValue"))
		    FILL_PRESENCE_VALUE_X(xnode, pr->plist);
     } else if (NMATCH(node, "GetPresenceRequest")) {
	  UserIDList_t ul = csp_msg_new(UserIDList, NULL, /* we use 1.3 style. */
					FV(ulist, gwlist_create()));
	  GetPresence_Request_t gp = msg = csp_msg_new(GetPresence_Request, NULL, 
						 UFV(u, Imps_UserIDList, ul));
	  void *x;
	  
	  /* handle user list, ignore version for now. */
	  for (xnode = node->children; xnode; xnode = xnode->next) 
	       if (NMATCH(xnode, "VerUserID") && 
		   (x = NATTR(xnode, "userID")) != NULL) {
		    gwlist_append(ul->ulist, 
				  csp_String_from_cstr(x, Imps_UserID));		    
		    xmlFree(x);
	       }
	  
	  if ((xnode = find_node(node->children, "AttributeList", 3)) != NULL && 
	      (xnode = find_node(xnode->children, "PresenceSubList", 1)) != NULL) {
	       PresenceSubList_t pslist  = NULL;
	       parse_PresenceSubList(xnode, &x, 0, (void *)&pslist);
	       CSP_MSG_SET_FIELD(gp, pslist, pslist);
	  }
     } else if (NMATCH(node, "GetPresenceResponse")) { /* treat as notification. */
	  xmlNodePtr status_node = find_node(node->children, "Status", 2);
	  void *x1, *x2; /* dummies for below. */
	  Result_t r = status_node ? ssp2csp_msg(status_node, (void *)&x1, 
						 (void *)&x2, csp_ver, NULL) : NULL;
	  PresenceNotification_Request_t  pn = msg = csp_msg_new(PresenceNotification_Request, NULL, 
								 FV(plist, gwlist_create()));
	  
	  if (r == NULL || r->code != 200) {
	       msg = NULL;
	       csp_msg_free(pn);
	  } else 
	       /* handle presence values. */
	       for (xnode = node->children; xnode; xnode = xnode->next) 
		    if (NMATCH(xnode, "PresenceValue"))
			 FILL_PRESENCE_VALUE(xnode, pn, plist);
	  csp_msg_free(r);
     } else if (NMATCH(node, "SendMessageRequest")) {
	  char *x = NATTR(node,"deliveryReport");
	  SendMessage_Request_t sm = msg = csp_msg_new(SendMessage_Request, NULL,
						       FV(dreport, 
							  (x && strcasecmp(x, "yes") == 0)));
	  MessageInfo_t minfo = NULL; 
	  int csize;
	  
	  /* get content. */
	  if ((xnode = find_node(node, "ContentData", 1)) != NULL) {
	       Octstr *x = _xmlNodeContent(xnode);
	       char *enc = NATTR(xnode, "encoding");
	       
	       if (enc) 
		    octstr_base64_to_binary(x);
	       
	       csize = octstr_len(x);
	       
	       CSP_MSG_SET_FIELD(sm, data, csp_String_from_bstr(x, Imps_ContentData));
	       octstr_destroy(x);
	       if (enc) xmlFree(enc);
	  } else 
	       csize = 0;
	  
	  if ((xnode = find_node(node, "MessageInfo", 1)) != NULL)
	       minfo = parse_message_info(xnode, csize); /* we return the real sender.*/
	  else 
	       minfo = NULL;
	  CSP_MSG_SET_FIELD(sm, msginfo, minfo);
	  if (x) xmlFree(x);
     } else if (NMATCH(node, "SendMessageResponse")) {
	  void *x1, *x2; /* dummies. */
	  char *msgid = NATTR(node, "messageID");
	  Result_t r = (xnode = find_node(node->children, "Status", 2)) ? 
	       ssp2csp_msg(xnode, (void *)&x1, (void *)&x2, csp_ver, NULL) : NULL;
	  msg = csp_msg_new(SendMessage_Response, NULL,
			    FV(res, r));
			    
	  if (msgid)
	       CSP_MSG_SET_FIELD((SendMessage_Response_t)msg, msgid, 
				 csp_String_from_cstr(msgid, Imps_MessageID));
	  if (msgid) xmlFree(msgid);
     } else if (NMATCH(node, "DeliveryStatusReport")) {
	  void *x1, *x2; /* dummies. */
	  xmlNodePtr xnode;
	  MessageInfo_t minfo = (xnode = find_node(node->children, "MessageInfo", 1)) ?
	       parse_message_info(xnode, 0) : NULL;
	  Result_t r = (xnode = find_node(node->children, "Status", 3)) ? 
	       ssp2csp_msg(xnode, (void *)&x1, (void *)&x2, csp_ver, NULL) : NULL;
	  DeliveryReport_Request_t dlr = msg = csp_msg_new(DeliveryReport_Request, NULL,
							   FV(res, r), FV(minfo, minfo));
	  
	  if ((xnode = find_node(node->children, "DeliveryTime", 2)) != NULL) {
	       struct universaltime ut;
	       Octstr *x = _xmlNodeContent(xnode);
	       
	       if (date_parse_iso(&ut, x) >= 0) 
		    CSP_MSG_SET_FIELD(dlr, dtime, date_convert_universal(&ut));
	       octstr_destroy(x);
	  }	  
     } else if (NMATCH(node, "DeleteGroupRequest")) {
	  char *x = NATTR(node, "groupID");
	  msg = (x) ?  csp_msg_new(DeleteGroup_Request, NULL,
				   FV(gid, csp_String_from_cstr(x, 
								Imps_GroupID))) : NULL;
	  if (x) xmlFree(x);
     } else if (NMATCH(node, "JoinGroupRequest")) {
	  char *x = NATTR(node, "groupID");
	  JoinGroup_Request_t jg = msg = (x) ? 
	       csp_msg_new(JoinGroup_Request, NULL,
			   FV(gid,
			      csp_String_from_cstr(x, Imps_GroupID))) : NULL;
	  if (jg) {
	    void *y, *x;
	       if ((x = NATTR(node, "joinedListRequest")) != NULL) {
		    CSP_MSG_SET_FIELD(jg, jreq, strcasecmp(x, "yes") == 0);
		    xmlFree(x);
	       }
	       if ((x = NATTR(node, "subscribeNotif")) != NULL) {
		    CSP_MSG_SET_FIELD(jg, snotify, strcasecmp(x, "yes") == 0);
		    xmlFree(x);
	       }
	       
	       if ((xnode = find_node(node->children, "OwnProperties", 2)) != NULL) {
		    OwnProperties_t op = NULL;
		    void *z; /* dummy. */
		    parse_OwnProperties(xnode, &z, 0, (void *)&op);
		    CSP_MSG_SET_FIELD(jg, oprop, op);
	       }
	       if ((xnode = find_node(node->children, "ScreenName", 2)) != NULL && 
		   (y = parse_user_type(xnode)) != NULL) 
		    CSP_MSG_SET_FIELD(jg, sname, y);	       
	  }
	  if (x) xmlFree(x);
     } else if (NMATCH(node, "JoinGroupResponse")) {
	  void *x1, *x2; /* dummies */
	  List *ml = gwlist_create();
	  List *ul = gwlist_create();
	  WelcomeNote_t wnote = (xnode = find_node(node->children, "WelcomeNote", 2)) ? 
	       parse_welcome_note(xnode) : NULL;
	  Result_t r = (xnode = find_node(node->children, "Status",2)) ? 
	       ssp2csp_msg(xnode, (void *)&x1, (void *)&x2, csp_ver, NULL) : NULL;
	  JoinGroup_Response_t jg = msg = csp_msg_new(JoinGroup_Response, NULL,
						      FV(wnote, wnote));
	  JoinGroup_Request_t orig = orig_msg && 
	       (CSP_MSG_TYPE(orig_msg) == Imps_JoinGroup_Request) ? 
	       orig_msg : NULL;
	  GroupID_t ogid = orig ? orig->gid : NULL; /* Look at original message. */
	  
	  if ((xnode = find_node(node->children, "JoinedList", 1)) != NULL)
	       for (xnode = xnode->children; xnode; xnode = xnode->next)
		    if (NMATCH(xnode, "Name") && 
			(x1 = _xmlNodeContent(xnode))  != NULL) {
			 SName_t s = csp_String_from_bstr(x1, Imps_SName);
			 if (csp_ver > CSP_VERSION(1,1))
			      gwlist_append(ml, csp_msg_new(Mapping, NULL, FV(sname, s)));
			 else {
			      ScreenName_t sx = csp_msg_new(ScreenName, NULL,
							    FV(sname, s),
							    FV(gid, csp_msg_copy(ogid))); 
			      gwlist_append(ul, sx);
			 }
			 octstr_destroy(x1);
		    }
	  if (gwlist_len(ml) > 0) {	       
	       UserMapping_t um = csp_msg_new(UserMapping, NULL, FV(mlist, ml));
	       UserMapList_t uml = csp_msg_new(UserMapList, NULL, 
					       FV(umap, um));
	       if (csp_ver >= CSP_VERSION(1,3))
		   CSP_MSG_SET_FIELD(jg, joined, 
				     csp_msg_new(Joined, NULL, 
						 FV(umlist, uml)));
	       else /* v1.2 uses usermap list */
		    CSP_MSG_SET_FIELD(jg, umlist, uml);
	  } else 
	       gwlist_destroy(ml, NULL);

	  if (gwlist_len(ul) > 0) {
	       UserList_t ux = csp_msg_new(UserList, NULL, FV(slist, ul));
	       CSP_MSG_SET_FIELD(jg, ulist, ux);
	  } else 
	       gwlist_destroy(ul, NULL);

	  if (r && r->code != 200) {
	       csp_msg_free(jg);
	       msg = r; /* error. */
	  } else 
	       csp_msg_free(r); 
     } else if (NMATCH(node, "LeaveGroupRequest")) {
	  char *x = NATTR(node, "groupID");
	  msg = (x) ?  csp_msg_new(LeaveGroup_Request, NULL,
				   FV(gid, csp_String_from_cstr(x, 
								Imps_GroupID))) : NULL;
	  if (x) xmlFree(x);
     }  else if (NMATCH(node, "LeaveGroupIndication")) {
	  void *x1, *x2; /* dummies */
	  char *x = NATTR(node, "groupID");
	  Result_t r = (xnode = find_node(node->children, "Status", 1)) ? 
	       ssp2csp_msg(xnode, (void *)&x1, (void *)&x2, csp_ver, NULL) : NULL;

	  msg = (x) ?  csp_msg_new(LeaveGroup_Response, NULL,
				   FV(gid, csp_String_from_cstr(x, 
								Imps_GroupID)), 
				   FV(res, r)) : NULL;
	  if (x) xmlFree(x);
     } else if (NMATCH(node, "GetGroupMemberRequest")) {
	  char *x = NATTR(node, "groupID");
	  msg = (x) ?  csp_msg_new(GetGroupMembers_Request, NULL,
				   FV(gid, csp_String_from_cstr(x, 
								Imps_GroupID))) : NULL;
	  if (x) xmlFree(x);
     } else if (NMATCH(node, "GetGroupMemberResponse")) {
	  GetGroupMembers_Response_t gm = msg = csp_msg_new(GetGroupMembers_Response,
							    NULL, NULL);

	  PARSE_GROUP_MEMBER_LISTS(gm);
	  
     } else if (NMATCH(node, "GetJoinedUsersRequest")) {
	  char *x = NATTR(node, "groupID");
	  
	  if (x) {
	       msg = csp_msg_new(GetJoinedUsers_Request, NULL,
				 FV(gid, csp_String_from_cstr(x, Imps_GroupID)));
	       xmlFree(x);
	  } else 
	       msg = NULL;
     } else if (NMATCH(node, "GetJoinedUsersResponse")) {
	  void *x1, *x2;
	  GetJoinedUsers_Request_t orig = orig_msg && 
	       (CSP_MSG_TYPE(orig_msg) == Imps_GetJoinedUsers_Request) ? orig_msg : NULL;
	  GroupID_t ogid = orig ? orig->gid : NULL;
	  Result_t r = (xnode = find_node(node->children, "Status", 1)) ? 	  
	       ssp2csp_msg(xnode, (void *)&x1, (void *)&x2, csp_ver, NULL) : NULL;
	  if (r && r->code != 200)
	       msg = r;
	  else {
	       GetJoinedUsers_Response_t gj = msg = csp_msg_new(GetJoinedUsers_Response, 
								NULL, NULL);
	       AdminMapList_t amap = NULL;
	       UserMapList_t umap = NULL;
	       
	       csp_msg_free(r);
	       if ((xnode = find_node(node->children, "JoinedAdmin", 1)) != NULL) {
		    List *xl = parse_mapping_list(xnode->children, Imps_Mapping, ogid);
		    AdminMapping_t x = csp_msg_new(AdminMapping, NULL, FV(mlist, xl));
		    
		    amap = csp_msg_new(AdminMapList, NULL, FV(amap, x));
	       }

	       if ((xnode = find_node(node->children, "JoinedUsers", 1)) != NULL) {
		    List *xl = parse_mapping_list(xnode->children, Imps_Mapping, ogid);
		    UserMapping_t x = csp_msg_new(UserMapping, NULL, FV(mlist, xl));
		    if (amap) 
			 CSP_MSG_SET_FIELD(amap, umap, x);
		    else 
			 umap = csp_msg_new(UserMapList, NULL, FV(umap, x));
	       }
	       
	       CSP_MSG_SET_UFIELD(gj, u, 
				  amap ? Imps_AdminMapList : Imps_UserMapList,
				  amap ? (void *)amap : umap); /* set the union field. */

	       if ((xnode = find_node(node->children, "JoinedBlocked", 1)) != NULL) {
		    List *xl = parse_mapping_list(xnode->children, Imps_ScreenName, ogid);
		    UserList_t ulist = csp_msg_new(UserList, NULL, 
						   FV(slist, xl));
		    CSP_MSG_SET_FIELD(gj,jb, 
				      csp_msg_new(JoinedBlocked, NULL,
						  FV(ulist, ulist)));	    		    
	       }
	  }
     } else if (NMATCH(node, "MemberAccessRequest")) {
	  char *x = NATTR(node, "groupID");
	  MemberAccess_Request_t gm = msg = csp_msg_new(MemberAccess_Request, NULL,
							FV(gid, 
							   csp_String_from_cstr(x ? x: "", 
										Imps_GroupID)));
	  PARSE_GROUP_MEMBER_LISTS(gm);
	  if (x) xmlFree(x);
     } else if (NMATCH(node, "AddGroupMemberRequest")) {
	  char *x = NATTR(node, "groupID");
	  List *ulist = parse_userid_list(node->children, "UserID", Imps_UserID);
	  UserIDList_t ul = csp_msg_new(UserIDList, NULL, FV(ulist, ulist));

	  msg = csp_msg_new(AddGroupMembers_Request, NULL,
			    FV(gid, 
			       csp_String_from_cstr(x ? x: "", 
						    Imps_GroupID)),
			    UFV(ulist, Imps_UserIDList, ul));	  
	  if (x) xmlFree(x);
     }  else if (NMATCH(node, "RemoveGroupMemberRequest")) {
	  char *x = NATTR(node, "groupID");
	  List *ulist = parse_userid_list(node->children, "UserID", Imps_UserID);
	  UserIDList_t ul = csp_msg_new(UserIDList, NULL, FV(ulist, ulist));
	  
	  msg = csp_msg_new(RemoveGroupMembers_Request, NULL,
			    FV(gid, 
			       csp_String_from_cstr(x ? x: "", 
						    Imps_GroupID)),
			    UFV(ulist, Imps_UserIDList, ul));	  
	  if (x) xmlFree(x);
     } else if (NMATCH(node, "GetGroupPropsRequest")) {
	  char *x = NATTR(node, "groupID");
	  msg = (x) ?  csp_msg_new(GetGroupProps_Request, NULL,
				   FV(gid, csp_String_from_cstr(x, 
								Imps_GroupID))) : NULL;
	  if (x) xmlFree(x);
     }  else if (NMATCH(node, "GetGroupPropsResponse")) {
	  void *x1, *x2;
	  Result_t r = (xnode = find_node(node->children, "Status", 1)) ? 	  
	       ssp2csp_msg(xnode, (void *)&x1, (void *)&x2, csp_ver, NULL) : NULL;
	  if (r && r->code != 200)
	       msg = r;
	  else {
	       void *x1;
	       OwnProperties_t oprop = NULL;
	       GetGroupProps_Response_t gprop;
	       
	       if ((xnode = find_node(node->children, "OwnProperties", 1)) != NULL)
		    parse_OwnProperties(xnode, (void *)&x1, 0, (void *)&oprop);		   
	       
	       gprop = msg = csp_msg_new(GetGroupProps_Response, NULL,
					 FV(oprop, oprop));
	       if ((xnode = find_node(node->children, "GroupProperties", 1)) != NULL) 
		    CSP_MSG_SET_FIELD(gprop, gprop, parse_gprop(xnode));
		    
	  }		   
     } else if (NMATCH(node, "SetGroupPropsRequest")) {
	  char *x = NATTR(node, "groupID");
	  void *x1;
	  OwnProperties_t oprop = NULL;

	  SetGroupProps_Request_t sg = msg =  
	       csp_msg_new(SetGroupProps_Request, NULL,
			   FV(gid, csp_String_from_cstr(x ? x : "", 
							Imps_GroupID)));
	  
	  if ((xnode = find_node(node->children, "OwnProperties", 1)) != NULL)
	       parse_OwnProperties(xnode, (void *)&x1, 0, (void *)&oprop);		   
	  
	  CSP_MSG_SET_FIELD(sg, oprop, oprop);
	  
	  if ((xnode = find_node(node->children, "GroupProperties", 1)) != NULL) 
	       CSP_MSG_SET_FIELD(sg, gprop, parse_gprop(xnode));
	  
	  if (x) xmlFree(x);

     } else if (NMATCH(node, "RejectListRequest")) {
	  char *x = NATTR(node, "groupID");
	  GroupID_t gid = csp_String_from_cstr(x ? x : "", Imps_GroupID);
	  RejectList_Request_t r = msg = csp_msg_new(RejectList_Request, NULL,
					       FV(gid, gid));
	  
	  if ((xnode =  find_node(node->children, "AddUsers", 1)) != NULL) {
	       List *l = parse_userid_list(xnode->children, "UserID", Imps_UserID);
	       AddList_t al = csp_msg_new(AddList, NULL, FV(users, l));
	       CSP_MSG_SET_FIELD(r, alist, al);
	  }
	  if ((xnode =  find_node(node->children, "RemoveUsers", 1)) != NULL) {
	       List *l = parse_userid_list(xnode->children, "UserID", Imps_UserID);
	       RemoveList_t rl = csp_msg_new(RemoveList, NULL, FV(users, l));
	       CSP_MSG_SET_FIELD(r, rlist, rl);
	  }
	  if (x) xmlFree(x);
     } else if (NMATCH(node, "RejectListResponse")) {
	  RejectList_Response_t rj = msg = csp_msg_new(RejectList_Response, NULL, NULL);

	  if ((xnode =  find_node(node->children, "RejectList", 1)) != NULL) {
	       List *l = parse_userid_list(xnode->children, "UserID", Imps_User);
	       UserList_t ul = csp_msg_new(UserList, NULL, FV(ulist, l));
	       
	       CSP_MSG_SET_FIELD(rj, ulist, ul);
	  }
     } else if (NMATCH(node, "SubscribeGroupChangeRequest") || 
		NMATCH(node, "UnsubscribeGroupChangeRequest") ||
		NMATCH(node, "GetGroupSubStatusRequest")) {  /* all map to the same save for stype */
	  char *x = NATTR(node, "groupID");
	  char *stype;
	  
	  if (NMATCH(node, "SubscribeGroupChangeRequest"))
	      stype = "S";
	  else if (NMATCH(node, "UnsubscribeGroupChangeRequest"))
	       stype = "U";
	  else 
	       stype = "G";
	  
	  msg = csp_msg_new(SubscribeGroupNotice_Request, NULL,
			    FV(gid, csp_String_from_cstr(x ? x : "", 
							 Imps_GroupID)),
			    FV(stype, csp_String_from_cstr(stype, Imps_SubscribeType)));
	  if (x) xmlFree(x);
     } else if (NMATCH(node, "GetGroupSubStatusResponse")) {
	  char *x = NATTR(node, "subscribed");	  
	  char *sres = (x && strcasecmp(x, "Yes") == 0) ? "T" : "F";

	  msg = csp_msg_new(SubscribeGroupNotice_Response, NULL,
			    FV(value, csp_String_from_cstr(sres, Imps_Value)));
	  if (x) xmlFree(x);
     } else if (NMATCH(node, "GroupChangeNotice")) {
	  User_t ux;
	  Octstr *x1;	  
	  char *x = NATTR(node, "groupID");
	  GroupID_t xgid = x ? csp_String_from_cstr(x, Imps_GroupID) : NULL;
	  GroupChangeNotice_t gc = msg = csp_msg_new(GroupChangeNotice, NULL,
						     FV(gid, xgid));
	  
	  /* get the recipient list */
	  *rcptlist = gwlist_create();
	  for (xnode = node->children; xnode; xnode = xnode->next)
	       if (NMATCH(xnode, "User") && 
		   (ux = parse_user_type(xnode)) != NULL)
		    gwlist_append(*rcptlist, ux);
	  
	  if ((xnode = find_node(node->children, "Joined", 1)) != NULL) {
	       List *ml = gwlist_create();
	       UserMapping_t um;
	       UserMapList_t uml;
	       for (xnode = xnode->children; xnode; xnode = xnode->next)
		    if (NMATCH(xnode, "Name") && 
			(x1 = _xmlNodeContent(xnode))  != NULL) {
			 SName_t s = csp_String_from_bstr(x1, Imps_SName);
			 
			 gwlist_append(ml, csp_msg_new(Mapping, NULL, FV(sname, s)));
			 octstr_destroy(x1);
		    }
	       um = csp_msg_new(UserMapping, NULL, FV(mlist, ml));
	       uml = csp_msg_new(UserMapList, NULL, 
				 FV(umap, um));
	       CSP_MSG_SET_FIELD(gc, joined, csp_msg_new(Joined, NULL, 
							 FV(umlist, uml)));
	  }
	  
	  if ((xnode = find_node(node->children, "Left", 1)) != NULL) {
	       UserList_t ul = csp_msg_new(UserList, NULL, FV(slist, gwlist_create()));

	       for (xnode = xnode->children; xnode; xnode = xnode->next)
		    if (NMATCH(xnode, "Name") && 
			(x1 = _xmlNodeContent(xnode))  != NULL) {
			 SName_t s = csp_String_from_bstr(x1, Imps_SName);
			 ScreenName_t sn = csp_msg_new(ScreenName, NULL, 
						       FV(sname, s),
						       FV(gid, csp_msg_copy(xgid)));
			 
			 gwlist_append(ul->slist, sn);
			 octstr_destroy(x1);
		    }
	       CSP_MSG_SET_FIELD(gc, left, 
				 csp_msg_new(Left, NULL, FV(ulist, ul)));
	  }
	  
	  if ((xnode = find_node(node->children, "JoinedBlocked", 1)) != NULL) {
	       List *xl = parse_mapping_list(xnode->children, Imps_ScreenName, xgid);
	       UserList_t ulist = csp_msg_new(UserList, NULL, 
					      FV(slist, xl));
	       CSP_MSG_SET_FIELD(gc,jblock, 
				 csp_msg_new(JoinedBlocked, NULL,
					     FV(ulist, ulist)));	    		    
	  }

	  if ((xnode = find_node(node->children, "LeftBlocked", 1)) != NULL && 
	      (xnode = find_node(xnode->children, "UserList", 1)) != NULL) {
	       UserList_t ulist = csp_msg_new(UserList, NULL, 
					      FV(ulist, gwlist_create()),
					      FV(slist, gwlist_create()));
	       ScreenName_t sn;
	       User_t ux;
	       
	       /* Look for screennames */
	       for (xnode = xnode->children; xnode; xnode = xnode->next) 
		    if (NMATCH(xnode, "ScreenName") && 
			(sn = parse_user_type(xnode)) != NULL)
			 gwlist_append(ulist->slist, sn);
		    else if (NMATCH(xnode, "User") && 
			     (ux = parse_user_type(xnode)) != NULL)
			 gwlist_append(ulist->ulist, ux);
	       
	       CSP_MSG_SET_FIELD(gc, lblock, 
				 csp_msg_new(LeftBlocked, NULL,
					     FV(ulist, ulist)));
	  }

	  if ((xnode = find_node(node->children, "GroupProperties", 1)) != NULL) 
	       CSP_MSG_SET_FIELD(gc, gprop, parse_gprop(xnode));

	  if ((xnode = find_node(node->children, "OwnProperties", 1)) != NULL) {
	       OwnProperties_t op = NULL;
	       void *z; /* dummy. */
	       parse_OwnProperties(xnode, &z, 0, (void *)&op);

	       CSP_MSG_SET_FIELD(gc, oprop, op);
	  }
	  if (x) xmlFree(x);
     } else
	  msg = NULL;
     
     return msg;
}
