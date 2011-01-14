-- 
CREATE LANGUAGE plpgsql; -- and ignore result
-- users table
CREATE TABLE users (
 id bigserial PRIMARY KEY,
 userid text NOT NULL,
 domain text NOT NULL DEFAULT '',
 
 firstname text NOT NULL DEFAULT '', 
 lastname  text NOT NULL DEFAULT '', 
 
 nickname  text NOT NULL DEFAULT '', -- can also be the name of the Bot

 email  text NOT NULL DEFAULT '',  

 phone  text NOT NULL DEFAULT '',  
 city  text NOT NULL DEFAULT '',  
 country  text NOT NULL DEFAULT '',  
 gender  text  CHECK (gender IN ('M','F','U')),  
 
 dob timestamp, -- date of birth.	 
 online_status text NOT NULL DEFAULT 'Offline',

 intention text,
 hobbies text,

 marital_status varchar(1) DEFAULT 'U' CHECK (marital_status IN ('C','D','E','M','S','U','W')),
 other_info text, -- free_text field

 
 nonce text NOT NULL DEFAULT 'nonce', -- random nonce
 rand_salt text NOT NULL DEFAULT random():: text || current_timestamp::text, -- salt for use below 
 crypt_md5_pass text NOT NULL DEFAULT '', -- md5(md5(password + nonce) + rand_salt)

 lastt timestamp NOT NULL DEFAULT current_timestamp,
   
  default_attr_list int, -- default authorised presence attr list (as a bits, one for each attribute, in order of appearance in spec)
 
  default_notify boolean NOT NULL DEFAULT TRUE, -- if default notification is sought. 

  grant_list_in_use boolean NOT NULL DEFAULT FALSE,
  block_list_in_use boolean NOT NULL DEFAULT FALSE,
  -- more fields as needed
  auto_reg boolean NOT NULL DEFAULT FALSE,
  bot_url text, -- If this is set, then it is the URL of the agent who handles IMs to this user. 
                -- this means that this is actually a Bot not a real user. 
  security_question text NOT NULL DEFAULT '',
  security_answer text,
 UNIQUE(userid,domain)
);

CREATE VIEW users_view AS 
SELECT 'wv:'|| (case when domain = '' then userid else userid || '@' || domain end) as full_userid, 
* from users;



CREATE TABLE sessions (
  id bigserial PRIMARY KEY,

  userid bigint REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE,
  clientid text NOT NULL DEFAULT '', -- includes app ID if any
  sessionid text,

  full_userid text NOT NULL,
  
 -- More fields -- capabilities
   csp_version varchar(16) NOT NULL DEFAULT '1.2',
   pull_len int NOT NULL DEFAULT 100000,
   push_len int NOT NULL DEFAULT 100000,
   text_len int NOT NULL DEFAULT 100000,
   
   anycontent boolean NOT NULL DEFAULT FALSE,
   client_type text NOT NULL DEFAULT '',
   lang text NOT NULL DEFAULT 'en',
   deliver_method varchar(1) NOT NULL DEFAULT 'P',
   multi_trans int NOT NULL DEFAULT 1,
   offline_ete_m_handling varchar(32) NOT NULL DEFAULT 'SENDSTORE',
   online_ete_m_handling varchar(32) NOT NULL DEFAULT 'SERVERLOGIC',
   
   parse_size int NOT NULL DEFAULT 10000,
   server_poll_min int NOT NULL DEFAULT 60,
   priority int NOT NULL DEFAULT 10, -- session priority
   ip  text NOT NULL DEFAULT '', -- client  IP address as gleaned from headers.
   msisdn text, -- the session msisdn (null if not known)
   request_ip text, -- request IP
   default_notify boolean NOT NULL DEFAULT FALSE, -- whether default notification was negotiated
   caps boolean NOT NULL DEFAULT FALSE, -- whether capabilities were negotiated
   cir_mask int NOT NULL DEFAULT 0,
   cdate timestamp NOT NULL DEFAULT current_timestamp,
   lastt timestamp NOT NULL DEFAULT current_timestamp,
   ttl  int NOT NULL DEFAULT 30*60, -- default TTL in seconds. 
   cookie text NOT NULL DEFAULT '',
   presence bytea, -- presence element
   last_pres_update timestamp NOT NULL DEFAULT current_timestamp,
   cir boolean NOT NULL DEFAULT FALSE, -- Whether session has CIR.
   sudp_port int NOT NULL DEFAULT 56732,
   UNIQUE(sessionid)
);
 
-- trigger to update fulluserid

CREATE OR REPLACE FUNCTION sess_before_update() RETURNS trigger AS $$
       BEGIN
	  NEW.full_userid := '';

	  SELECT full_userid INTO NEW.full_userid FROM users_view uv WHERE uv.id = NEW.userid;

	  RETURN NEW;
       END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER sess_before_update BEFORE UPDATE OR INSERT ON sessions 
       FOR EACH ROW EXECUTE PROCEDURE sess_before_update();

CREATE OR REPLACE FUNCTION sess_before_insert() RETURNS trigger AS $$
       BEGIN
	 NEW.sessionid := '';

	 SELECT upper(md5(current_timestamp::text)) || NEW.id::text || 'G' INTO NEW.sessionid;
	 RETURN NEW;
       END;       
$$ LANGUAGE plpgsql;

CREATE TRIGGER sess_before_insert BEFORE INSERT ON sessions 
       FOR EACH ROW EXECUTE PROCEDURE sess_before_insert();


-- groups table
CREATE TABLE groups (
  id bigserial PRIMARY KEY,

  groupid text NOT NULL, -- excludes domain part.

  domain text NOT NULL DEFAULT '',

  creator bigint REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE, -- NULL if system group
   
   cdate timestamp NOT NULL DEFAULT current_timestamp, -- date of creation

   welcome_note bytea,
   welcome_note_ctype text NOT NULL DEFAULT 'text/plain',	
  -- more fields to come
  
  
 UNIQUE(groupid, domain)
);

CREATE TABLE group_properties (
	id bigserial PRIMARY KEY,
	groupid bigint NOT NULL REFERENCES groups ON DELETE CASCADE ON UPDATE CASCADE,
        
	item text NOT NULL,
	value text NOT NULL,

	UNIQUE(groupid,item)
);

CREATE VIEW groups_view AS 
SELECT 'wv:'|| (case when domain = '' then groupid else groupid || '@' || domain end) as group_id, 
*,
  (SELECT value FROM group_properties gp WHERE gp.groupid = g.id AND  item='Name') as group_name, 
  (SELECT value FROM group_properties gp WHERE gp.groupid = g.id AND  item='Topic') as topic
 from groups g;

-- List of members, joined,  autojoin users. 
CREATE TABLE group_members (
   id bigserial PRIMARY KEY,

  groupid bigint NOT NULL REFERENCES groups ON UPDATE CASCADE ON DELETE CASCADE,

  -- info (either one of userid or foreign_userid is set)
  local_userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,
  foreign_userid text CHECK (foreign_userid IS NOT NULL OR local_userid IS NOT NULL),
 
   member_type varchar(6) NOT NULL DEFAULT 'User' CHECK (member_type IN ('User', 'Mod', 'Admin')),

  screen_name text, -- screen name of user in list.
  clientid text,
  
  isjoined boolean NOT NULL DEFAULT false,  -- true if user is currently joined (see auto-join above)
  ismember boolean NOT NULL DEFAULT false, -- true if a member
  subscribe_notify boolean NOT NULL DEFAULT false, -- if user subscribes to notification

  sessionid bigint REFERENCES sessions ON UPDATE CASCADE ON DELETE SET NULL,
   -- more fields to come
   
  UNIQUE(groupid, local_userid,clientid),
  UNIQUE(groupid,foreign_userid,clientid),
  UNIQUE(groupid,screen_name)
);

CREATE SEQUENCE screen_name_sequence; -- for screen names

CREATE TABLE group_member_properties (
	id bigserial PRIMARY KEY,
	jid bigint NOT NULL REFERENCES group_members ON DELETE CASCADE ON UPDATE CASCADE,
        
	item text NOT NULL,
	value text NOT NULL,

	UNIQUE(jid,item)
);

CREATE TABLE group_reject_list (
	id bigserial PRIMARY KEY,

	groupid bigint NOT NULL REFERENCES groups ON UPDATE CASCADE ON DELETE CASCADE,

  -- member info (either one of userid or foreign_userid is set)
       local_userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,
       foreign_userid text CHECK (foreign_userid IS NOT NULL OR local_userid IS NOT NULL),
	
    UNIQUE(groupid, local_userid),
    UNIQUE(groupid,foreign_userid)
     	
);


CREATE VIEW group_members_view AS 
	SELECT g.*, gm.local_userid,gm.foreign_userid, 
	(CASE WHEN local_userid IS NOT NULL THEN (select full_userid FROM users_view WHERE gm.local_userid = users_view.id) ELSE foreign_userid END) AS full_userid , 
	gm.member_type, gm.screen_name,gm.clientid, gm.ismember, gm.id AS gmid,
	(SELECT value FROM group_member_properties WHERE jid = gm.id AND item='AutoJoin') as auto_join, 
	gm.groupid AS group_id,gm.isjoined,gm.subscribe_notify FROM
   	groups g, group_members gm WHERE g.id = gm.groupid;

CREATE VIEW group_reject_list_view AS 
  SELECT g.*, (CASE WHEN local_userid IS NOT NULL THEN 
	(select full_userid FROM users_view WHERE gm.local_userid = users_view.id) ELSE foreign_userid END) AS full_userid, gm.groupid AS group_id, gm.id AS rid 
	FROM group_reject_list gm, groups g WHERE gm.groupid = g.id; 


CREATE TABLE group_session_limits (
  id bigserial PRIMARY KEY,
  
  sessid bigint REFERENCES sessions ON DELETE CASCADE ON UPDATE CASCADE,

  groupid TEXT NOT NULL,
  push_len int NOT NULL DEFAULT 100000,
  pull_len int NOT NULL DEFAULT 100000,
  deliver_method varchar(1) NOT NULL DEFAULT 'P',
  UNIQUE(sessid,groupid)
);
  	
CREATE VIEW session_users AS 
	SELECT sessions.*,nickname FROM sessions,users_view WHERE sessions.userid = users_view.id;

CREATE TABLE session_content_types (
  id bigserial PRIMARY KEY,
  
  sessionid bigint REFERENCES sessions ON DELETE CASCADE ON UPDATE CASCADE,

  ctype text NOT NULL,
  max_len int NOT NULL DEFAULT 100000,
  cpolicy varchar(1) NOT NULL DEFAULT 'N',
  cpolicy_limit int NOT NULL DEFAULT 100000  
);

CREATE TABLE session_charsets (
  id bigserial PRIMARY KEY,
  
  sessionid bigint REFERENCES sessions ON DELETE CASCADE ON UPDATE CASCADE,

  charset int NOT NULL

);

-- list of presence subscribers for a user
CREATE TABLE presence_watchlists (
 id bigserial PRIMARY KEY,

 sessid bigint REFERENCES sessions ON DELETE CASCADE ON UPDATE CASCADE, -- link to the watcher session

 userid bigint NOT NULL REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE, -- link to watched user
 

 foreign_userid text CHECK (foreign_userid IS NOT NULL OR sessid IS NOT NULL), -- set it if this is foreign watcher. 
 foreign_clientid text ,
 
 attribs_requested int NOT NULL DEFAULT 0, -- attributes requested

 UNIQUE(userid,sessid),
 UNIQUE(userid,foreign_userid,foreign_clientid)
);

CREATE VIEW pr_watchlist_user_view AS 
 SELECT presence_watchlists.*, full_userid as local_userid,nickname
  FROM presence_watchlists LEFT JOIN session_users ON
  presence_watchlists.sessid = session_users.id;


CREATE VIEW pr_watchlist_userid_view AS 
       SELECT p.*, s.userid AS local_userid, s.clientid FROM presence_watchlists p LEFT JOIN sessions s ON
       p.sessid = s.id;

-- table of users who have been authorised to see our presence. 
CREATE TABLE presence_user_authorisations (
   id bigserial PRIMARY KEY,

   userid bigint NOT NULL REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE, -- link to user who has authorised
 
   -- authorised user info (either one of userid or foreign_userid is set)
  local_userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,
  foreign_userid text CHECK (foreign_userid IS NOT NULL OR local_userid IS NOT NULL),

  attribs_authorised int NOT NULL DEFAULT 0, -- attributes authorised (bit field). Ensure it is zero when status is not GRANTED!

  user_notify boolean NOT NULL DEFAULT false, -- set to true until GRANTED or DENIED.
  react boolean NOT NULL DEFAULT false,
  status varchar(8) NOT NULL DEFAULT 'GRANTED' CHECK (status IN ('GRANTED', 'DENIED', 'PENDING')),
  UNIQUE(userid, local_userid),
  UNIQUE(userid, foreign_userid)
); 

CREATE VIEW pr_users_view  AS  
	SELECT presence_user_authorisations.*, (CASE WHEN local_userid IS NOT NULL THEN 
	(SELECT full_userid FROM users_view WHERE id = local_userid) ELSE NULL END) AS localuserid 
	FROM presence_user_authorisations;
	
CREATE TABLE searches (
   id bigserial PRIMARY KEY,

   session bigint NOT NULL REFERENCES  sessions ON DELETE CASCADE ON UPDATE CASCADE,
   stype varchar(1) NOT NULL CHECK (stype IN ('G','U')), -- type of search -- Group or Users
   slimit int NOT NULL DEFAULT 5, -- limit on number of results to return each time.
   start_results_id bigint, -- an optimisation: start index of results in table below.
   result_count int NOT NULL DEFAULT 0
);

CREATE TABLE search_results (
   id bigserial PRIMARY KEY,
   
   sid bigint REFERENCES searches ON DELETE CASCADE ON UPDATE CASCADE,

   v1 text,
   V2 text
);

CREATE SEQUENCE message_sequence;
-- tables for queue management

-- locally destined messages: 
CREATE TABLE csp_message_queue (
  id bigserial PRIMARY KEY,
 
  tdate timestamp NOT NULL DEFAULT current_timestamp, -- date of entry
 
  edate timestamp NOT NULL DEFAULT (current_timestamp + interval '1 week'), -- expiry date

  msgid text, -- the textual message id  -- can be null
  sender text NOT NULL, -- sender of IM (formatted in readable manner)

  msg_type text NOT NULL, -- taken from packet itself. 

  msg_data bytea NOT NULL,   -- message data.

   delivery_report boolean NOT NULL DEFAULT FALSE,
   internal_rcpt_struct_path text, -- path to the Recepient struct within struct
   csp_ver int NOT NULL DEFAULT 17,
  UNIQUE(msgid) -- message id must be unique
);

CREATE TABLE csp_message_recipients (
   id bigserial PRIMARY KEY, -- also used for generating transact ID when delivering message locally

   messageid bigint NOT NULL REFERENCES csp_message_queue ON UPDATE CASCADE ON DELETE CASCADE,
  
   userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,

   clientid text, -- if sent to specific client (and application)
   screen_name text, -- if the user was addressed using a screen name, this is it (s:sname,g:groupname)

    gsender text, -- sender of IM (formatted in readable manner) if a group
   msg_status varchar(1)  NOT NULL DEFAULT 'N', -- 'N' == new, 'R' == rejected, 'F' == fetched
   num_fetches int NOT NULL DEFAULT 0, -- number of times fetched.
   next_fetch timestamp NOT NULL DEFAULT '-infinity'
);

CREATE VIEW csp_message_recipients_view AS 
  SELECT q.*, r.id as rid, r.userid, r.screen_name, r.clientid, r.msg_status, r.num_fetches, r.next_fetch,
	(SELECT full_userid FROM users_view WHERE id = r.userid) AS full_userid FROM 
  csp_message_queue q, csp_message_recipients r WHERE r.messageid = q.id;

-- externally destined messages
CREATE TABLE ssp_message_queue (
   id bigserial PRIMARY KEY, -- will also be used for transaction ID on outgoing SSP transactions, unless incoming_transid is set.

  tdate timestamp NOT NULL DEFAULT current_timestamp, -- date of entry
 
  edate timestamp NOT NULL DEFAULT (current_timestamp + interval '24 hours'), -- expiry date
  
   -- message ID must not be unique and can be NULL
  msgid text, -- the textual message id  

  sender text NOT NULL, -- sender of IM (formatted in readable manner)

  domain text NOT NULL, -- domain to which to send message
  msg_type text NOT NULL, -- taken from packet itself. 

  msg_data bytea NOT NULL,   -- message data. (recipients are within struct, presumably!)

  lastt timestamp NOT NULL default '-infinity', -- last send attempt,
  nextt timestamp NOT NULL default current_timestamp, -- when is next send attempt

  num_tries int NOT NULL DEFAULT 0, -- number of attempts to send.
 
  sent boolean NOT NULL DEFAULT false, -- this is true if message was sent successfully (and we're waiting for response)
 -- info about the real sender.
  userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,
  clientid text,
  csp_ver int NOT NULL DEFAULT 17 -- Default version set to 1.1
);

-- to be used when recipients are not within the structure above
CREATE TABLE ssp_message_recipients (
	id bigserial PRIMARY KEY,
  	messageid BIGINT NOT NULL REFERENCES ssp_message_queue ON DELETE CASCADE ON UPDATE CASCADE,

	foreign_userid text NOT NULL,

	clientid text,

	gsender text -- sender of IM (formatted in readable manner) if a group
);

-- ssp sessions 
CREATE TABLE ssp_sessions (
       id bigserial PRIMARY KEY,
       ssp_domain text NOT NULL, -- the domain we're speaking for
       ssp_domain_url text,  -- the actual URL of ghandler in the domain (relay, etc)
       outgoing boolean NOT NULL DEFAULT false, -- is this an incoming or outgoing connection?
       a_secret text , -- our secret (if any, base64 coded)
       b_secret text, -- their secret
       sdate timestamp NOT NULL DEFAULT current_timestamp, -- time of first contact
       ldate timestamp NOT NULL DEFAULT '-infinity', -- when last active (only set once logon is complete.)
       edate timestamp NOT NULL DEFAULT (current_timestamp + interval '24 hours'), -- expiry date
       -- The session ID pair.
       a_sessionid text, -- requestor side session ID (NULL until we have setup the connection)
       b_sessionid text, -- response side's session ID (NULL until we have setup the connection)
       b_transid text,
       pw_check_ok boolean  NOT NULL DEFAULT false,
       mydomain text NOT NULL,
       UNIQUE(ssp_domain, a_sessionid)
);

-- table for archive messages 
CREATE TABLE message_archive (
  id bigserial PRIMARY KEY,

  userid text NOT NULL, -- the user to whom/from whom message sent/received

  msg_direction varchar(5)  NOT NULL CHECK (msg_direction IN ('RECVD', 'SENT')),
 
  msg_type varchar(32) NOT NULL, -- type of message
  tdate timestamp NOT NULL DEFAULT current_timestamp,
  msg_data bytea NOT NULL
 
 );


-- table listing all local domains (i.e. ones for which we handle IM)

CREATE TABLE localdomains (
  id bigserial PRIMARY KEY,

  cdate timestamp NOT NULL DEFAULT current_timestamp,
 
  domain text NOT NULL,
 
 -- comma-separated list of message types to archive from/to this domain
  archive_sent text NOT NULL DEFAULT '',
  archive_recvd text NOT NULL DEFAULT '',

  UNIQUE(domain)
);

-- table listing the settings for the domain
CREATE TABLE settings (
  id serial,
  
  item varchar(32),
  value text,
 
  UNIQUE(item)
);

CREATE TABLE contactlists (
  id bigserial PRIMARY KEY,

  cid text NOT NULL, -- exclused domain part
 
  domain text NOT NULL,

  userid bigint REFERENCES users ON DELETE CASCADE ON UPDATE CASCADE, -- NULL if system list

  isdefault boolean NOT NULL DEFAULT false,

  descr text NOT NULL DEFAULT '',

  friendly_name text NOT NULL DEFAULT '',

  presence_attribs_authorised int, -- authorised presence attributes (if any)

  contact_list_notify boolean NOT NULL DEFAULT false,
  presence_attribs_auto_subscribe int, -- auto-subscribed presence attributes
 UNIQUE(userid,cid,domain)
);

CREATE VIEW contactlists_VIEW AS 
	SELECT *, 'wv:'||(case when domain = '' then cid else cid || '@' || domain end) AS contactlistid FROM contactlists;

CREATE TABLE contactlist_members (
 id bigserial PRIMARY KEY,

 cid bigint NOT NULL REFERENCES contactlists ON UPDATE CASCADE ON DELETE CASCADE,

  -- member info (either one of userid or foreign_userid is set)
  local_userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,
  foreign_userid text CHECK (foreign_userid IS NOT NULL OR local_userid IS NOT NULL),
 

  cname text NOT NULL, -- name of user in list.
   -- more fields to come
   
  UNIQUE(cid, local_userid),
  UNIQUE(cid,foreign_userid)
);

create view contactlist_members_view AS 
	SELECT *,(select 'wv:'||userid||'@'||domain FROM users WHERE users.id = local_userid LIMIT 1) as localuserid FROM contactlist_members;

-- access lists: GRANT/BLOCK

CREATE TABLE access_lists (
	id bigserial NOT NULL PRIMARY KEY,
	
-- owner of the access list
	owner bigint NOT NULL REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,

--  allow = true means on GRANT list, else on BLOCK list
 	allow boolean NOT NULL DEFAULT FALSE,

-- references to the users, screen names or groups that are granted or blocked
	local_userid bigint REFERENCES users ON UPDATE CASCADE ON DELETE CASCADE,
	foreign_userid text,

	screen_name text,
	
	group_id text,
	application_id text
);

CREATE VIEW access_lists_view AS 
  SELECT *, (CASE WHEN local_userid IS NOT NULL THEN 
	(select full_userid FROM users_view WHERE local_userid = id) ELSE foreign_userid END) AS full_userid 
	FROM access_lists; 

-- shared content table
CREATE TABLE shared_content (
   id bigserial PRIMARY KEY,
   
   cdate timestamp NOT NULL DEFAULT current_timestamp,
   edate timestamp NOT NULL DEFAULT (current_timestamp + interval '7 days'), -- expiry date
   content_type text NOT NULL,   
   content bytea NOT NULL,
   content_encoding text,
   content_key text, -- some key for identifying content
   content_keyword text -- a keyword, for more permanent content
); 
-- create a user entry
CREATE  OR REPLACE FUNCTION new_user_md5(u text, d text, xnonce text, xpass text, areg boolean) RETURNS bigint AS $$
	DECLARE
		uid bigint;
		x text;
		cp text;
		y text;
	BEGIN
	SELECT (random()::text || current_timestamp::text) INTO y;
	SELECT md5(xpass||y) INTO cp;
	uid := -1;
	INSERT into users (userid,domain,nonce,crypt_md5_pass, rand_salt,auto_reg) VALUES 
	(u,d, xnonce, cp, y, areg) RETURNING id INTO uid; 

	RETURN uid;
 	END;
$$ LANGUAGE plpgsql;

-- create new user with nonce -- simply calls the other one.
CREATE  OR REPLACE FUNCTION new_user_with_nonce(u text, p text, d text, xnonce text, areg boolean) RETURNS bigint AS $$
	DECLARE
		x text;
	BEGIN
	x := xnonce || p;
	SELECT md5(x) INTO x;

	RETURN new_user_md5(u,d,xnonce,x,areg);
 	END;
$$ LANGUAGE plpgsql;


CREATE  OR REPLACE FUNCTION new_user(u text, p text, d text, areg boolean) RETURNS bigint AS $$
	DECLARE
		xnonce text;
	BEGIN
	-- Make the nonce
	SELECT md5(current_timestamp::text) INTO xnonce;

	RETURN new_user_with_nonce(u, p, d, xnonce, areg);
 	END;
$$ LANGUAGE plpgsql;

-- verify a password
CREATE OR REPLACE FUNCTION verify_plain_pass(u text, d text, p text) RETURNS boolean AS $$
	DECLARE
	  t boolean;
	BEGIN
		SELECT crypt_md5_pass = md5(md5(nonce||p)|| rand_salt) INTO t FROM users WHERE userid = u AND domain = d AND bot_url IS NULL; -- must NOT be a Bot
		IF NOT FOUND THEN
		  RETURN false;
		END IF;
		RETURN t;	
	END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_plain_pass(uid bigint, pass text) RETURNS boolean AS $$
       DECLARE 
         t boolean;
	 r text;
        xnonce text;
       BEGIN
           SELECT (random()::text || current_timestamp::text) INTO r; -- rand salt
	   SELECT md5(current_timestamp::text) INTO xnonce; -- nonce

	   UPDATE users SET rand_salt = r,nonce=xnonce,crypt_md5_pass = md5(md5(xnonce||pass)||r) WHERE id = uid;
	   RETURN TRUE;
       END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION verify_md5_pass(u text, d text, p text) RETURNS boolean AS $$
	DECLARE
	  t boolean;
	BEGIN
		SELECT crypt_md5_pass = md5(p|| rand_salt) INTO t FROM users WHERE userid = u AND domain = d AND bot_url IS NULL;
		IF NOT FOUND THEN
		  RETURN false;
		END IF;
		RETURN t;	
	END;
$$ LANGUAGE plpgsql;

-- type for the functions below to return
CREATE TYPE user_auth_data as (
	  attribs int, 
          auth_type varchar(16),
	  notify boolean,
	  status varchar(8));

CREATE OR REPLACE FUNCTION get_local_user_auth(watched bigint, watcher bigint) RETURNS SETOF user_auth_data AS $$
    DECLARE
	r user_auth_data%rowtype;
	attribs int;
	atype varchar(16);
        notify boolean;
	n int;
    BEGIN

	-- first try the user.
	SELECT attribs_authorised, 'User', user_notify,status INTO r FROM 
	presence_user_authorisations  WHERE userid = watched AND local_userid = watcher;

	IF FOUND THEN
	  RETURN NEXT r;
	  RETURN;
  	END IF;	
	-- then try the contact lists
	
	SELECT bit_or(presence_attribs_authorised), bool_or(contact_list_notify), count(*) 
	INTO attribs, notify, n FROM contactlists WHERE
	userid = watched AND presence_attribs_authorised IS NOT NULL AND 
	EXISTS (SELECT id FROM contactlist_members WHERE 
	cid = contactlists.id AND local_userid = watcher);

	IF FOUND AND n > 0 THEN
		r.attribs := attribs;
		r.notify := notify;
		r.auth_type := 'ContactList';
		r.status := 'GRANTED';
		RETURN NEXT r;
		RETURN;
	END IF;
	-- then try the default.	
	SELECT default_attr_list, 'Default', default_notify,'GRANTED' as status INTO r FROM 
	users  WHERE id = watched AND default_attr_list IS NOT NULL;
	
	IF FOUND THEN	        
		RETURN NEXT r;
		RETURN;
	END IF;	
	-- otherwise return nothing.
	RETURN;
   END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_foreign_user_auth(watched bigint, watcher text) RETURNS SETOF user_auth_data AS $$
    DECLARE
	r user_auth_data%rowtype;
	attribs int;
	atype varchar(16);
        notify boolean;
	n int;
    BEGIN

	-- first try the user.
	SELECT attribs_authorised, 'User', user_notify,status INTO r FROM 
	presence_user_authorisations  WHERE userid = watched AND foreign_userid = watcher;

	IF FOUND THEN
	  RETURN NEXT r;
	  RETURN;
  	END IF;	
	-- then try the contact lists
	
	SELECT bit_or(presence_attribs_authorised), bool_or(contact_list_notify), count(*) 
	INTO attribs, notify, n FROM contactlists WHERE
	userid = watched AND presence_attribs_authorised IS NOT NULL AND 
	EXISTS (SELECT foreign_userid FROM contactlist_members WHERE 
	cid = contactlists.id AND foreign_userid = watcher);

	IF FOUND AND n > 0 THEN
		r.attribs := attribs;
		r.notify := notify;
		r.auth_type := 'ContactList';
		r.status := 'GRANTED';
		RETURN NEXT r;
		RETURN;
	END IF;
	-- then try the default.	
	SELECT default_attr_list, 'Default', default_notify,'GRANTED' as status INTO r FROM 
	users  WHERE id = watched AND default_attr_list IS NOT NULL;
	
	IF FOUND THEN
		RETURN NEXT r;
		RETURN;
	END IF;	
	-- otherwise return nothing.
	RETURN;
   END;
$$ LANGUAGE plpgsql;

