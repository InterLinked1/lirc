/*
 * LIRC - IRC Client Library for C
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the Mozilla Public License Version 2.
 */

/*! \brief Maximum length of an IRC message, including trailing CR LF */
#define IRC_MAX_MSG_LEN 512

/*! \brief Default port for insecure connections */
#define IRC_DEFAULT_PORT 6667

/*! \brief Default port for secure connections */
#define IRC_DEFAULT_TLS_PORT 6697

/*!
 * \brief IRCv3 numerics
 * \note Reference: https://defs.ircdocs.horse/defs/numerics.html
 *       Some irrelevant numerics are not included here.
 */
enum irc_numeric {
	NUMERIC_NONE = 0,
	RPL_WELCOME = 1,	/* The first message sent after client registration. The text used varies widely */
	RPL_YOURHOST = 2,	/* Part of the post-registration greeting. Text varies widely. Also known as RPL_YOURHOSTIS (InspIRCd v2) */
	RPL_CREATED = 3,	/* Part of the post-registration greeting. Text varies widely and <date> is returned in a human-readable format. Also known as RPL_SERVERCREATED (InspIRCd v2) */
	RPL_MYINFO = 4,		/* Part of the post-registration greeting. Also known as RPL_SERVERVERSION (InspIRCd v2) */
	RPL_ISUPPORT = 5,	/* Advertises features, limits, and protocol options that clients should be aware of. Also known as RPL_PROTOCTL (Bahamut, Unreal, Ultimate). Also see RPL_REMOTEISUPPORT (105). */
	RPL_SNOMASK = 8,	/* Server notice mask (hex). Also known as RPL_SNOMASKIS (InspIRCd) */
	RPL_STATMEMTOT = 9,
	RPL_BOUNCE = 10,	/* Sent to the client to redirect it to another server. Also known as RPL_REDIR */
	RPL_STATMEM = 10,
	RPL_YOURCOOKIE = 14,
	RPL_MAP = 15,
	RPL_MAPMORE = 16,
	RPL_MAPEND = 17,	/* Also known as RPL_ENDMAP (InspIRCd) */
	RPL_MAPUSERS = 18,
	RPL_HELLO = 20,		/* Used by Rusnet to send the initial "Please wait while we process your connection" message, rather than a server-sent NOTICE. */
	RPL_APASSWARN_SET = 30,
	RPL_APASSWARN_SECRET = 31,
	RPL_APASSWARN_CLEAR = 32,
	RPL_YOURID = 42,	/* Also known as RPL_YOURUUID (InspIRCd) */
	RPL_SAVENICK = 43,	/* Sent to the client when their nickname was forced to change due to a collision */
	RPL_ATTEMPTINGJUNC = 50,
	RPL_ATTEMPTINGREROUTE = 51,
	RPL_REMOTEISUPPORT = 105,	/* Same format as RPL_ISUPPORT, but returned when the client is requesting information from a remote server instead of the server it is currently connected to. Also see RPL_ISUPPORT (005). */
	RPL_TRACELINK = 200,	/* See RFC */
	RPL_TRACECONNECTING = 201,	/* See RFC */
	RPL_TRACEHANDSHAKE = 202,	/* See RFC */
	RPL_TRACEUNKNOWN = 203,	/* See RFC */
	RPL_TRACEOPERATOR = 204,	/* See RFC */
	RPL_TRACEUSER = 205,	/* See RFC */
	RPL_TRACESERVER = 206,	/* See RFC */
	RPL_TRACESERVICE = 207,	/* See RFC */
	RPL_TRACENEWTYPE = 208,	/* See RFC */
	RPL_TRACECLASS = 209,	/* See RFC */
	RPL_TRACERECONNECT = 210,
	RPL_STATS = 210,	/* Used instead of having multiple stats numerics */
	RPL_STATSHELP = 210,	/* Used to send lists of stats flags and other help information. */
	RPL_STATSLINKINFO = 211,	/* Reply to STATS (See RFC) */
	RPL_STATSCOMMANDS = 212,	/* Reply to STATS (See RFC) */
	RPL_STATSCLINE = 213,	/* Reply to STATS (See RFC) */
	RPL_STATSNLINE = 214,	/* Reply to STATS (See RFC), Also known as RPL_STATSOLDNLINE (ircu, Unreal) */
	RPL_STATSILINE = 215,	/* Reply to STATS (See RFC) */
	RPL_STATSKLINE = 216,	/* Reply to STATS (See RFC) */
	RPL_STATSQLINE = 217,
	RPL_STATSYLINE = 218,	/* Reply to STATS (See RFC) */
	RPL_ENDOFSTATS = 219,	/* End of RPL_STATS* list. */
	RPL_STATSPLINE = 220,
	RPL_UMODEIS = 221,	/* Information about a user's own modes. Some daemons have extended the mode command and certain modes take parameters (like channel modes). */
	RPL_STATSSPAMF = 229,
	RPL_STATSEXCEPTTKL = 230,
	RPL_SERVICEINFO = 231,
	RPL_ENDOFSERVICES = 232,
	RPL_RULES = 232,
	RPL_SERVICE = 233,
	RPL_SERVLIST = 234,	/* A service entry in the service list */
	RPL_SERVLISTEND = 235,	/* Termination of an RPL_SERVLIST list */
	RPL_STATSVERBOSE = 236,	/* Verbose server list? */
	RPL_STATSENGINE = 237,	/* Engine name? */
	RPL_STATSIAUTH = 239,
	RPL_STATSVLINE = 240,
	RPL_STATSXLINE = 240,
	RPL_STATSLLINE = 241,	/* Reply to STATS (See RFC) */
	RPL_STATSUPTIME = 242,	/* Reply to STATS (See RFC) */
	RPL_STATSOLINE = 243,	/* Reply to STATS O (See RFC); The privileges field is an extension in some IRC daemons, which returns either the name of a set of privileges, or a set of privileges. The class extension field returns which connection class the o-line applies to (this is also know to be placeholders like "0" and "-1" when inapplicable.) ircu doesn't have the privileges field and irc2 uses it to display which port, if any, the oper is restricted to. */
	RPL_STATSHLINE = 244,	/* Reply to STATS (See RFC) */
	RPL_STATSSLINE = 245,
	RPL_STATSPING = 246,
	RPL_STATSBLINE = 247,
	RPL_STATSDLINE = 250,
	RPL_LUSERCLIENT = 251,	/* Reply to LUSERS command, other versions exist (eg. RFC2812); Text may vary. */
	RPL_LUSEROP = 252,	/* Reply to LUSERS command - Number of IRC operators online */
	RPL_LUSERUNKNOWN = 253,	/* Reply to LUSERS command - Number of connections in an unknown/unregistered state */
	RPL_LUSERCHANNELS = 254,	/* Reply to LUSERS command - Number of channels formed */
	RPL_LUSERME = 255,	/* Reply to LUSERS command - Information about local connections; Text may vary. */
	RPL_ADMINME = 256,	/* Start of an RPL_ADMIN* reply. In practice, the server parameter is often never given, and instead the last parameter contains the text 'Administrative info about <server>'. Newer daemons seem to follow the RFC and output the server's hostname in the last parameter, but also output the server name in the text as per traditional daemons. */
	RPL_ADMINLOC1 = 257,	/* Reply to ADMIN command (Location, first line) */
	RPL_ADMINLOC2 = 258,	/* Reply to ADMIN command (Location, second line) */
	RPL_ADMINEMAIL = 259,	/* Reply to ADMIN command (E-mail address of administrator) */
	RPL_TRACELOG = 261,	/* See RFC */
	RPL_TRACEPING = 262,	/* Extension to RFC1459? */
	RPL_TRACEEND = 262,	/* Used to terminate a list of RPL_TRACE* replies. Also known as RPL_ENDOFTRACE */
	RPL_TRYAGAIN = 263,	/* When a server drops a command without processing it, it MUST use this reply. The last parameter text changes, and commonly provides the client with more information about why the command could not be processed (such as rate-limiting). Also known as RPL_LOAD_THROTTLED and RPL_LOAD2HI, I'm presuming they do the same thing. */
	RPL_USINGSSL = 264,
	RPL_LOCALUSERS = 265,	/* Returns the number of clients currently and the maximum number of clients that have been connected directly to this server at one time, respectively. The two optional parameters are not always provided. Also known as RPL_CURRENT_LOCAL */
	RPL_GLOBALUSERS = 266,	/* Returns the number of clients currently connected to the network, and the maximum number of clients ever connected to the network at one time, respectively. Also known as RPL_CURRENT_GLOBAL */
	RPL_START_NETSTAT = 267,
	RPL_NETSTAT = 268,
	RPL_END_NETSTAT = 269,
	RPL_PRIVS = 270,
	RPL_SILELIST = 271,
	RPL_ENDOFSILELIST = 272,
	RPL_NOTIFY = 273,
	RPL_ENDNOTIFY = 274,
	RPL_STATSDELTA = 274,
	RPL_WHOISCERTFP = 276,	/* Shows the SSL/TLS certificate fingerprint used by the client with the given nickname. Only sent when users `"WHOIS"` themselves or when an operator sends the `"WHOIS"`. Also adopted by hybrid 8.1 and charybdis 3.2 */
	RPL_STATSRLINE = 276,
	RPL_VCHANEXIST = 276,	/* Gone from hybrid 7.1 (2003) */
	RPL_VCHANLIST = 277,	/* Gone from hybrid 7.1 (2003) */
	RPL_VCHANHELP = 278,	/* Gone from hybrid 7.1 (2003) */
	RPL_GLIST = 280,
	RPL_HELPIGN = 295,
	RPL_CHANINFO_KICKS = 296,
	RPL_END_CHANINFO = 299,
	RPL_NONE = 300,	/* Dummy reply, supposedly only used for debugging/testing new features, however has appeared in production daemons. */
	RPL_AWAY = 301,	/* Used in reply to a command directed at a user who is marked as away */
	RPL_USERHOST = 302,	/* Reply used by USERHOST (see RFC) */
	RPL_ISON = 303,	/* Reply to the ISON command (see RFC) */
	RPL_TEXT = 304,	/* Displays text to the user. This seems to have been defined in irc2.7h but never used. Servers generally use specific numerics or server notices instead of this. Unreal uses this numeric, but most others don't use it */
	RPL_UNAWAY = 305,	/* Reply from AWAY when no longer marked as away */
	RPL_NOWAWAY = 306,	/* Reply from AWAY when marked away */
	RPL_WHOISUSER = 311,	/* Reply to WHOIS - Information about the user */
	RPL_WHOISSERVER = 312,	/* Reply to WHOIS - What server they're on */
	RPL_WHOISOPERATOR = 313,	/* Reply to WHOIS - User has IRC Operator privileges */
	RPL_WHOWASUSER = 314,	/* Reply to WHOWAS - Information about the user */
	RPL_ENDOFWHO = 315,	/* Used to terminate a list of RPL_WHOREPLY replies */
	RPL_WHOISPRIVDEAF = 316,
	RPL_WHOISCHANOP = 316,	/* This numeric was reserved, but never actually used. The source code notes "redundant and not needed but reserved" */
	RPL_WHOISIDLE = 317,	/* Reply to WHOIS - Idle information */
	RPL_ENDOFWHOIS = 318,	/* Reply to WHOIS - End of list */
	RPL_WHOISCHANNELS = 319,	/* Reply to WHOIS - Channel list for user (See RFC) */
	RPL_WHOISVIRT = 320,
	RPL_WHOIS_HIDDEN = 320,
	RPL_WHOISSPECIAL = 320,
	RPL_LISTSTART = 321,	/* Channel list - Header */
	RPL_LIST = 322,	/* Channel list - A channel */
	RPL_LISTEND = 323,	/* Channel list - End of list */
	RPL_CHANNELMODEIS = 324,
	RPL_UNIQOPIS = 325,
	RPL_CHANNELPASSIS = 325,
	RPL_WHOISWEBIRC = 325,
	RPL_CHANNELMLOCKIS = 325,	/* Defined in header file in charybdis, but never used. Also known as RPL_CHANNELMLOCK. */
	RPL_NOCHANPASS = 326,
	RPL_CHPASSUNKNOWN = 327,
	RPL_WHOISHOST = 327,
	RPL_CHANNEL_URL = 328,	/* Also known as RPL_CHANNELURL in charybdis */
	RPL_CREATIONTIME = 329,	/* Also known as RPL_CHANNELCREATED (InspIRCd) */
	RPL_WHOWAS_TIME = 330,
	RPL_WHOISACCOUNT = 330,	/* Also known as RPL_WHOISLOGGEDIN (ratbox?, charybdis) */
	RPL_NOTOPIC = 331,	/* Response to TOPIC when no topic is set. Also known as RPL_NOTOPICSET (InspIRCd) */
	RPL_TOPIC = 332,	/* Response to TOPIC with the set topic. Also known as RPL_TOPICSET (InspIRCd) */
	RPL_TOPICWHOTIME = 333,	/* Also known as RPL_TOPICTIME (InspIRCd). */
	RPL_LISTUSAGE = 334,
	RPL_USERIP = 340,
	RPL_INVITING = 341,	/* Returned by the server to indicate that the attempted INVITE message was successful and is being passed onto the end client. Note that RFC1459 documents the parameters in the reverse order. The format given here is the format used on production servers, and should be considered the standard reply above that given by RFC1459. */
	RPL_SUMMONING = 342,	/* Returned by a server answering a SUMMON message to indicate that it is summoning that user */
	RPL_WHOISKILL = 343,
	RPL_WHOISCOUNTRY = 344,	/* Used by the third-party m_geoipban InspIRCd module. */
	RPL_INVITELIST = 346,	/* An invite mask for the invite mask list. Also known as RPL_INVEXLIST in hybrid 8.2.0 */
	RPL_ENDOFINVITELIST = 347,	/* Termination of an RPL_INVITELIST list. Also known as RPL_ENDOFINVEXLIST in hybrid 8.2.0 */
	RPL_EXCEPTLIST = 348,	/* An exception mask for the exception mask list. Also known as RPL_EXLIST (Unreal, Ultimate). Bahamut calls this RPL_EXEMPTLIST and adds the last two optional params, <who> being either the nickmask of the client that set the exception or the server name, and <set-ts> being a unix timestamp representing when it was set. */
	RPL_ENDOFEXCEPTLIST = 349,	/* Termination of an RPL_EXCEPTLIST list. Also known as RPL_ENDOFEXLIST (Unreal, Ultimate) or RPL_ENDOFEXEMPTLIST (Bahamut). */
	RPL_WHOISGATEWAY = 350,	/* Used by InspIRCd's m_cgiirc module. */
	RPL_VERSION = 351,	/* Reply by the server showing its version details, however this format is not often adhered to */
	RPL_WHOREPLY = 352,	/* Reply to vanilla WHO (See RFC). This format can be very different if the 'WHOX' version of the command is used (see ircu). */
	RPL_NAMREPLY = 353,	/* Reply to NAMES (See RFC) */
	RPL_WHOSPCRPL = 354,	/* Reply to WHO, however it is a 'special' reply because it is returned using a non-standard (non-RFC1459) format. The format is dictated by the command given by the user, and can vary widely. When this is used, the WHO command was invoked in its 'extended' form, as announced by the 'WHOX' ISUPPORT tag. Also known as RPL_RWHOREPLY (Bahamut). */
	RPL_NAMREPLY_ = 355,	/* Reply to the \users (when the channel is set +D, QuakeNet relative). The proper define name for this numeric is unknown at this time. Also known as RPL_DELNAMREPLY (ircu). Also see RPL_NAMREPLY (353). */
	RPL_WHOWASREAL = 360,	/* Defined in header file, but never used. Initially introduced in charybdis 2.1 behind `"#if 0"`, with the other side using RPL_WHOISACTUALLY */
	RPL_KILLDONE = 361,
	RPL_CLOSING = 362,
	RPL_CLOSEEND = 363,
	RPL_LINKS = 364,	/* Reply to the LINKS command */
	RPL_ENDOFLINKS = 365,	/* Termination of an RPL_LINKS list */
	RPL_ENDOFNAMES = 366,	/* Termination of an RPL_NAMREPLY list */
	RPL_BANLIST = 367,	/* A ban-list item (See RFC); <setter>, <time left> and <reason> are additions used by various servers. */
	RPL_ENDOFBANLIST = 368,	/* Termination of an RPL_BANLIST list */
	RPL_ENDOFWHOWAS = 369,	/* Reply to WHOWAS - End of list */
	RPL_INFO = 371,	/* Reply to INFO */
	RPL_MOTD = 372,	/* Reply to MOTD */
	RPL_INFOSTART = 373,
	RPL_ENDOFINFO = 374,	/* Termination of an RPL_INFO list */
	RPL_MOTDSTART = 375,	/* Start of an RPL_MOTD list */
	RPL_ENDOFMOTD = 376,	/* Termination of an RPL_MOTD list */
	RPL_KICKEXPIRED = 377,
	RPL_SPAM = 377,	/* Used during the connection (after MOTD) to announce the network policy on spam and privacy. Supposedly now obsoleted in favor of using NOTICE. */
	RPL_YOUREOPER = 381,	/* Successful reply from OPER. Also known as RPL_YOUAREOPER (InspIRCd) */
	RPL_REHASHING = 382,	/* Successful reply from REHASH */
	RPL_YOURESERVICE = 383,	/* Sent upon successful registration of a service */
	RPL_MYPORTIS = 384,
	RPL_NOTOPERANYMORE = 385,
	RPL_ENDOFALIST = 389,
	RPL_TIME = 391,	/* Response to the TIME command. The string format may vary greatly. */
	RPL_USERSSTART = 392,	/* Start of an RPL_USERS list */
	RPL_USERS = 393,	/* Response to the USERS command (See RFC) */
	RPL_ENDOFUSERS = 394,	/* Termination of an RPL_USERS list */
	RPL_NOUSERS = 395,	/* Reply to USERS when nobody is logged in */
	RPL_VISIBLEHOST = 396,	/* Also known as RPL_YOURDISPLAYEDHOST (InspIRCd) or RPL_HOSTHIDDEN (ircu, charybdis, Quakenet, Unreal). <hostname> can also be in the form <user@hostname> (Quakenet). */
	RPL_CLONES = 399,
	ERR_UNKNOWNERROR = 400,	/* Sent when an error occurred executing a command, but it is not specifically known why the command could not be executed. */
	ERR_NOSUCHNICK = 401,	/* Used to indicate the nickname parameter supplied to a command is currently unused */
	ERR_NOSUCHSERVER = 402,	/* Used to indicate the server name given currently doesn't exist */
	ERR_NOSUCHCHANNEL = 403,	/* Used to indicate the given channel name is invalid, or does not exist */
	ERR_CANNOTSENDTOCHAN = 404,	/* Sent to a user who does not have the rights to send a message to a channel */
	ERR_TOOMANYCHANNELS = 405,	/* Sent to a user when they have joined the maximum number of allowed channels and they tried to join another channel */
	ERR_WASNOSUCHNICK = 406,	/* Returned by WHOWAS to indicate there was no history information for a given nickname */
	ERR_TOOMANYTARGETS = 407,	/* The given target(s) for a command are ambiguous in that they relate to too many targets */
	ERR_NOSUCHSERVICE = 408,	/* Returned to a client which is attempting to send an SQUERY (or other message) to a service which does not exist */
	ERR_NOORIGIN = 409,	/* PING or PONG message missing the originator parameter which is required since these commands must work without valid prefixes */
	ERR_INVALIDCAPCMD = 410,	/* Returned when a client sends a CAP subcommand which is invalid or otherwise issues an invalid CAP command. Also known as ERR_INVALIDCAPSUBCOMMAND (InspIRCd) or ERR_UNKNOWNCAPCMD (ircu) */
	ERR_NORECIPIENT = 411,	/* Returned when no recipient is given with a command */
	ERR_NOTEXTTOSEND = 412,	/* Returned when NOTICE/PRIVMSG is used with no message given */
	ERR_NOTOPLEVEL = 413,	/* Used when a message is being sent to a mask without being limited to a top-level domain (i.e. * instead of *.au) */
	ERR_WILDTOPLEVEL = 414,	/* Used when a message is being sent to a mask with a wild-card for a top level domain (i.e. *.*) */
	ERR_BADMASK = 415,	/* Used when a message is being sent to a mask with an invalid syntax */
	ERR_TOOMANYMATCHES = 416,	/* Returned when too many matches have been found for a command and the output has been truncated. An example would be the WHO command, where by the mask '*' would match everyone on the network! Ouch! */
	ERR_QUERYTOOLONG = 416,	/* Same as ERR_TOOMANYMATCHES */
	ERR_INPUTTOOLONG = 417,	/* Returned when an input line is longer than the server can process (512 bytes), to let the client know this line was dropped (rather than being truncated) */
	ERR_LENGTHTRUNCATED = 419,
	ERR_AMBIGUOUSCOMMAND = 420,	/* Used by InspIRCd's m_abbreviation module */
	ERR_UNKNOWNCOMMAND = 421,	/* Returned when the given command is unknown to the server (or hidden because of lack of access rights) */
	ERR_NOMOTD = 422,	/* Sent when there is no MOTD to send the client */
	ERR_NOADMININFO = 423,	/* Returned by a server in response to an ADMIN request when no information is available. RFC1459 mentions this in the list of numerics. While it's not listed as a valid reply in section 4.3.7 ('Admin command'), it's confirmed to exist in the real world. */
	ERR_FILEERROR = 424,	/* Generic error message used to report a failed file operation during the processing of a command */
	ERR_NOOPERMOTD = 425,
	ERR_TOOMANYAWAY = 429,
	ERR_EVENTNICKCHANGE = 430,	/* Returned by NICK when the user is not allowed to change their nickname due to a channel event (channel mode +E) */
	ERR_NONICKNAMEGIVEN = 431,	/* Returned when a nickname parameter expected for a command isn't found */
	ERR_ERRONEUSNICKNAME = 432,	/* Returned after receiving a NICK message which contains a nickname which is considered invalid, such as it's reserved ('anonymous') or contains characters considered invalid for nicknames. This numeric is misspelt, but remains with this name for historical reasons :) */
	ERR_NICKNAMEINUSE = 433,	/* Returned by the NICK command when the given nickname is already in use */
	ERR_NICKCOLLISION = 436,	/* Returned by a server to a client when it detects a nickname collision */
	ERR_UNAVAILRESOURCE = 437,	/* Return when the target is unable to be reached temporarily, eg. a delay mechanism in play, or a service being offline */
	ERR_TARGETTOOFAST = 439,	/* Also known as many other things, RPL_INVTOOFAST, RPL_MSGTOOFAST, ERR_TARGETTOFAST (Bahamut), etc */
	ERR_SERVICESDOWN = 440,
	ERR_USERNOTINCHANNEL = 441,	/* Returned by the server to indicate that the target user of the command is not on the given channel */
	ERR_NOTONCHANNEL = 442,	/* Returned by the server whenever a client tries to perform a channel effecting command for which the client is not a member */
	ERR_USERONCHANNEL = 443,	/* Returned when a client tries to invite a user to a channel they're already on */
	ERR_NOLOGIN = 444,	/* Returned by the SUMMON command if a given user was not logged in and could not be summoned */
	ERR_SUMMONDISABLED = 445,	/* Returned by SUMMON when it has been disabled or not implemented */
	ERR_USERSDISABLED = 446,	/* Returned by USERS when it has been disabled or not implemented */
	ERR_NONICKCHANGE = 447,	/* This numeric is called ERR_CANTCHANGENICK in InspIRCd */
	ERR_FORBIDDENCHANNEL = 448,	/* Returned when this channel name has been explicitly blocked and is not allowed to be used. */
	ERR_NOTIMPLEMENTED = 449,	/* Returned when a requested feature is not implemented (and cannot be completed) */
	ERR_NOTREGISTERED = 451,	/* Returned by the server to indicate that the client must be registered before the server will allow it to be parsed in detail */
	ERR_IDCOLLISION = 452,
	ERR_NICKLOST = 453,
	ERR_HOSTILENAME = 455,
	ERR_ACCEPTFULL = 456,
	ERR_ACCEPTEXIST = 457,
	ERR_ACCEPTNOT = 458,
	ERR_NOHIDING = 459,	/* Not allowed to become an invisible operator? */
	ERR_NOTFORHALFOPS = 460,
	ERR_NEEDMOREPARAMS = 461,	/* Returned by the server by any command which requires more parameters than the number of parameters given */
	ERR_ALREADYREGISTERED = 462,	/* Returned by the server to any link which attempts to register again Also known as ERR_ALREADYREGISTRED (sic) in ratbox/charybdis. */
	ERR_NOPERMFORHOST = 463,	/* Returned to a client, which attempts to register with a server which has been configured to refuse connections from the client's host */
	ERR_PASSWDMISMATCH = 464,	/* Returned by the PASS command to indicate the given password was required and was either not given or was incorrect */
	ERR_YOUREBANNEDCREEP = 465,	/* Returned to a client after an attempt to register on a server configured to ban connections from that client */
	ERR_YOUWILLBEBANNED = 466,	/* Sent by a server to a user to inform that access to the server will soon be denied */
	ERR_KEYSET = 467,	/* Returned when the channel key for a channel has already been set */
	ERR_LINKSET = 469,
	ERR_CHANNELISFULL = 471,	/* Returned when attempting to join a channel which is set +l and is already full */
	ERR_UNKNOWNMODE = 472,	/* Returned when a given mode is unknown */
	ERR_INVITEONLYCHAN = 473,	/* Returned when attempting to join a channel, which is invite only without an invitation */
	ERR_BANNEDFROMCHAN = 474,	/* Returned when attempting to join a channel a user is banned from */
	ERR_BADCHANNELKEY = 475,	/* Returned when attempting to join a key-locked channel either without a key or with the wrong key */
	ERR_BADCHANMASK = 476,	/* The given channel mask was invalid */
	ERR_NOCHANMODES = 477,	/* Returned when attempting to set a mode on a channel, which does not support channel modes, or channel mode changes. Also known as ERR_MODELESS */
	ERR_BANLISTFULL = 478,	/* Returned when a channel access list (i.e. ban list etc) is full and cannot be added to */
	ERR_NOPRIVILEGES = 481,	/* Returned by any command requiring special privileges (eg. IRC operator) to indicate the operation was unsuccessful */
	ERR_CHANOPRIVSNEEDED = 482,	/* Returned by any command requiring special channel privileges (eg. channel operator) to indicate the operation was unsuccessful. InspIRCd also uses this numeric "for other things like trying to kick a uline" */
	ERR_CANTKILLSERVER = 483,	/* Returned by KILL to anyone who tries to kill a server */
	ERR_RESTRICTED = 484,	/* Sent by the server to a user upon connection to indicate the restricted nature of the connection (i.e. usermode +r) */
	ERR_UNIQOPRIVSNEEDED = 485,	/* Any mode requiring 'channel creator' privileges returns this error if the client is attempting to use it while not a channel creator on the given channel */
	ERR_NOOPERHOST = 491,	/* Returned by OPER to a client who cannot become an IRC operator because the server has been configured to disallow the client's host */
	ERR_NOSERVICEHOST = 492,
	ERR_BADLOGTYPE = 495,
	ERR_DELAYREJOIN = 495,	/* This numeric is marked as "we should use 'resource temporarily unavailable' from ircnet/ratbox or whatever". Removed in InspIRCd 3.0. */
	ERR_BADLOGSYS = 496,
	ERR_BADLOGVALUE = 497,
	ERR_ISOPERLCHAN = 498,
	ERR_CHANOWNPRIVNEEDED = 499,	/* Works just like ERR_CHANOPRIVSNEEDED except it indicates that owner status (+q) is needed. Also see ERR_CHANOPRIVSNEEDED (482). */
	ERR_UMODEUNKNOWNFLAG = 501,	/* Returned by the server to indicate that a MODE message was sent with a nickname parameter and that the mode flag sent was not recognised. */
	ERR_USERSDONTMATCH = 502,	/* Error sent to any user trying to view or change the user mode for a user other than themselves */
	ERR_GHOSTEDCLIENT = 503,
	ERR_VWORLDWARN = 503,	/* Warning about Virtual-World being turned off. Obsoleted in favor for RPL_MODECHANGEWARN. Also see RPL_MODECHANGEWARN (662). */
	ERR_USERNOTONSERV = 504,
	ERR_SILELISTFULL = 511,
	ERR_BADPING = 513,	/* Also known as ERR_NEEDPONG (Unreal/Ultimate) for use during registration, however it is not used in Unreal (and might not be used in Ultimate either). Also known as ERR_WRONGPONG (Ratbox/charybdis) */
	ERR_BADEXPIRE = 515,
	ERR_DONTCHEAT = 516,
	ERR_DISABLED = 517,
	ERR_WHOSYNTAX = 522,
	ERR_WHOLIMEXCEED = 523,
	ERR_INVALIDKEY = 525,
	ERR_REMOTEPFX = 525,	/* Proposed. */
	ERR_PFXUNROUTABLE = 526,	/* Proposed. */
	ERR_CANTSENDTOUSER = 531,
	ERR_BADHOSTMASK = 550,
	ERR_HOSTUNAVAIL = 551,
	ERR_USINGSLINE = 552,
	ERR_NOTLOWEROPLEVEL = 560,
	ERR_NOTMANAGER = 561,
	ERR_CHANSECURED = 562,
	ERR_UPASSSET = 563,
	ERR_UPASSNOTSET = 564,
	ERR_NOMANAGER = 566,
	ERR_UPASS_SAME_APASS = 567,
	RPL_REAWAY = 597,
	RPL_GONEAWAY = 598,	/* Used when adding users to their `"WATCH"` list. */
	RPL_NOTAWAY = 599,	/* Used when adding users to their `"WATCH"` list. */
	RPL_LOGON = 600,
	RPL_LOGOFF = 601,
	RPL_WATCHOFF = 602,
	RPL_WATCHSTAT = 603,
	RPL_NOWON = 604,
	RPL_NOWOFF = 605,
	RPL_WATCHLIST = 606,
	RPL_ENDOFWATCHLIST = 607,
	RPL_WATCHCLEAR = 608,	/* Also known as RPL_CLEARWATCH in Unreal */
	RPL_NOWISAWAY = 609,	/* Returned when adding users to their `"WATCH"` list. */
	RPL_ISLOCOP = 611,
	RPL_ISNOTOPER = 612,
	RPL_ENDOFISOPER = 613,
	RPL_DCCLIST = 618,
	RPL_OMOTDSTART = 624,
	RPL_OMOTD = 625,
	RPL_ENDOFOMOTD = 626,
	RPL_SETTINGS = 630,
	RPL_ENDOFSETTINGS = 631,
	RPL_DUMPING = 640,	/* Never actually used by Unreal - was defined however the feature that would have used this numeric was never created. */
	RPL_DUMPRPL = 641,	/* Never actually used by Unreal - was defined however the feature that would have used this numeric was never created. */
	RPL_EODUMP = 642,	/* Never actually used by Unreal - was defined however the feature that would have used this numeric was never created. */
	RPL_SYNTAX = 650,	/* Sent when the user does not provide enough parameters for a command. */
	RPL_CHANNELSMSG = 651,
	RPL_WHOWASIP = 652,
	RPL_UNINVITED = 653,
	RPL_SPAMCMDFWD = 659,	/* Used to let a client know that a copy of their command has been passed to operators and the reason for it. */
	RPL_STARTTLS = 670,	/* Indicates that the client may begin the TLS handshake */
	RPL_WHOISSECURE = 671,	/* The text in the last parameter may change. Also known as RPL_WHOISSSL (Nefarious). */
	RPL_CANNOTSETMODES = 673,	/* Returns a full list of modes that cannot be set when a client issues a MODE command */
	RPL_WHOISYOURID = 674,	/* Used to display the user's TS6 UID in WHOIS. */
	ERR_REDIRECT = 690,	/* Indicates an error when setting a channel redirect (MODE +L) or using the banredirect module */
	ERR_STARTTLS = 691,	/* Indicates that a server-side error has occurred */
	ERR_INVALIDMODEPARAM = 696,	/* Indicates that there was a problem with a mode parameter. Replaces various non-standard mode specific numerics. */
	ERR_LISTMODEALREADYSET = 697,	/* Indicates that the user tried to set a list mode which is already set. Replaces various non-standard mode specific numerics. */
	ERR_LISTMODENOTSET = 698,	/* Indicates that the user tried to unset a list mode which is not set. Replaces various non-standard mode specific numerics. */
	RPL_COMMANDS = 700,
	RPL_COMMANDSEND = 701,
	RPL_MODLIST = 702,	/* Output from the MODLIST command */
	RPL_ENDOFMODLIST = 703,	/* Terminates MODLIST output */
	RPL_HELPSTART = 704,	/* Start of HELP command output */
	RPL_HELPTXT = 705,	/* Output from HELP command */
	RPL_ENDOFHELP = 706,	/* End of HELP command output */
	ERR_TARGCHANGE = 707,	/* See doc/tgchange.txt in the charybdis source. */
	RPL_ETRACEFULL = 708,	/* Output from 'extended' trace */
	RPL_ETRACE = 709,	/* Output from 'extended' trace */
	RPL_KNOCK = 710,	/* Message delivered using KNOCK command */
	RPL_KNOCKDLVR = 711,	/* Message returned from using KNOCK command (KNOCK delivered) */
	ERR_TOOMANYKNOCK = 712,	/* Message returned when too many KNOCKs for a channel have been sent by a user */
	ERR_CHANOPEN = 713,	/* Message returned from KNOCK when the channel can be freely joined by the user */
	ERR_KNOCKONCHAN = 714,	/* Message returned from KNOCK when the user has used KNOCK on a channel they have already joined */
	RPL_QUIETLIST = 728,	/* Same thing as RPL_BANLIST, but for mode +q (quiet) */
	RPL_ENDOFQUIETLIST = 729,	/* Same thing as RPL_ENDOFBANLIST, but for mode +q (quiet) */
	RPL_MONONLINE = 730,	/* Used to indicate to a client that either a target has just become online, or that a target they have added to their monitor list is online */
	RPL_MONOFFLINE = 731,	/* Used to indicate to a client that either a target has just left the IRC network, or that a target they have added to their monitor list is offline */
	RPL_MONLIST = 732,	/* Used to indicate to a client the list of targets they have in their monitor list */
	RPL_ENDOFMONLIST = 733,	/* Used to indicate to a client the end of a monitor list */
	ERR_MONLISTFULL = 734,	/* Used to indicate to a client that their monitor list is full, so the MONITOR command failed */
	RPL_RSACHALLENGE2 = 740,	/* From the ratbox m_challenge module, to auth opers. */
	RPL_ENDOFRSACHALLENGE2 = 741,	/* From the ratbox m_challenge module, to auth opers. */
	ERR_MLOCKRESTRICTED = 742,	/* InspIRCd 2.0 doesn't send the <client> parameter, while 3.0 does */
	ERR_INVALIDBAN = 743,
	ERR_TOPICLOCK = 744,	/* Defined in the Charybdis source code with the comment "inspircd" */
	RPL_SCANMATCHED = 750,	/* From the ratbox m_scan module. */
	RPL_SCANUMODES = 751,	/* From the ratbox m_scan module. */
	RPL_ETRACEEND = 759,
	RPL_WHOISKEYVALUE = 760,	/* Reply to WHOIS - Metadata key/value associated with the target */
	RPL_KEYVALUE = 761,	/* Returned to show a currently set metadata key and its value, or a metadata key that has been cleared if no value is present in the response */
	RPL_METADATAEND = 762,	/* Indicates the end of a list of metadata keys */
	ERR_METADATALIMIT = 764,	/* Used to indicate to a client that their metadata store is full, and they cannot add the requested key(s) */
	ERR_TARGETINVALID = 765,	/* Indicates to a client that the target of a sent METADATA command is invalid */
	ERR_NOMATCHINGKEY = 766,	/* Indicates to a client that the requested metadata key does not exist */
	ERR_KEYINVALID = 767,	/* Indicates to a client that the requested metadata key is not valid */
	ERR_KEYNOTSET = 768,	/* Indicates to a client that the metadata key they requested to clear is not already set */
	ERR_KEYNOPERMISSION = 769,	/* Indicates to a client that they do not have permission to set the requested metadata key */
	RPL_XINFO = 771,	/* Used to send 'eXtended info' to the client, a replacement for the STATS command to send a large variety of data and minimize numeric pollution. */
	RPL_XINFOSTART = 773,	/* Start of an RPL_XINFO list */
	RPL_XINFOEND = 774,	/* Termination of an RPL_XINFO list */
	RPL_STATSCOUNTRY = 801,	/* Used by the m_geoclass module of InspIRCd. */
	RPL_CHECK = 802,	/* Used by the m_check module of InspIRCd. */
	RPL_OTHERUMODEIS = 803,	/* Similar to RPL_UMODEIS but used when an oper views the mode of another user. */
	RPL_OTHERSNOMASKIS = 804,	/* Similar to RPL_SNOMASK but used when an oper views the snomasks of another user. */
	RPL_LOGGEDIN = 900,	/* Sent when the user's account name is set (whether by SASL or otherwise) */
	RPL_LOGGEDOUT = 901,	/* Sent when the user's account name is unset (whether by SASL or otherwise) */
	ERR_NICKLOCKED = 902,	/* Sent when the SASL authentication fails because the account is currently locked out, held, or otherwise administratively made unavailable. */
	RPL_SASLSUCCESS = 903,	/* Sent when the SASL authentication finishes successfully. Also see RPL_LOGGEDIN (900). */
	ERR_SASLFAIL = 904,	/* Sent when the SASL authentication fails because of invalid credentials or other errors not explicitly mentioned by other numerics */
	ERR_SASLTOOLONG = 905,	/* Sent when credentials are valid, but the SASL authentication fails because the client-sent AUTHENTICATE command was too long (i.e. the parameter longer than 400 bytes) */
	ERR_SASLABORTED = 906,	/* Sent when the SASL authentication is aborted because the client sent an AUTHENTICATE command with * as the parameter */
	ERR_SASLALREADY = 907,	/* Sent when the client attempts to initiate SASL authentication after it has already finished successfully for that connection. */
	RPL_SASLMECHS = 908,	/* Sent when the client requests a list of SASL mechanisms supported by the server (or network, services). The numeric contains a comma-separated list of mechanisms */
	RPL_ACCESSLIST = 910,	/* Used by InspIRCd's m_autoop module. */
	RPL_ENDOFACCESSLIST = 911,	/* Used by InspIRCd's m_autoop module. */
	ERR_BADCHANNEL = 926,	/* Used by InspIRCd's m_denychans module. */
	ERR_WORDFILTERED = 936,	/* Replaced with ERR_CANNOTSENDTOCHAN in InspIRCd 3.0. */
	ERR_ALREADYCHANFILTERED = 937,	/* Used by InspIRCd's m_chanfilter module. Replaced with ERR_LISTMODEALREADYSET in 3.0. */
	ERR_NOSUCHCHANFILTER = 938,	/* Used by InspIRCd's m_chanfilter module. Replaced with ERR_LISTMODENOTSET in 3.0. */
	ERR_CHANFILTERFULL = 939,	/* Used by InspIRCd's m_chanfilter module. Replaced with ERR_BANLISTFULL in 3.0. */
	RPL_ENDOFSPAMFILTER = 940,	/* Used by InspIRCd's m_chanfilter module. */
	RPL_SPAMFILTER = 941,	/* Used by InspIRCd's m_chanfilter module. */
	ERR_INVALIDWATCHNICK = 942,	/* Used by InspIRCd's m_watch module. */
	RPL_IDLETIMESET = 944,	/* Used by InspIRCd's m_setidle module. */
	RPL_NICKLOCKOFF = 945,	/* Used by InspIRCd's m_nicklock module. */
	ERR_NICKNOTLOCKED = 946,	/* Used by InspIRCd's m_nicklock module. */
	RPL_NICKLOCKON = 947,	/* Used by InspIRCd's m_nicklock module. */
	ERR_INVALIDIDLETIME = 948,	/* Used by InspIRCd's m_setidle module. */
	RPL_UNSILENCED = 950,	/* Used by InspIRCd's m_silence module. */
	RPL_SILENCED = 951,	/* Used by InspIRCd's m_silence module. */
	ERR_SILENCE = 952,	/* Used by InspIRCd's m_silence module. The flags field was added in v3. */
	RPL_ENDOFEXEMPTIONLIST = 953,	/* Used by InspIRCd's m_exemptchanop module. */
	RPL_EXEMPTIONLIST = 954,	/* Used by InspIRCd's m_exemptchanop module. */
	RPL_ENDOFPROPLIST = 960,	/* Used by InspIRCd's m_namedmodes module. */
	RPL_PROPLIST = 961,	/* Used by InspIRCd's m_namedmodes module. */
	RPL_UNLOADEDMODULE = 973,
	RPL_SERVLOCKON = 988,	/* Used by InspIRCd's m_lockserv module. */
	RPL_SERVLOCKOFF = 989,	/* Used by InspIRCd's m_lockserv module. */
	RPL_DCCALLOWSTART = 990,	/* Used by InspIRCd's m_dccallow module */
	RPL_DCCALLOWLIST = 991,	/* Used by InspIRCd's m_dccallow module */
	RPL_DCCALLOWEND = 992,	/* Used by InspIRCd's m_dccallow module */
	RPL_DCCALLOWTIMED = 993,	/* Used by InspIRCd's m_dccallow module */
	RPL_DCCALLOWPERMANENT = 994,	/* Used by InspIRCd's m_dccallow module */
	RPL_DCCALLOWREMOVED = 995,	/* Used by InspIRCd's m_dccallow module. */
	ERR_DCCALLOWINVALID = 996,	/* Used by InspIRCd's m_dccallow module. */
	RPL_DCCALLOWEXPIRED = 997,	/* Used by InspIRCd's m_dccallow module. */
	ERR_UNKNOWNDCCALLOWCMD = 998,	/* Used by InspIRCd's m_dccallow module. */
	RPL_DCCALLOWHELP = 998,	/* Used by InspIRCd's m_dccallow module. */
	RPL_ENDOFDCCALLOWHELP = 999,	/* Used by InspIRCd's m_dccallow module. */
	ERR_NUMERIC_ERR = 999,	/* Also known as ERR_NUMERICERR (Unreal) or ERR_LAST_ERR_MSG */
};

enum irc_ctcp {
	CTCP_ACTION,
	CTCP_VERSION,
	CTCP_TIME,
	CTCP_PING,
	/* XXX Others missing */
};

/*! \brief IRC message */
struct irc_msg {
	char *prefix;
	int numeric;
	char *command;
	char *body;
};

/*! \brief IRC library log levels */
enum irc_log_level {
	IRC_LOG_ERR,
	IRC_LOG_WARN,
	IRC_LOG_INFO,
	IRC_LOG_DEBUG,
};

/*!
 * \brief Set logging callback function (so your application can log IRC library messages)
 * \param level irc_log_level of message
 * \param sublevel Debug messages only, numeric debug level
 * \param msg Logging message
 * \param len Message length
 */
void irc_log_callback(void (*callback)(enum irc_log_level level, int sublevel, const char *file, int line, const char *func, const char *msg));

/* IRC client flags */
#define IRC_CLIENT_USE_TLS (1 << 0)
#define IRC_CLIENT_VERIFY_SERVER (1 << 1)
#define IRC_CLIENT_USE_SASL (1 << 2)

/*!
 * \brief Request a new IRC client, good for a single server
 * \param hostname
 * \param port. Use 0 for default port (6667 plain text)
 * \param username
 * \param password
 * \returns Client on success, NULL on failure. A returned client must be freed with irc_client_destroy.
 */
struct irc_client *irc_client_new(const char *hostname, unsigned int port, const char *username, const char *password);

/*!
 * \brief Destroy (free) an IRC client
 * \param client
 */
void irc_client_destroy(struct irc_client *client);

/*! \brief Get the hostname of the server to which this IRC client connected */
const char *irc_client_hostname(struct irc_client *client);

/*! \brief Get the username of an IRC client */
const char *irc_client_username(struct irc_client *client);

/*! \brief Get the nickname of an IRC client */
const char *irc_client_nickname(struct irc_client *client);

/*! \brief Whether the client is actively connected to an IRC server */
int irc_client_connected(struct irc_client *client);

/*!
 * \brief Set channels to autojoin on connect
 * \param client
 * \param autojoin Comma-separated list of channels to autojoin. NULL to remove existing autojoin.
 * \retval 0 on success, -1 on failure
 */
int irc_client_autojoin(struct irc_client *client, const char *autojoin);

/*!
 * \brief Set client connection flags
 * \param client
 * \param flags IRC client flags
 * \retval 0 on success, -1 on failure
 */
int irc_client_set_flags(struct irc_client *client, int flags);

/*!
 * \brief Initiate a connection to an IRC server
 * \param client
 * \retval 0 on success, -1 on failure
 */
int irc_client_connect(struct irc_client *client);

/*!
 * \brief Identify with the IRC server
 * \note This should only be used if connecting to the server initially WITHOUT authenticating. Do not use in conjunction with irc_client_login.
 * \param client
 * \param username Nickname
 * \param password
 * \param realname
 * \retval 0 on success, -1 on failure
 */
int irc_client_auth(struct irc_client *client, const char *username, const char *password, const char *realname);

/*!
 * \brief Authenticate to the IRC server
 * \note If SASL is enabled, this will perform SASL authentication prior to logging in
 * \retval 0 on success, -1 on failure
 */
int irc_client_login(struct irc_client *client);

/*!
 * \brief Join channel(s)
 * \param client
 * \param channel Channel name(s). Should begin with # or &, comma-separated
 * \retval 0 on success, -1 on failure
 */
int irc_client_channel_join(struct irc_client *client, const char *channel);

/*!
 * \brief Leave channel(s)
 * \param client
 * \param channel Channel name(s). Should begin with # or &, comma-separated
 * \retval 0 on success, -1 on failure
 */
int irc_client_channel_leave(struct irc_client *client, const char *channel);

/*!
 * \brief Quit the server connection (disconnect from all channels and close session)
 * \param client
 * \param msg Optional quit message. NULL for no message.
 * \retval 0 on success, -1 on failure
 */
int irc_client_quit(struct irc_client *client, const char *msg);

/*!
 * \brief Send a message to a channel or user
 * \param client
 * \param channel Name of channel (beginning with # or &) or user
 * \param msg Message. Do NOT terminate with CR LF.
 * \retval 0 on success, -1 on failure
 */
int irc_client_msg(struct irc_client *client, const char *channel, const char *msg);

/*! \brief Same as irc_client_msg, but send a NOTICE instead of a PRIVMSG.
 *         This will inhibit any autoresponses, e.g. to prevent loops by bots
 */
int irc_client_notice(struct irc_client *client, const char *channel, const char *msg);

/*! \brief Get a CTCP code from a string */
enum irc_ctcp irc_ctcp_from_string(const char *s);

/*! \brief Get a string representation of a CTCP code */
const char *irc_ctcp_name(enum irc_ctcp ctcp);

/*!
 * \brief Send a CTCP command to another user (using PRIVMSG)
 * \param client
 * \param user Target user
 * \param ctcp CTCP command to request
 * \retval 0 on success, -1 on failure
 */
int irc_client_ctcp_request(struct irc_client *client, const char *user, enum irc_ctcp ctcp);

/*!
 * \brief Send a CTCP reply to another user (using NOTICE)
 * \param client
 * \param user Target user
 * \param ctcp CTCP command
 * \retval 0 on success, -1 on failure
 */
int irc_client_ctcp_reply(struct irc_client *client, const char *username, enum irc_ctcp ctcp, const char *data);

/*!
 * \brief Send an action message (CTCP action command) to a channel or user
 * \param client
 * \param channel Channel name for /me actions and username for /describe actions
 * \param msg
 * \retval 0 on success, -1 on failure
 */
int irc_client_action(struct irc_client *client, const char *channel, const char *msg);

/*!
 * \brief Change the client's nickname on the server
 * \param client
 * \param nick New nickname
 * \retval 0 on success, -1 on failure
 * \note This sends a NICK message and does NOT update the nickname internally. Use irc_client_set_nick for that.
 *       Typically you would call irc_client_change_nick on a /nick message, and after receiving a successful
 *       acknowledgment from the server, call irc_client_set_nick to actually reflect that in the client.
 */
int irc_client_change_nick(struct irc_client *client, const char *nick);

/*!
 * \brief Set the nickname of the client internally
 * \param client
 * \param nick New nickname
 * \retval 0 on success, -1 on failure
 * \note This only sets the nickname internally and does NOT send a NICK message to the server. Use irc_client_change_nick for that.
 */
int irc_client_set_nick(struct irc_client *client, const char *nick);

/*!
 * \brief Set a channel topic
 * \param client
 * \param channel Channel name
 * \param topic Topic to set
 * \retval 0 on success, -1 on failure
 */
int irc_client_set_channel_topic(struct irc_client *client, const char *channel, const char *topic);

/*!
 * \brief Query channels on server
 * \param client
 * \param channels If provided, comma-separated list of channels to which to limit the query
 * \retval 0 on success, -1 on failure
 */
int irc_client_list_channels(struct irc_client *client, const char *channels);

/*!
 * \brief Invite a user to a channel
 * \param client
 * \param nickname Nick of user to invite
 * \param channel Channel to which to invite the user
 * \retval 0 on success, -1 on failure
 */
int irc_client_invite_user(struct irc_client *client, const char *nickname, const char *channel);

/*!
 * \brief Parse data sent from the server
 * \param msg
 * \param s Null-terminated string that ends in CR LF
 * \retval 0 on success, -1 on failure
 */
int irc_parse_msg(struct irc_msg *msg, char *s);

/*!
 * \brief poll() wrapper for IRC client
 * \param client
 * \param ms
 * \param fd Optional additional fd to poll. -1 if none.
 * \note This function internally continues if poll is interrupted by EINTR, so if -1 is returned, it is a genuine failure.
 * \retval same as poll()
 */
int irc_poll(struct irc_client *client, int ms, int fd);

/*!
 * \brief read() wrapper for IRC client
 * \param client
 * \param buf
 * \param len
 * \note If TLS is enabled for the client, read data will be decrypted
 * \retval same as read()
 */
int irc_read(struct irc_client *client, char *buf, int len);

/*!
 * \brief write() wrapper for IRC client
 * \param client
 * \param buf
 * \param len
 * \note If TLS is enabled for the client, written data will be encrypted
 * \retval same as write()
 */
int irc_write(struct irc_client *client, const char *buf, int len);

/*!
 * \brief write() wrapper for IRC client
 * \param client
 * \param fmt printf-style format string
 * \note If TLS is enabled for the client, written data will be encrypted
 * \warning Avoid using this function directly, use irc_send() instead
 * \retval same as write()
 */
int __attribute__ ((format (gnu_printf, 2, 3))) irc_write_fmt(struct irc_client *client, const char *fmt, ...);

/*!
 * \brief write() wrapper for IRC client
 * \param client
 * \param fmt printf-style format string
 * \note If TLS is enabled for the client, written data will be encrypted
 * \retval 0 on success, 1 on failure
 */
#define irc_send(client, fmt, ...) (irc_write_fmt(client, fmt "\r\n", __VA_ARGS__) <= 0)
