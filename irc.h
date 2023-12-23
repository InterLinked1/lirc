/*
 * LIRC - IRC Client Library for C
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This library is free software, distributed under the terms of
 * the GNU Lesser General Public License Version 2.1. See the LICENSE file
 * at the top of the source tree.
 */

#define LIRC_VERSION_MAJOR 0
#define LIRC_VERSION_MINOR 2
#define LIRC_VERSION_PATCH 1

/*! \brief Maximum length of an IRC message, including trailing CR LF */
#define IRC_MAX_MSG_LEN 512

/*! \brief Default port for insecure connections */
#define IRC_DEFAULT_PORT 6667

/*! \brief Default port for secure connections */
#define IRC_DEFAULT_TLS_PORT 6697

enum irc_msg_type {
	IRC_UNPARSED,		/*!< Message type was never parsed (default) */
	IRC_NUMERIC,
	IRC_CMD_PRIVMSG,
	IRC_CMD_NOTICE,		/*!< Same as PRIVMSG, but should never be acknowledged, to prevent loops */
	IRC_CMD_PING,
	IRC_CMD_JOIN,
	IRC_CMD_PART,
	IRC_CMD_QUIT,
	IRC_CMD_KICK,
	IRC_CMD_NICK,
	IRC_CMD_MODE,
	IRC_CMD_TOPIC,
	/*! \todo Add more message types here as needed */
	IRC_CMD_ERROR,
	IRC_CMD_OTHER,		/*!< Some command that doesn't have an enum value */
};

enum irc_ctcp_type {
	CTCP_UNPARSED,
	CTCP_ACTION,
	CTCP_VERSION,
	CTCP_TIME,
	CTCP_PING,
	CTCP_DCC,
	/* XXX Others missing */
	CTCP_UNKNOWN,
};

/*! \brief IRC message */
#ifdef EXPOSE_IRC_MSG
/*! \note This is intentionally not opaque, so callers can stack allocate it if needed.
 * (If using irc_loop, applications should not need to expose this).
 * However, you should NOT directly access any members of this struct;
 * instead, use the defined accessor functions. */
struct irc_msg {
	char *prefix;
	int numeric;
	const char *command;
	const char *channel;
	enum irc_msg_type type;
	enum irc_ctcp_type ctcp_type;
	unsigned int ctcp:1;
	char *body;
};
#else
struct irc_msg;
#endif

/*! \brief IRC message */
struct irc_msg;

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

/*!
 * \brief Send a PONG reply to a PING message
 * \param client
 * \param msg PING message
 * \retval 0 on success, -1 on failure
 */
int irc_client_pong(struct irc_client *client, struct irc_msg *msg);

/*! \brief Get a CTCP code from a string */
enum irc_ctcp_type irc_ctcp_from_string(const char *s);

/*! \brief Get a string representation of a CTCP code */
const char *irc_ctcp_name(enum irc_ctcp_type ctcp);

/*!
 * \brief Send a CTCP command to another user (using PRIVMSG)
 * \param client
 * \param user Target user
 * \param ctcp CTCP command to request
 * \retval 0 on success, -1 on failure
 * \note Use irc_client_action to send a CTCP action, rather than using this function directly.
 */
int irc_client_ctcp_request(struct irc_client *client, const char *user, enum irc_ctcp_type ctcp);

/*!
 * \brief Send a CTCP reply to another user (using NOTICE)
 * \param client
 * \param user Target user
 * \param ctcp CTCP command
 * \retval 0 on success, -1 on failure
 */
int irc_client_ctcp_reply(struct irc_client *client, const char *username, enum irc_ctcp_type ctcp, const char *data);

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
 * \param[out] msg
 * \param s Null-terminated string that ends in CR LF
 * \retval 0 on success, -1 on failure
 * \note msg should be zeroed before calling.
 */
int irc_parse_msg(struct irc_msg *msg, char *s);

/*!
 * \brief Parse the message type
 * \param msg
 * \note May only be called after irc_parse_msg
 *       If this function is not called, irc_msg_type will return IRC_UNPARSED.
 *       This means you can avoid this parsing overhead if you don't need
 *       to call irc_msg_type later.
 * \retval 0 on success, -1 on failure
 */
int irc_parse_msg_type(struct irc_msg *msg);

/*!
 * \brief Parse a CTCP message
 * \param msg
 * \note May only be called after irc_parse_msg_type, and if irc_msg_is_ctcp() == 1
 *       If this function is not called, irc_msg_ctcp_type will return CTCP_UNPARSED.
 *       This means you can avoid this parsing overhead if you don't need
 *       to call irc_msg_ctcp_type later.
 * \retval 0 on success, -1 on failure
 */
int irc_parse_msg_ctcp(struct irc_msg *msg);

/*!
 * \brief Get the IRC message prefix.
 * \param msg
 * \note May only be called after irc_parse_msg
 * \return Message prefix
 */
char *irc_msg_prefix(struct irc_msg *msg);

/*!
 * \brief Get the IRC message numeric
 * \param msg
 * \note May only be called after irc_parse_msg
 * \return Message numeric
 * \retval 0, if not a numeric message
 */
int irc_msg_numeric(struct irc_msg *msg);

/*!
 * \brief Get the IRC message command
 * \param msg
 * \note May only be called after irc_parse_msg
 * \return Message command
 */
const char *irc_msg_command(struct irc_msg *msg);

/*!
 * \brief Get the IRC message type
 * \param msg
 * \note May only be called after irc_parse_msg_type
 * \return Message type
 */
enum irc_msg_type irc_msg_type(struct irc_msg *msg);

/*!
 * \brief Get whether the IRC message is a CTCP message
 * \param msg
 * \note May only be called after irc_parse_msg
 * \retval 1 if CTCP
 * \retval 0 if not CTCP
 */
int irc_msg_is_ctcp(struct irc_msg *msg);

/*!
 * \brief Get the CTCP message type
 * \param msg
 * \note May only be called after irc_parse_ctcp
 * \return CTCP message type
 */
enum irc_ctcp_type irc_msg_ctcp_type(struct irc_msg *msg);

/*!
 * \brief Get the IRC message channel
 * \param msg
 * \note May only be called after irc_parse_msg
 * \return Channel name
 * \return NULL, if not a channel-oriented message type
 */
const char *irc_msg_channel(struct irc_msg *msg);

/*!
 * \brief Get the IRC message body
 * \param msg
 * \note May only be called after irc_parse_msg
 * \return Message body
 */
char *irc_msg_body(struct irc_msg *msg);

/*!
 * \brief Execute a loop that will receive and process IRC messages. To make the loop exit, call irc_disconnect from another thread.
 * \param client
 * \param logfile Optional log file to which to log messages (NULL if don't log)
 * \param cb Callback function to execute for each received message
 * \param data Custom data to pass to callback function
 * \note This is a high-level convenience function that calls irc_poll and irc_read; you do not need to use this function.
 */
void irc_loop(struct irc_client *client, FILE *logfile, void (*cb)(void *data, struct irc_msg *msg), void *data);

/*!
 * \brief Disconnect an IRC client
 * \param client
 * \retval 0 on success, -1 on failure
 * \note This is most useful for causing irc_loop to exit immediately (or irc_poll to return immediately from another thread)
 */
int irc_disconnect(struct irc_client *client);

/*!
 * \brief poll() wrapper for IRC client
 * \param client
 * \param ms
 * \param fd Optional additional fd to poll. -1 if none.
 * \note This function internally continues if poll is interrupted by EINTR, so if -1 is returned, it is a genuine failure.
 * \retval -1 on failure, 0 if no activity, 1 if the client had activity, 2 if fd had activity
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
ssize_t irc_read(struct irc_client *client, char *buf, size_t len);

/*!
 * \brief write() wrapper for IRC client
 * \param client
 * \param buf
 * \param len
 * \note If TLS is enabled for the client, written data will be encrypted
 * \retval same as write()
 */
ssize_t irc_write(struct irc_client *client, const char *buf, size_t len);

/*!
 * \brief write() wrapper for IRC client
 * \param client
 * \param fmt printf-style format string
 * \note If TLS is enabled for the client, written data will be encrypted
 * \warning Avoid using this function directly, use irc_send() instead
 * \retval same as write()
 */
ssize_t __attribute__ ((format (gnu_printf, 2, 3))) irc_write_fmt(struct irc_client *client, const char *fmt, ...);

/*!
 * \brief write() wrapper for IRC client
 * \param client
 * \param fmt printf-style format string
 * \note If TLS is enabled for the client, written data will be encrypted
 * \retval 0 on success, 1 on failure
 */
#define irc_send(client, fmt, ...) (irc_write_fmt(client, fmt "\r\n", __VA_ARGS__) <= 0)
