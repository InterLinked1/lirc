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

/*! \file
 *
 * \brief TLS/SASL-capable IRC client program
 *
 * \note This is a fully functional IRC client.
 * This was written primarily to test the functionality of the library,
 * but can also be used as a standalone client in and of itself,
 * or for debugging or troubleshooting, etc.
 * However, it is limited in that it only supports connection to 1 server at a time,
 * whereas richer clients may support multiple servers/networks/etc.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h> /* use gettimeofday */
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <termios.h>

#include "irc.h"

#define CLIENT_VERSION "LIRC client 0.1.0" /* LIRC refers to the library, this is the LIRC client demo program */
#define CLIENT_COPYRIGHT CLIENT_VERSION ", Copyright (C) 2023 Naveen Albert"

static pthread_t rx_thread_id;
static int debug_level = 0;
static int fully_started = 0;
static int shutting_down = 0;
static int do_not_disturb = 0;
static char client_prompt[84] = "IRC> ";
static char fg_chan[64] = "";
static int iopipe[2] = { -1, -1 };
static FILE *clientlog = NULL;

static struct termios orig_term;

static void restore_term(void)
{
	tcsetattr(STDIN_FILENO, TCSANOW, &orig_term);
}

static int set_term(void)
{
	struct termios term;

	memset(&orig_term, 0, sizeof(orig_term));

	if (tcgetattr(STDIN_FILENO, &orig_term)) {
		fprintf(stderr, "tcgetattr failed: %s\n", strerror(errno));
		return -1;
	}
	memcpy(&term, &orig_term, sizeof(term));
	term.c_lflag &= ~ICANON; /* Disable canonical mode to disable input buffering */
	if (tcsetattr(STDIN_FILENO, TCSANOW, &term)) {
		fprintf(stderr, "tcsetattr failed: %s\n", strerror(errno));
		return -1;
	}
	atexit(restore_term);
	return 0;
}

#define COLOR_RESET "\033[0m"
#define COLOR_BEGIN "\033[1;"
#define COLOR_RED COLOR_BEGIN "31m"
#define COLOR_GREEN COLOR_BEGIN "32m"
#define COLOR_CYAN COLOR_BEGIN "36m"
#define COLOR_WHITE COLOR_BEGIN "37m"

static inline void print_time(int fd)
{
	time_t lognow;
    struct tm logdate;
	struct timeval now;
	char datestr[20];

	/* Print current time */
	gettimeofday(&now, NULL);
	lognow = time(NULL);
	localtime_r(&lognow, &logdate);
	strftime(datestr, sizeof(datestr), "%Y-%m-%d %T", &logdate);
	dprintf(fd, "\r[%s] ", datestr); /* Begin with CR to erase prompt on existing line. */
}

#define client_log(level, fmt, ...)  _client_log(level, 0, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__)

static void __client_log(enum irc_log_level level, int sublevel, const char *file, int line, const char *func, const char *msg)
{
	int fd = fully_started ? iopipe[1] : STDOUT_FILENO;
	assert(fd != -1);
	/* Log messages already have a newline, don't add another one */
	switch (level) {
		case IRC_LOG_ERR:
			print_time(fd);
			dprintf(fd, "[%sERROR%s] %s:%d %s() %s", COLOR_RED, COLOR_RESET, file, line, func, msg);
			break;
		case IRC_LOG_WARN:
			print_time(fd);
			dprintf(fd, "[%sWARN %s] %s:%d %s() %s", COLOR_RED, COLOR_RESET, file, line, func, msg);
			break;
		case IRC_LOG_INFO:
			print_time(fd);
			dprintf(fd, "[%sINFO %s] %s:%d %s() %s", COLOR_CYAN, COLOR_RESET, file, line, func, msg);
			break;
		case IRC_LOG_DEBUG:
			if (debug_level >= sublevel) {
				print_time(fd);
				dprintf(fd, "[%sDEBUG%s] %s:%d %s() %s", COLOR_GREEN, COLOR_RESET, file, line, func, msg);
			}
			break;
	}
}

static void __attribute__ ((format (gnu_printf, 6, 7))) _client_log(enum irc_log_level level, int sublevel, const char *file, int line, const char *func, const char *fmt, ...)
{
	char *buf;
	int len;
	va_list ap;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len >= 0) {
		__client_log(level, sublevel, file, line, func, buf);
		free(buf);
	}
}

static void __attribute__ ((format (gnu_printf, 1, 2))) irc_print(const char *fmt, ...)
{
	char *buf;
	int len;
	va_list ap;
	int fd = fully_started ? iopipe[1] : STDOUT_FILENO;

	assert(fd != -1);
	print_time(fd);

	va_start(ap, fmt);
	/* For some reason, if vdprintf() is called on the write end of a pipe
	 * while elsewhere we're calling poll() on the read end,
	 * all kinds of weird corruption will happen, leading quickly to a segfault.
	 * vasprintf + write instead works just fine.
	 * This is the first time I had used the vdprintf function specifically,
	 * so not really sure what's up. Just avoid it I guess... */
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len >= 0) {
		write(fd, buf, len);
		free(buf);
	}
}

static void update_prompt(struct irc_client *client)
{
	if (*irc_client_nickname(client)) {
		if (*fg_chan) {
			snprintf(client_prompt, sizeof(client_prompt), "%s@%s (%s)> ", irc_client_nickname(client), irc_client_hostname(client), fg_chan);
		} else {
			snprintf(client_prompt, sizeof(client_prompt), "%s@%s> ", irc_client_nickname(client), irc_client_hostname(client));
		}
	} else {
		snprintf(client_prompt, sizeof(client_prompt), "%s> ", irc_client_hostname(client));
	}
}

static void set_term_title(const char *s)
{
	printf("\033]2;%s\007", s);
}

static void set_fg_chan(const char *fgchan)
{
	strncpy(fg_chan, fgchan, sizeof(fg_chan) - 1);
	fg_chan[sizeof(fg_chan) - 1] = '\0';
	set_term_title(fg_chan);
}

/* Forward declaration */
static void handle_irc_msg(struct irc_client *client, struct irc_msg *msg);

static void *rx_thread(void *varg)
{
	/* Thread will get killed on shutdown */
	int res = 0;
	char readbuf[IRC_MAX_MSG_LEN + 1];
	struct irc_msg msg;
	char *prevbuf, *mybuf = readbuf;
	int prevlen, mylen = sizeof(readbuf) - 1;
	struct irc_client *client = varg;
	char *start, *eom;
	int rounds;

	clientlog = fopen("client.txt", "a"); /* Create or append */
	if (!clientlog) {
		client_log(IRC_LOG_ERR, "Failed to open file\n");
		return NULL;
	}

	start = readbuf;
	for (;;) {
begin:
		rounds = 0;
		if (mylen <= 1) {
			/* IRC max message is 512, but we could have received multiple messages in one read() */
			char *a;
			/* Shift current message to beginning of the whole buffer */
			for (a = readbuf; *start; a++, start++) {
				*a = *start;
			}
			*a = '\0';
			mybuf = a;
			mylen = sizeof(readbuf) - 1 - (mybuf - readbuf);
			start = readbuf;
			if (mylen <= 1) { /* Couldn't shift, whole buffer was full */
				/* Could happen but this would not be valid. Abort read and reset. */
				client_log(IRC_LOG_ERR, "Buffer truncation!\n");
				start = readbuf;
				mybuf = readbuf;
				mylen = sizeof(readbuf) - 1;
			}
		}
		/* Wait for data from server */
		if (res != sizeof(readbuf) - 1) {
			/* XXX We don't poll if we read() into an entirely full buffer and there's still more data to read.
			 * poll() won't return until there's even more data (but it feels like it should). */
			res = irc_poll(client, -1, -1);
			if (res <= 0) {
				break;
			}
		}
		prevbuf = mybuf;
		prevlen = mylen;
		res = irc_read(client, mybuf, mylen);
		if (res <= 0) {
			break;
		}

		mybuf[res] = '\0'; /* Safe */
		do {
			eom = strstr(mybuf, "\r\n");
			if (!eom) {
				/* read returned incomplete message */
				mybuf = prevbuf + res;
				mylen = prevlen - res;
				goto begin; /* In a double loop, can't continue */
			}

			/* Got more than one message? */
			if (*(eom + 2)) {
				*(eom + 1) = '\0'; /* Null terminate before the next message starts */
			}

			memset(&msg, 0, sizeof(msg));
			fprintf(clientlog, "%s\n", start); /* Append to log file */
			if (!irc_parse_msg(&msg, start)) {
				handle_irc_msg(client, &msg);
			}

			mylen -= (eom + 2 - mybuf);
			start = mybuf = eom + 2;
			rounds++;
		} while (mybuf && *mybuf);

		start = mybuf = readbuf; /* Reset to beginning */
		mylen = sizeof(readbuf) - 1;
	}

	client_log(IRC_LOG_INFO, "IRC client receive thread has exited\n");
	assert(!irc_client_connected(client));
	write(iopipe[1], "", 1);
	return NULL;
}

static int client_readline(char *buf, size_t len)
{
	int num_read = 0;
	int lastpos = 0;
	struct pollfd fds[2];
	char outputbuf[512];
	int res;
	char *bufstart = buf;

	printf("%s", client_prompt);
	fflush(stdout);

#define CLEAR_LINE "\r\033[0K"

	for (;;) {
		fds[0].fd = STDIN_FILENO;
		fds[0].events = POLLIN;
		fds[0].revents = 0;
		fds[1].fd = iopipe[0];
		fds[1].events = POLLIN;
		fds[1].revents = 0;

		res = poll(fds, 2, -1);
		if (res < 0) {
			if (errno == EINTR) {
				continue;
			}
			client_log(IRC_LOG_ERR, "poll failed: %s\n", strerror(errno));
			break;
		} else if (fds[0].revents) {
			/* Input from CLI: read one char at a time (we're in noncanonical mode anyways). */
			res = read(STDIN_FILENO, buf, 1);
			if (res <= 0) {
				break;
			}
			/* Intentionally avoid using libedit and just implement a simple line editor ourselves.
			 * It's not too much work, and it was easier than trying to debug some uninitialized
			 * usage errors in the library... since there's no debug symbols package for libedit
			 * for Debian. */
			if (*buf == '\n') {
				if (!num_read) {
					/* New prompt */
					printf("%s", client_prompt);
					fflush(stdout);
					continue; /* Ignore empty lines, or we'd return 0 and disconnect */
				}
				return num_read; /* End of line */
			} else if (*buf == 8 || *buf == 127) { /* Backspace / Delete */
				if (num_read) {
					/* There's not really a good way to do backspace of a character manually
					 * in a way that is compatible with all terminal emulators.
					 * This is why it's generally preferred to use the line editor in canonical mode.
					 * But if we do that, then we can't do the write over prompt trick below.
					 * "\b \b" is good for some (SyncTERM) but leaves artifacts on others (PuTTY/KiTTY)
					 * Echoing the character itself (8 or 127) has the same problem (though not necessarily
					 * with the same programs).
					 * Invoke the nuclear option: just go ahead and rewrite the whole entire line.
					 * (This won't be pretty on slow connections.)
					 */
					num_read--;
					buf--;
					len++;
				} else {
					write(STDOUT_FILENO, "\a", 1); /* Ring the bell to signal nothing to erase in buffer */
					/* This will print ^? to the CLI, so write over the whole line as well */
				}
				printf(CLEAR_LINE "%s%.*s", client_prompt, num_read, bufstart);
				fflush(stdout);
				continue;
			}
			/* XXX Arrow keys (for editing) not currently supported */
			buf += res;
			len -= res;
			num_read += res;
			lastpos = 0;
			if (len <= 1) {
				return num_read; /* Buffer is full, send what we got */
			}
		} else if (fds[1].revents) {
			/* Output for CLI */
			res = read(iopipe[0], outputbuf, sizeof(outputbuf) - 1);
			if (res <= 0) {
				break;
			} else if (res == 1 && *outputbuf == '\0') {
				shutting_down = 1;
				break; /* Signal handler wrote this, telling us to exit. */
			}

			outputbuf[res] = '\0'; /* Safe */
			/* Write over the CLI prompt */
			if (!lastpos) {
				if (write(STDOUT_FILENO, CLEAR_LINE, 5) < 0) {
					client_log(IRC_LOG_ERR, "Failed to write: %s\n", strerror(errno));
					break;
				}
			}

			printf("%s", outputbuf);
			fflush(stdout);

			if ((res < (int) sizeof(outputbuf) - 1) && ((outputbuf[res - 1] == '\n') || (res >= 2 && outputbuf[res - 2] == '\n'))) {
				/* Output has been written, now redisplay the prompt and whatever had been typed so far */
				printf("\r%s%.*s", client_prompt, num_read, bufstart);
				fflush(stdout);
				/* Continue */
			}
			lastpos = 1;
		}
	}
	return -1;
}

static void __sigint_handler(int num)
{
	(void) num;
	write(iopipe[1], "", 1); /* This will cause the client_readline loop to wake up and exit after setting shutting_down = 1 */
}

/*! \brief Replacement for the obsolete getpass(3) */
static int get_password(char *buf, size_t len)
{
	struct termios old, new;
	int nread;

	if (tcgetattr(STDIN_FILENO, &old)) {
		return -1;
	}

	new = old;
	new.c_lflag &= ~ECHO;

	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new)) {
		return -1;
	}

	nread = read(STDIN_FILENO, buf, len - 1);
	if (nread <= 0) {
		return -1;
	}
	buf[nread] = '\0'; /* Safe */
	if (nread > 1 && buf[nread - 1] == '\n') {
		buf[nread - 1] = '\0';
	}
	if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &old)) {
		return -1;
	}

	fprintf(stderr, "\n");
	return 0;
}

static struct timeval ctcp_ping_time;

static void handle_irc_msg(struct irc_client *client, struct irc_msg *msg)
{
	if (msg->numeric) {
		switch (msg->numeric) {
			/* 1 to 5 */
			case RPL_WELCOME:
			case RPL_YOURHOST:
			case RPL_CREATED:
			case RPL_MYINFO:
			case RPL_ISUPPORT:
				irc_print("%s\n", msg->body);
				break;
			/* 250 to 255 */
			case RPL_STATSDLINE:
			case RPL_LUSERCLIENT:
			case RPL_LUSEROP:
			case RPL_LUSERUNKNOWN:
			case RPL_LUSERCHANNELS:
			case RPL_LUSERME:
			/* 265 to 266 */
			case RPL_LOCALUSERS:
			case RPL_GLOBALUSERS:
				irc_print("%s\n", msg->body);
				break;
			/* 375, 372, 376 */
			case RPL_MOTDSTART:
			case RPL_MOTD:
			case RPL_ENDOFMOTD:
				irc_print("%s\n", msg->body);
				break;
			/* 353, 366 */
			case RPL_NAMREPLY:
			case RPL_ENDOFNAMES:
				irc_print("%s\n", msg->body);
				break;
			case RPL_VISIBLEHOST: /* 396 */
				irc_print("%s\n", msg->body);
				break;
			case RPL_LISTSTART: /* 321-323 */
			case RPL_LIST:
			case RPL_LISTEND:
				irc_print("%s\n", msg->body);
				break;
			case ERR_NOTEXTTOSEND: /* 412 */
				irc_print("%s %s\n", msg->prefix, msg->body);
				break;
			case ERR_CANNOTSENDTOCHAN: /* 404 */
			case ERR_UNKNOWNCOMMAND: /* 421 */
				irc_print("%s%s %s%s\n", COLOR_RED, msg->prefix, msg->body, COLOR_RESET);
				break;
			/* Intentionally complain if we haven't explicitly handled a numeric, so we can choose how to best handle it */
			default:
				client_log(IRC_LOG_WARN, "Unhandled numeric: prefix: %s, num: %d, body: %s\n", msg->prefix, msg->numeric, msg->body);
		}
		return;
	}
	/* else, it's a command */
	if (!msg->command) {
		assert(0);
	}
	if (!strcmp(msg->command, "PRIVMSG") || !strcmp(msg->command, "NOTICE")) { /* This is intentionally first, as it's the most common one. */
		/* NOTICE is same as PRIVMSG, but should never be acknowledged (replied to), to prevent loops, e.g. for use with bots. */
		char *channel, *body = msg->body;

		/* Format of msg->body here is CHANNEL :BODY */
		channel = strsep(&body, " ");
		body++; /* Skip : */

		/* Mentions, e.g. jsmith: you there? */
		if (!do_not_disturb && !strncasecmp(body, irc_client_nickname(client), strlen(irc_client_nickname(client)))) {
			irc_print("\a"); /* Ring the bell to grab the user's attention, s/he just got mentioned */
		}

		if (*body == 0x01) { /* sscanf stripped off the leading : */
			/* CTCP command: known extended data = ACTION, VERSION, TIME, PING, DCC, SED, etc. */
			/* Remember: CTCP requests use PRIVMSG, responses use NOTICE! */
			char *tmp, *ctcp_name;
			enum irc_ctcp ctcp;

			body++; /* Skip leading \001 */
			if (!*body) {
				client_log(IRC_LOG_ERR, "Nothing after \\001?\n");
				return;
			}
			/* Don't print the trailing \001 */
			tmp = strchr(body, 0x01);
			if (tmp) {
				*tmp = '\0';
			} else {
				client_log(IRC_LOG_WARN, "Couldn't find trailing \\001?\n");
			}

			ctcp_name = strsep(&body, " ");

			tmp = strchr(msg->prefix, '!');
			if (tmp) {
				*tmp = '\0'; /* Strip everything except the nickname from the prefix */
			}

			ctcp = irc_ctcp_from_string(ctcp_name);
			if (ctcp < 0) {
				client_log(IRC_LOG_ERR, "Unsupported CTCP extended data type: %s\n", ctcp_name);
				return;
			}

			if (!strcmp(msg->command, "PRIVMSG")) {
				switch (ctcp) {
				case CTCP_ACTION: /* /me, /describe */
					irc_print("[ACTION] %s %s %s\n", msg->prefix, channel, body);
					break;
				case CTCP_VERSION:
					irc_client_ctcp_reply(client, msg->prefix, ctcp, CLIENT_VERSION);
					break;
				case CTCP_PING:
					irc_client_ctcp_reply(client, msg->prefix, ctcp, body); /* Reply with the data that was sent */
					break;
				case CTCP_TIME:
					{
						char timebuf[32];
						time_t nowtime;
						struct tm nowdate;

						nowtime = time(NULL);
						localtime_r(&nowtime, &nowdate);
						strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M:%S %P %Z", &nowdate);
						irc_client_ctcp_reply(client, msg->prefix, ctcp, timebuf);
					}
					break;
				default:
					client_log(IRC_LOG_ERR, "Unhandled CTCP extended data type: %s\n", ctcp_name);
				}
			} else { /* NOTICE (reply) */
				struct timeval tnow;
				double secs;
				switch (ctcp) {
				case CTCP_PING:
					/* XXX We don't keep track the ping reply is from the same user to whom we sent a ping request */
					gettimeofday(&tnow, NULL);
					secs = (1.0 * (tnow.tv_sec - ctcp_ping_time.tv_sec) * 1000000 + tnow.tv_usec - ctcp_ping_time.tv_usec) / 1000000;
					irc_print("Ping reply from %s in %.3f seconds\n", msg->prefix, secs);
					break;
				default:
					irc_print("CTCP %s reply %s from %s\n", ctcp_name, body, msg->prefix);
					break;
				}
			}
		} else {
			irc_print("%s %s %s\n", msg->prefix, channel, body);
		}
	} else if (!strcmp(msg->command, "PING")) {
		/* Reply with the same data that it sent us (some servers may actually require that) */
		int sres = irc_send(client, "PONG :%s", msg->body ? msg->body + 1 : ""); /* If there's a body, skip the : and bounce the rest back */
		if (sres) {
			return;
		}
	} else if (!strcmp(msg->command, "JOIN")) {
		irc_print("%s has %sjoined%s %s\n", msg->prefix, COLOR_GREEN, COLOR_RESET, msg->body);
	} else if (!strcmp(msg->command, "PART")) {
		irc_print("%s has %sleft%s %s\n", msg->prefix, COLOR_RED, COLOR_RESET, msg->body);
	} else if (!strcmp(msg->command, "QUIT")) {
		irc_print("%s has %squit%s %s\n", msg->prefix, COLOR_RED, COLOR_RESET, msg->body);
	} else if (!strcmp(msg->command, "KICKED")) {
		irc_print("%s has been %skicked%s %s\n", msg->prefix, COLOR_RED, COLOR_RESET, msg->body);
	} else if (!strcmp(msg->command, "NICK")) {
		char oldnick[64];
		char *tmp, *realnick;
		irc_print("%s is %snow known as%s %s\n", msg->prefix, COLOR_CYAN, COLOR_RESET, msg->body);
		strncpy(oldnick, msg->prefix, sizeof(oldnick) - 1);
		oldnick[sizeof(oldnick)] = '\0'; /* In case buffer is full */
		tmp = oldnick;
		realnick = strsep(&tmp, "!");
		if (realnick) {
			if (!strcmp(realnick, irc_client_nickname(client))) {
				/* We successfully updated our nickname */
				irc_client_set_nick(client, msg->body + 1); /* Skip leading : */
				update_prompt(client); /* If we changed our nick, update the prompt accordingly to reflect that */
			}
		}
	} else if (!strcmp(msg->command, "MODE")) {
		irc_print("%s %s\n", msg->prefix, msg->body);
	} else if (!strcmp(msg->command, "ERROR")) {
		irc_print("%s%s%s\n", COLOR_RED, msg->body, COLOR_RESET);
	} else if (!strcmp(msg->command, "TOPIC")) {
		irc_print("%s has %schanged the topic%s of %s\n", msg->prefix, COLOR_GREEN, COLOR_RESET, msg->body);
	} else {
		client_log(IRC_LOG_WARN, "Unhandled command: prefix: %s, command: %s, body: %s\n", msg->prefix, msg->command, msg->body);
	}
}

#define REQUIRED_PARAMETER(var, name) \
	if (!(var)) { \
		client_log(IRC_LOG_ERR, "Missing required parameter %s\n", name); \
		return -1; \
	}

#define REQUIRE_FG_CHANNEL() \
	if (!*fg_chan) { \
		client_log(IRC_LOG_WARN, "No current foreground channel. Type /help for help.\n"); \
		return -1; \
	}

static int handle_send_msg(struct irc_client **clientptr, char *input)
{
	int res = 0;
	char *channel, *msg = NULL, *s = input;
	struct irc_client *client = *clientptr;

	if (*s == '/') {
		/* IRC clients use /commands, but the IRC protocol itself doesn't have this concept */
		char *command;
		s++; /* Skip / */
		command = strsep(&s, " ");
		if (!strcasecmp(command, "help")) {
			printf("/help                     - Show client commands\n");
			printf("/debug                    - Set client debug level (0-10)\n");
			printf("/dnd                      - Toggle Do Not Disturb\n");
			printf("/fg                       - Set the foreground (default) channel for sending messages to\n");
			printf("/raw <MSG>                - Send a raw message to the server\n");
			printf("/quit [<MSG>]             - Quit from server with optional MSG\n");
			printf("/part <CHANS>             - Leave channel(s), comma-separated\n");
			printf("/join <CHANS>             - Join channel(s), comma-separated\n");
			printf("/msg <CHAN> <MSG>         - Send MSG to channel CHAN\n");
			printf("/notice <CHAN> <MSG>      - Send MSG to channel CHAN, inhibit autoresponses\n");
			printf("/me <ACTION>              - Send action msg to current foreground channel\n");
			printf("/describe <USER> <ACTION> - Send action msg for specified user\n");
			printf("/ctcp <TARGET> <CMD>      - Send CTCP command request to another user\n");
			printf("/nick <NICK>              - Change nickname to NICK\n");
			printf("/topic <CHAN> <TOPIC>     - Set channel CHAN's topic to TOPIC\n");
			printf("/lsit [<CHANS>]           - List channels on server (with optional filter of comma-separated channels)\n");
			printf("/invite <NICK> <CHAN>     - Invite user NICK to channel CHAN\n");
			printf("/identify <USER> <PASS>   - Authenticate to the server if not authenticated already.\n");
			printf("/server <HOST> <PORT>     - Connect to an IRC server, if not already connected to one.\n");
			printf("^C                        - Exit client\n");
		} else if (!strcasecmp(command, "debug")) {
			int level;
			msg = strsep(&s, " ");
			REQUIRED_PARAMETER(msg, "level");
			level = atoi(msg);
			if (level >= 0 && level <= 10) {
				debug_level = level;
				irc_print("Debug level is now %d\n", debug_level);
			}
		} else if (!strcasecmp(command, "dnd")) {
			do_not_disturb = do_not_disturb ? 0 : 1;
			irc_print("Do Not Disturb is now %s\n", do_not_disturb ? "enabled" : "disabled");
		} else if (!strcasecmp(command, "fg")) {
			/* Set the foreground channel */
			channel = strsep(&s, " "); /* Even if *s is NULL, this is actually safe. See strsep(3) */
			set_fg_chan(channel);
			update_prompt(client); /* Foreground channel changed */
		} else {
			/* If not connected to a server, then the only other permissible operation is to connect to one. */
			if (!strcasecmp(command, "server")) {
				int port = 0, flags = 0;
				const char *portstr, *server = strsep(&s, " ");
				REQUIRED_PARAMETER(server, "hostname");
				portstr = strsep(&s, " ");
				if (portstr) {
					port = atoi(portstr);
				}
				/* XXX Attempt to guess whether or not we should use TLS based on the port */
				if (port && port > 6670) {
					flags |= IRC_CLIENT_USE_TLS;
					flags &= ~IRC_CLIENT_VERIFY_SERVER;
				}
				client = irc_client_new(server, port, "", ""); /* It's okay to pass a port of 0, this will default based on TLS or not */
				if (!client) {
					return -1;
				}
				/* Replace the original client with the new one */
				irc_client_destroy(*clientptr);
				*clientptr = client;
				if (flags) {
					res = irc_client_set_flags(client, flags);
				}
				res = irc_client_connect(client);
				/* Now, start the main loop to receive messages from the server */
				if (!res && pthread_create(&rx_thread_id, NULL, rx_thread, (void*) client)) {
					return -1;
				}
				update_prompt(client);
				return res;
			} else if (!irc_client_connected(client)) {
				client_log(IRC_LOG_ERR, "Not connected to a server, operation not permitted.\n");
				return -1;
			}
			if (!strcasecmp(command, "raw")) {
				res = irc_send(client, "%s", s); /* (For advanced users): Send raw IRC message: everything following /raw */
			} else if (!strcasecmp(command, "quit")) {
				/* Directly use s, since the quit message is whatever follows, if anything */
				res = irc_client_quit(client, s); /* Disconnect from server completely */
				/* Wait for server to close connection and kick us */
			/* part and join accept a comma-separated list. The library does not touch this. The IRC server itself handles this. */
			} else if (!strcasecmp(command, "part")) {
				res = irc_client_channel_leave(client, s); /* Explicitly leave channel(s) */
			} else if (!strcasecmp(command, "join")) {
				res = irc_client_channel_join(client, s); /* Explicitly join channel(s) */
			} else if (!strcasecmp(command, "msg")) {
				channel = strsep(&s, " ");
				REQUIRED_PARAMETER(s, "message"); /* if channel is NULL, so is s */
				res = irc_client_msg(client, channel, s);
			} else if (!strcasecmp(command, "notice")) {
				channel = strsep(&s, " ");
				REQUIRED_PARAMETER(s, "message");
				res = irc_client_notice(client, channel, s);
			} else if (!strcasecmp(command, "me")) {
				REQUIRE_FG_CHANNEL();
				res = irc_client_action(client, fg_chan, s);
			} else if (!strcasecmp(command, "describe")) {
				channel = strsep(&s, " ");
				REQUIRED_PARAMETER(s, "message");
				res = irc_client_action(client, channel, s);
			} else if (!strcasecmp(command, "ctcp")) {
				enum irc_ctcp ctcp;
				const char *ctcp_name;
				channel = strsep(&s, " ");
				REQUIRED_PARAMETER(channel, "target");
				ctcp_name = strsep(&s, " ");
				REQUIRED_PARAMETER(ctcp_name, "code");
				ctcp = irc_ctcp_from_string(ctcp_name);
				if (ctcp < 0) {
					return -1;
				}
				if (ctcp == CTCP_PING) {
					gettimeofday(&ctcp_ping_time, NULL);
				}
				res = irc_client_ctcp_request(client, channel, ctcp);
			} else if (!strcasecmp(command, "nick")) {
				msg = strsep(&s, " "); /* Okay to use strsep, since NICKs are only one word anyways */
				REQUIRED_PARAMETER(msg, "nickname");
				res = irc_client_change_nick(client, msg ? msg : ""); /* Explicitly join this channel */
			} else if (!strcasecmp(command, "topic")) {
				channel = strsep(&s, " ");
				REQUIRED_PARAMETER(channel, "channel");
				REQUIRED_PARAMETER(s, "topic");
				res = irc_client_set_channel_topic(client, channel, s);
			} else if (!strcasecmp(command, "list")) {
				res = irc_client_list_channels(client, s);
			} else if (!strcasecmp(command, "invite")) {
				const char *nickname = strsep(&s, " ");
				REQUIRED_PARAMETER(nickname, "nickname");
				channel = strsep(&s, " ");
				REQUIRED_PARAMETER(channel, "channel");
				res = irc_client_invite_user(client, nickname, channel);
			} else if (!strcasecmp(command, "identify")) {
				const char *password, *nickname = strsep(&s, " ");
				REQUIRED_PARAMETER(nickname, "nickname");
				password = strsep(&s, " ");
				REQUIRED_PARAMETER(password, "password");
				res = irc_client_auth(client, nickname, password, nickname);
				update_prompt(client);
			} else {
				client_log(IRC_LOG_WARN, "Invalid command: %s\n", command);
			}
		}
	} else {
		/* We don't have tabs in this client, just the concept of a "foreground" channel that is the currently default for sending to */
		REQUIRE_FG_CHANNEL();
		res = irc_client_msg(client, fg_chan, input); /* Send message to current foreground channel */
	}
	return res;
}

int main(int argc, char *argv[])
{
	int mainres = 0;
	char input[513];
	struct irc_client *client;
	int res, flags = 0;
	unsigned int port = 0;
	char passwordbuf[73];
	const char *server = NULL, *username = NULL, *autojoin = NULL, *fgchan = NULL;
	char *password = NULL; /* non-const so we can zero it out later */

	/* Parse options */
	static const char *getopt_settings = "?a:df:h:k:p:stu:V";
	int c;
	while ((c = getopt(argc, argv, getopt_settings)) != -1) {
		switch (c) {
		case '?':
			printf("%s\n\n", CLIENT_COPYRIGHT);
			printf("This is a simple IRC client for use with a single IRC server. It can also be used for debugging.\n");
			printf("There are 3 ways to use this program. Specify a server, username, and password to log in immediately.\n");
			printf("   You can specify just a server to connect to the server unauthenticated,\n");
			printf("   or specify nothing to just open the client without connecting to any server first.\n\n");
			printf("-a<chans>       Channels to autojoin on connect (comma-separated)\n");
			printf("-d              Increase debug level\n");
			printf("-f<chan>        Set foreground channel on connect\n");
			printf("-h<hostname>    IRC server hostname\n");
			printf("-k<password>    IRC password. For security reasons, you may omit this and provide on STDIN instead.\n");
			printf("-p<port>        IRC server port. If not provided, default is 6667 for plain text and 6697 for TLS.\n");
			printf("-s              Use SASL authentication. Some servers may require this.\n");
			printf("-t              Use TLS encryption. Recommended if supported by server (remember to use the right port).\n");
			printf("-u<username>    IRC username\n");
			printf("-V              Display version and exit\n");
			return -1;
		case 'a':
			autojoin = optarg;
			break;
		case 'd':
			if (debug_level >= 10) {
				fprintf(stderr, "Maximum debug level is %d\n", 10);
				return -1;
			}
			debug_level++;
			break;
		case 'f':
			fgchan = optarg;
			break;
		case 'h':
			server = optarg;
			break;
		case 'k':
			password = optarg;
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 's':
			flags |= IRC_CLIENT_USE_SASL;
			break;
		case 't':
			flags |= IRC_CLIENT_USE_TLS;
			flags &= ~IRC_CLIENT_VERIFY_SERVER;
			break;
		case 'u':
			username = optarg;
			break;
		case 'V':
			printf("%s\n", CLIENT_COPYRIGHT);
			return -1;
		}
	}

	printf("%s\n", CLIENT_COPYRIGHT); /* Initial identification */
	set_term_title(CLIENT_VERSION);

	if (username && !password && isatty(STDIN_FILENO)) { /* Read the password on STDIN, if user desires for privacy */
		fprintf(stderr, "Password for %s@%s: ", username, server);
		if (get_password(passwordbuf, sizeof(passwordbuf))) {
			fprintf(stderr, "Password not provided, and failed to read interactively\n");
			return -1;
		}
		password = passwordbuf;
	}

	if (pipe(iopipe)) { /* Create a pipe for buffering output. Need to do this before logging is set up. */
		fprintf(stderr, "Failed to create pipe: %s\n", strerror(errno));
		return -1;
	}

	if (debug_level) {
		printf("IRC client started with debug level %d\n", debug_level);
	}
	irc_log_callback(__client_log); /* Set up logging */

	/* Create a single, new client */
	if (server && port) {
		/* We already have connection info. Connect to the server immediately. */
		client = irc_client_new(server, port, username ? username : "", password ? password : ""); /* If port is 0, that's fine, the library will default it properly. */
		if (!client) {
			mainres = -1;
			goto closepipes;
		}

		update_prompt(client);

		/* Set client connection flags */
		res = irc_client_set_flags(client, flags);
		if (res) {
			mainres = -1;
			goto closepipes;
		}

		irc_client_autojoin(client, autojoin); /* Set channels to join automatically on login */
		res = irc_client_connect(client); /* Actually connect */
		if (res) {
			mainres = -1;
			goto closepipes;
		}

		if (password) {
			/* As soon as we create the client, destroy the password, so it doesn't linger in memory. */
			if (password && password == passwordbuf) {
				memset(passwordbuf, 0, sizeof(passwordbuf));
			} else if (password) {
				memset(password, 0, strlen(password));
			}
			res = irc_client_login(client); /* Authenticate */
			if (res) {
				return -1;
			}

			if (fgchan) {
				set_fg_chan(fgchan);
			}
		}
		/* Now, start the main loop to receive messages from the server */
		if (pthread_create(&rx_thread_id, NULL, rx_thread, (void*) client)) {
			return -1;
		}
	} else {
		/* Start the client without being connected to anything. */
		client = irc_client_new("", 0, "", "");
		if (!client) {
			mainres = -1;
			goto closepipes;
		}
	}

	printf("=== IRC client is now ready. Press ^C to exit ===\n");
	set_term(); /* Disable canonical mode so we can read input char by char */
	signal(SIGINT, __sigint_handler);
	fully_started = 1;

	for (;;) {
		res = client_readline(input, sizeof(input) - 1);
		if (shutting_down) {
			printf("\nClient requested disconnect...\n");
			break;
		} else if (res <= 0) {
			printf("\nClient disconnected\n");
			break;
		} else {
			input[res] = '\0'; /* Safe */
			handle_send_msg(&client, input);
		}
	}

	printf("=== Client is exiting ===\n");

	/* Clean up, clean up, everybody clean up. */
	pthread_cancel(rx_thread_id);
	pthread_join(rx_thread_id, NULL);

	if (clientlog) {
		fclose(clientlog);
		clientlog = NULL;
	}
	irc_client_destroy(client); /* Destroy/free client */

closepipes:
	close(iopipe[0]);
	close(iopipe[1]);
	return mainres;
}
