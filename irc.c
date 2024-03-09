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

/*! \file
 *
 * \brief TLS/SASL-capable IRC client library
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h> /* use sockaddr_in */
#include <netdb.h>
#include <arpa/inet.h>

/* Compile the library with TLS support, using OpenSSL */
#define HAVE_OPENSSL

#ifdef HAVE_OPENSSL
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef ROOT_CERT_PATH
#define ROOT_CERT_PATH "/etc/ssl/certs/ca-certificates.crt" /* Debian */
#endif /* ROOT_CERT_PATH */

#endif /* HAVE_OPENSSL */

#include <assert.h>

#define EXPOSE_IRC_MSG

/* Compiling without the headers installed in the system directories yet,
 * just use a relative path since it should be in the same directory. */
#include "irc.h"

/*! \brief A client for one IRC server. Use multiple clients for multiple servers or for multiple clients on the same server */
struct irc_client {
	int sfd;						/*!< Client socket file descriptor */
#ifdef HAVE_OPENSSL
	SSL*     ssl;
	SSL_CTX* ctx;
#endif
	const char *hostname;			/*!< IRC server hostname */
	unsigned int port;				/*!< IRC server port */
	const char *username;			/*!< IRC client username */
	const char *password;			/*!< IRC client password */
	char *nickname;					/*!< IRC client nickname */
	char *autojoin;					/*!< Comma-separated list of channels to autojoin */
	/* Flags */
	unsigned int tls:1;				/*!< Whether to use TLS */
	unsigned int tlsverify:1;		/*!< Whether to verify the server */
	unsigned int sasl:1;			/*!< Whether to use SASL authentication */
	/* Internal */
	unsigned int active:1;			/*!< Whether client is currently actively connected to a server */
	/* Flexible Struct Member */
	char data[];
};

static void (*log_callback)(enum irc_log_level level, int sublevel, const char *file, int line, const char *func, const char *msg) = NULL;

void irc_log_callback(void (*callback)(enum irc_log_level level, int sublevel, const char *file, int line, const char *func, const char *msg))
{
	log_callback = callback;
}

#define irc_err(fmt, ...) __irc_log(IRC_LOG_ERR, 0, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__)
#define irc_warn(fmt, ...) __irc_log(IRC_LOG_WARN, 0, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__)
#define irc_info(fmt, ...) __irc_log(IRC_LOG_INFO, 0, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__)
#define irc_debug(level, fmt, ...) __irc_log(IRC_LOG_DEBUG, level, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__)

static void __attribute__ ((format (gnu_printf, 6, 7))) __irc_log(enum irc_log_level level, int sublevel, const char *file, int line, const char *func, const char *fmt, ...)
{
	char *buf = NULL;
	int len = 0;
	va_list ap;

	if (!log_callback) {
		return;
	}

	/* Action Name and ID */
	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0 || !buf) {
		return; /* Can't log */
	}
	log_callback(level, sublevel, file, line, func, buf);
	free(buf);
}

struct irc_client *irc_client_new(const char *hostname, unsigned int port, const char *username, const char *password)
{
	struct irc_client *client;
	size_t hostlen, userlen, passlen;

	if (!hostname) {
		irc_err("Missing hostname\n");
		return NULL;
	} else if (!username) {
		irc_err("Missing username\n");
		return NULL;
	} else if (!password) {
		irc_err("Missing password\n");
		return NULL;
	}

	hostlen = strlen(hostname);
	userlen = strlen(username);
	passlen = strlen(password);

	/* Use a single allocation rather than strdup'ing each field */
	client = calloc(1, sizeof(*client) + hostlen + userlen + passlen + 3); /* 3 NULs */
	if (!client) {
		irc_err("calloc failed\n");
		return NULL;
	}

	client->port = port;
	client->sfd = -1;

	client->hostname = client->data;
	strcpy(client->data, hostname); /* Safe */
	client->username = client->hostname + hostlen + 1;
	strcpy(client->data + hostlen + 1, username); /* Safe */
	client->password = client->hostname + hostlen + userlen + 2;
	strcpy(client->data + hostlen + 1 + userlen + 1, password); /* Safe */

	client->nickname = strdup(client->username); /* Default nick to username */

	return client;
}

void irc_client_destroy(struct irc_client *client)
{
#ifdef HAVE_OPENSSL
	if (client->ssl) {
		SSL_shutdown(client->ssl);
		SSL_free(client->ssl);
		client->ssl = NULL;
	}
	if (client->ctx) {
		SSL_CTX_free(client->ctx);
		client->ctx = NULL;
	}
#endif
	if (client->sfd != -1) { /* If a client creates a client but never connects, this will be -1 at destroy time */
		close(client->sfd);
		client->sfd = -1;
	}
	if (client->autojoin) { /* If we added an autojoin but never actually authenticated, then this will still be set */
		free(client->autojoin);
	}
	if (client->nickname) {
		free(client->nickname);
	}
	free(client);
}

const char *irc_client_hostname(struct irc_client *client)
{
	return client->hostname;
}

const char *irc_client_username(struct irc_client *client)
{
	return client->username;
}

const char *irc_client_nickname(struct irc_client *client)
{
	return client->nickname;
}

int irc_client_connected(struct irc_client *client)
{
	return client->active;
}

int irc_client_autojoin(struct irc_client *client, const char *autojoin)
{
	if (client->autojoin) {
		free(client->autojoin);
	}
	if (!autojoin) {
		return 0; /* Deleting autojoin */
	}
	client->autojoin = strdup(autojoin);
	return client->autojoin ? 0 : -1;
}

#define SET_FLAG_IF_SET(client, flags, flag, flagname) \
	if (flags & flagname) { \
		irc_debug(6, "Client %p %s %d -> %d\n", client, #flagname, client->tls, 1); \
		client->flag = 1; \
	} else if (flags & ~flagname) { \
		irc_debug(6, "Client %p %s %d -> %d\n", client, #flagname, client->tls, 0); \
		client->flag = 0; \
	}

int irc_client_set_flags(struct irc_client *client, int flags)
{
	SET_FLAG_IF_SET(client, flags, tls, IRC_CLIENT_USE_TLS);
	SET_FLAG_IF_SET(client, flags, tlsverify, IRC_CLIENT_VERIFY_SERVER);
	SET_FLAG_IF_SET(client, flags, sasl, IRC_CLIENT_USE_SASL);
#ifndef HAVE_OPENSSL
	if (client->tls) {
		client->tls = 0;
		irc_err("TLS is not supported (OpenSSL unavailable)\n");
		return -1;
	}
#endif
	if (client->sasl && !client->tls) {
		irc_warn("SASL authentication without TLS is not secure\n");
	}
	if (client->tlsverify && !client->tls) {
		client->tlsverify = 0;
		irc_err("Cannot verify server when TLS is disabled\n");
		return -1;
	}
	return 0;
}

int irc_client_connect(struct irc_client *client)
{
	char ip[256];
	int e;
	struct addrinfo hints, *res, *ai;
	struct sockaddr_in *saddr_in; /* IPv4 */
	struct sockaddr_in6 *saddr_in6; /* IPv6 */

	if (client->sfd != -1) {
		irc_err("IRC client %p is currently connected (socket fd %d)\n", client, client->sfd);
		return -1;
	}

	if (!client->port) {
		client->port = client->tls ? IRC_DEFAULT_TLS_PORT : IRC_DEFAULT_PORT;
	}

	/* Resolve the hostname */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* TCP */

	e = getaddrinfo(client->hostname, NULL, &hints, &res);
	if (e) {
		irc_err("getaddrinfo (%s): %s\n", client->hostname, gai_strerror(e));
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		ip[0] = '\0'; /* Avoid possibly uninitialized usage warning */
		if (ai->ai_family == AF_INET) {
			saddr_in = (struct sockaddr_in *) ai->ai_addr;
			saddr_in->sin_port = htons((uint16_t) client->port);
			inet_ntop(ai->ai_family, &saddr_in->sin_addr, ip, sizeof(ip)); /* Print IPv4*/
		} else if (ai->ai_family == AF_INET6) {
			saddr_in6 = (struct sockaddr_in6 *) ai->ai_addr;
			saddr_in6->sin6_port = htons((uint16_t) client->port);
			inet_ntop(ai->ai_family, &saddr_in6->sin6_addr, ip, sizeof(ip)); /* Print IPv6 */
		}
		if (!strcmp(ip, "130.185.232.126")) {
			continue; /* Bad IP for libera chat */
		}
		client->sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (client->sfd == -1) {
			irc_err("socket: %s\n", strerror(errno));
			continue;
		}
		irc_info("Attempting %s connection to %s:%d\n", client->tls ? "secure" : "insecure", ip, client->port);
		if (connect(client->sfd, ai->ai_addr, ai->ai_addrlen)) {
			irc_err("connect: %s\n", strerror(errno));
			close(client->sfd);
			client->sfd = -1;
			continue;
		}
		break; /* Use the 1st one that works */
	}

	freeaddrinfo(res);
	if (client->sfd == -1) {
		return -1;
	}

	irc_debug(1, "Connected to %s:%d\n", client->hostname, client->port);

#ifdef HAVE_OPENSSL
	if (client->tls) {
		X509 *server_cert;
		long verify_result;
		char *str;

		OpenSSL_add_ssl_algorithms();
		SSL_load_error_strings();
		client->ctx = SSL_CTX_new(TLS_client_method());
		if (!client->ctx) {
			irc_err("Failed to setup new SSL context\n");
			return -1;
		}
		SSL_CTX_set_verify(client->ctx, SSL_VERIFY_PEER, NULL);
		SSL_CTX_load_verify_locations(client->ctx, ROOT_CERT_PATH, NULL);
		SSL_CTX_set_options(client->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3); /* Only use TLS */
		client->ssl = SSL_new(client->ctx);
		if (!client->ssl) {
			irc_err("Failed to create new SSL\n");
			SSL_CTX_free(client->ctx);
			client->ctx = NULL;
			return -1;
		}

		if (SSL_set_fd(client->ssl, client->sfd) != 1) {
			irc_err("Failed to connect SSL: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto sslcleanup;
		}
		if (SSL_connect(client->ssl) == -1) {
			irc_err("Failed to connect SSL: %s\n", ERR_error_string(ERR_get_error(), NULL));
			goto sslcleanup;
		}
		/* Verify cert */
		server_cert = SSL_get_peer_certificate(client->ssl);
		if (!server_cert) {
			irc_err("Failed to get peer certificate\n");
			goto sslcleanup;
		}
		str = X509_NAME_oneline(X509_get_subject_name(server_cert), 0, 0);
		if (!str) {
			irc_err("Failed to get peer certificate\n");
			goto sslcleanup;
		}
		irc_debug(8, "TLS SN: %s\n", str);
		OPENSSL_free(str);
		str = X509_NAME_oneline(X509_get_issuer_name (server_cert), 0, 0);
		if (!str) {
			irc_err("Failed to get peer certificate\n");
			goto sslcleanup;
		}
		irc_debug(8, "TLS Issuer: %s\n", str);
		OPENSSL_free(str);
		X509_free(server_cert);
		verify_result = SSL_get_verify_result(client->ssl);
		if (verify_result != X509_V_OK) {
			if (client->tlsverify) {
				irc_err("SSL verify failed: %ld (%s)\n", verify_result, X509_verify_cert_error_string(verify_result));
				goto sslcleanup; /* If told to verify, then this is fatal */
			}
			irc_warn("SSL verify failed: %ld (%s)\n", verify_result, X509_verify_cert_error_string(verify_result));
		} else {
			irc_debug(4, "TLS verification successful\n");
		}
	}
#endif

	client->active = 1;
	return 0;

sslcleanup:
#ifdef HAVE_OPENSSL
	SSL_CTX_free(client->ctx);
	SSL_free(client->ssl);
	client->ctx = NULL;
	client->ssl = NULL;
#endif
	close(client->sfd);
	return -1;
}

void irc_loop(struct irc_client *client, FILE *logfile, void (*cb)(void *data, struct irc_msg *msg), void *data)
{
	ssize_t res = 0;
	char readbuf[IRC_MAX_MSG_LEN + 1];
	struct irc_msg msg;
	char *prevbuf, *mybuf = readbuf;
	size_t prevlen, mylen = sizeof(readbuf) - 1;
	char *start, *eom;
	int rounds;

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
			mylen = sizeof(readbuf) - 1 - (size_t) (mybuf - readbuf);
			start = readbuf;
			if (mylen <= 1) { /* Couldn't shift, whole buffer was full */
				/* Could happen but this would not be valid. Abort read and reset. */
				irc_err("Buffer truncation!\n");
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
				mylen = prevlen - (size_t) res;
				goto begin; /* In a double loop, can't continue */
			}

			/* Got more than one message? */
			if (*(eom + 2)) {
				*(eom + 1) = '\0'; /* Null terminate before the next message starts */
			}

			memset(&msg, 0, sizeof(msg));
			if (logfile) {
				fprintf(logfile, "%s\n", start); /* Append to log file */
			}
			if (!irc_parse_msg(&msg, start) && !irc_parse_msg_type(&msg)) {
				cb(data, &msg);
			}

			mylen -= (unsigned long) (eom + 2 - mybuf);
			start = mybuf = eom + 2;
			rounds++;
		} while (mybuf && *mybuf);

		start = mybuf = readbuf; /* Reset to beginning */
		mylen = sizeof(readbuf) - 1;
	}
}

int irc_disconnect(struct irc_client *client)
{
	return shutdown(client->sfd, SHUT_RDWR);
}

int irc_poll(struct irc_client *client, int ms, int fd)
{
	int res;
	struct pollfd pfds[2];

	assert(client->sfd != -1);

	pfds[0].fd = client->sfd;
	pfds[0].events = POLLIN;

	if (fd != -1) {
		pfds[1].fd = fd;
		pfds[1].events = POLLIN;
	}

	for (;;) {
		pfds[0].revents = 0;
		pfds[1].revents = 0;
		res = poll(pfds, fd == -1 ? 1 : 2, ms);
		if (res < 0) {
			if (errno == EINTR) {
				continue;
			}
			irc_err("poll returned error: %s\n", strerror(errno));
			client->active = 0;
		}
		if (pfds[0].revents & POLLIN) {
			return 1;
		} else if (pfds[1].revents & POLLIN) {
			return 2;
		}
		if (pfds[0].revents) {
			irc_debug(1, "Exceptional poll activity on client fd\n");
		} else if (pfds[1].revents) {
			irc_debug(1, "Exceptional poll activity on custom fd\n");
		} else {
			return 0; /* Nothing happened */
		}
		break;
	}

	return -1;
}

ssize_t irc_read(struct irc_client *client, char *buf, size_t len)
{
	ssize_t bytes;
#ifdef HAVE_OPENSSL
	if (client->tls) {
		bytes = SSL_read(client->ssl, buf, len);
	} else
#endif
	{
		bytes = read(client->sfd, buf, len);
	}
	if (bytes > 0) {
		irc_debug(10, "<= %s %.*s", irc_client_hostname(client), (int) bytes, buf); /* Should already end in LF, additional one not needed */
	} else {
		irc_debug(1, "read returned %ld%s%s\n", bytes, bytes == -1 ? ": " : "", bytes == -1 ? strerror(errno) : "");
		client->active = 0;
	}
	return bytes;
}

ssize_t irc_write(struct irc_client *client, const char *buf, size_t len)
{
	const char *origbuf = buf;
	size_t origlen = len;
	size_t written = 0;

	/* All IRC commands must end in CR LF. If not, the command will fail. */
	if (len < 2 || *(buf + len - 2) != '\r' || *(buf + len - 1) != '\n') {
		irc_err("Message '%.*s' does not end in CR LF\n", (int) len, buf);
		return -1;
	}

	while (len > 0) {
		ssize_t res;
#ifdef HAVE_OPENSSL
		if (client->tls) {
			res = SSL_write(client->ssl, buf, len);
		} else
#endif
		{
			res = write(client->sfd, buf, len);
		}
		if (res <= 0) {
			written = res;
			break;
		}
		buf += res;
		len -= res;
		written += res;
	}
	if (written <= 0 || written != origlen) {
		irc_debug(1, "write returned %ld\n", written);
	}
	irc_debug(10, "=> %s [%lu] %.*s", irc_client_hostname(client), origlen, (int) origlen, origbuf); /* Don't add our own LF at the end, the message already ends in one */
	return written;
}

#define IRC_SEND_FIXED(client, s) irc_write(client, s "\r\n", strlen(s "\r\n"))

ssize_t __attribute__ ((format (gnu_printf, 2, 3))) irc_write_fmt(struct irc_client *client, const char *fmt, ...)
{
	ssize_t res;
	char buf[IRC_MAX_MSG_LEN + 1];
	int len = 0;
	va_list ap;

	assert(client->sfd != -1);
	if (!strstr(fmt, "\r\n")) {
		irc_err("Format string '%s' does not end in CR LF\n", fmt);
		return -1;
	}

	/* Action Name and ID */
	va_start(ap, fmt);
	/* No need for dynamic allocation, since a valid command is at most 512 bytes. */
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (len >= (int) sizeof(buf)) {
		irc_warn("Truncation occured trying to send %d-byte command\n", len);
	}

	res = irc_write(client, buf, (size_t) len);
	return res;
}

static char encoding_table[] =
{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
'w', 'x', 'y', 'z', '0', '1', '2', '3',
'4', '5', '6', '7', '8', '9', '+', '/'};

static int mod_table[] = {0, 2, 1};

/*! \brief Based on https://stackoverflow.com/questions/342409/how-do-i-base64-encode-decode-in-c/6782480#6782480 */
static char *base64_encode(const char *data, int input_length, int *outlen)
{
	char *encoded_data;
	int i, j, output_len;

	output_len = 4 * ((input_length + 2) / 3);
	encoded_data = malloc((size_t) output_len);
	if (!encoded_data) {
		return NULL;
	}

    for (i = 0, j = 0; i < input_length; ) {
        uint32_t octet_a = i < input_length ? (unsigned char) data[i++] : 0;
        uint32_t octet_b = i < input_length ? (unsigned char) data[i++] : 0;
        uint32_t octet_c = i < input_length ? (unsigned char) data[i++] : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (i = 0; i < mod_table[input_length % 3]; i++) {
        encoded_data[output_len - 1 - i] = '=';
	}

	*outlen = output_len;
    return encoded_data;
}

int irc_client_auth(struct irc_client *client, const char *username, const char *password, const char *realname)
{
	int res = 0;

	if (strchr(username, ' ')) {
		irc_err("IRC username %s is invalid\n", username);
		return -1;
	}

	/* PASS must be sent before both USER and JOIN, if it exists */
	if (password && *password) {
		res |= irc_send(client, "PASS %s", password); /* Password, if applicable (not actually used all that much) */
	}

	/* Confused about the difference between the two? See https://stackoverflow.com/questions/31666247/ */
	res |= irc_send(client, "NICK %s", username); /* Actual IRC nickname */
	res |= irc_send(client, "USER %s 0 * :%s", username, realname ? realname : username); /* User part of hostmask, mode, unused, real name for WHOIS */

	/* If we didn't already have a nickname set, set it now. */
	if (!*client->nickname) {
		irc_client_set_nick(client, username);
	}

	return res;
}

static int irc_client_nickserv_login(struct irc_client *client, const char *username, const char *password)
{
	int res = 0;

	if (strchr(username, ' ')) {
		irc_err("IRC username %s is invalid\n", username);
		return -1;
	}
	if (strchr(password, ' ')) {
		irc_err("IRC password is invalid\n");
		return -1;
	}

	/* Confused about the difference between the two? See https://stackoverflow.com/questions/31666247/ */
	res |= irc_send(client, "PRIVMSG NickServ :IDENTIFY %s %s", username, password); /* Actual IRC nickname */
	return 0;
}

static int wait_for_response(struct irc_client *client, char *buf, size_t len, int ms, const char *s)
{
	ssize_t bytes;
	for (;;) {
		int pres;
		pres = irc_poll(client, ms, -1);
		if (pres <= 0) {
			return -1;
		}
		/* Read it into the caller's buffer, so that if further checks
		 * need to be done when we return, they can be done. */
		bytes = irc_read(client, buf, len - 1);
		if (bytes <= 0) {
			return -1;
		}
		/* NUL terminate so we can use strstr */
		buf[bytes] = '\0'; /* Safe */
		printf("%s", buf); /* Print out whatever we received */
		if (strstr(buf, s)) {
			return 0;
		}
	}
	return -1;
}

static int do_sasl_auth(struct irc_client *client)
{
	int res, len, outlen;
	char *encoded;
	char decoded[256];
	char readbuf[256];

	/* General References:
	 * https://ircv3.net/specs/extensions/sasl-3.1.html */

	IRC_SEND_FIXED(client, "CAP LS 302"); /* Begin capability negotiation */
	if (irc_client_auth(client, client->username, NULL, NULL)) { /* Immediately send NICK and USER (but not PASS) */
		return -1;
	}
	if (wait_for_response(client, readbuf, sizeof(readbuf), 10000, "CAP * LS")) { /* Wait for CAP * LS response */
		return -1;
	}

	/*! \todo This is hardcoded to use PLAIN, we should properly support other modes as well
	 * For now this is a fine starting point, since with TLS this is not insecure. */
	if (!strstr(readbuf, "multi-prefix sasl") || !strstr(readbuf, "PLAIN")) {
		irc_err("Server does not support PLAIN authentication\n");
		return -1;
	}

	IRC_SEND_FIXED(client, "CAP REQ :multi-prefix sasl");
	if (wait_for_response(client, readbuf, sizeof(readbuf), 5000, "ACK")) { /* ACK :multi-prefix sasl */
		return -1;
	}
	IRC_SEND_FIXED(client, "AUTHENTICATE PLAIN"); /* This is secure if the connection is using TLS */

	if (wait_for_response(client, readbuf, sizeof(readbuf), 5000, "AUTHENTICATE +")) { /* Expect: AUTHENTICATE + */
		return -1;
	}

	/* Plain SASL: https://www.rfc-editor.org/rfc/rfc4616.html
	 * Base64 encode authentication identity, authorization identity, password (nick, name, password, separated by NUL, but not ending in it) */
	len = snprintf(decoded, sizeof(decoded), "%s%c%s%c%s", client->username, '\0', client->username, '\0', client->password);
	encoded = base64_encode(decoded, len, &outlen);
	if (!encoded) {
		irc_err("base64 encoding failed\n");
		return -1;
	}
	res = irc_send(client, "AUTHENTICATE %.*s", outlen, encoded);
	free(encoded);

	if (res || wait_for_response(client, readbuf, sizeof(readbuf), 5000, "903")) { /* Expect: 903... SASL authentication successful */
		return -1;
	}

	/* End capability negotiation */
	IRC_SEND_FIXED(client, "CAP END");
	return 0;
}

static int do_autojoin(struct irc_client *client)
{
	char *next, *all = client->autojoin;

	while ((next = strsep(&all, ","))) {
		irc_client_channel_join(client, next);
	}
	free(client->autojoin); /* This string has been eaten by strsep anyways, it's no longer useful */
	client->autojoin = NULL;
	return 0;
}

int irc_client_login(struct irc_client *client)
{
	if (client->sasl) { /* Some IRC servers require SASL from certain IPs to mitigate spam. */
		irc_debug(3, "Performing SASL authentication\n");
		if (do_sasl_auth(client)) {
			irc_err("SASL authentication failed\n");
			return -1;
		}
	} else if (client->password) { /* Authenticate to NickServ if we have a password */
		char readbuf[256];
		irc_debug(3, "Performing NickServ authentication\n");
		/* We can skip this if we authenticated with SASL, since SASL will log in us */
		if (irc_client_nickserv_login(client, client->username, client->password)) {
			irc_err("Failed to authenticate for username %s\n", client->username);
			return -1;
		}
		if (wait_for_response(client, readbuf, sizeof(readbuf), 5000, "You are now logged in")) { /* Expect: 900... You are now logged in as... */
			irc_err("Failed to get authentication response from NickServ\n");
			return -1;
		}
	} else {
		irc_err("Cannot authenticate in current state\n");
		return -1;
	}

	irc_info("Logged in to %s as %s successfully\n", client->hostname, client->username);

	/* Don't join any channels until we're fully logged in.
	 * This ensures that if we have a cloak, it gets applied, so we don't leak our IP address to other clients. */
	if (client->autojoin) {
		do_autojoin(client);
	}
	return 0;
}

/* A valid channel name starts with a symbol, not directly with an alphanumeric character */
#define VALID_CHANNEL_NAME(c) (!isalnum(*c))

int irc_client_channel_join(struct irc_client *client, const char *channel)
{
	if (!channel) {
		irc_err("Missing channel name(s)\n");
		return -1;
	}

	if (!VALID_CHANNEL_NAME(channel)) {
		irc_err("Channel name '%s' is invalid, must begin with a symbol\n", channel);
		return -1;
	}

	return irc_send(client, "JOIN %s", channel);
}

int irc_client_channel_leave(struct irc_client *client, const char *channel)
{
	if (!channel) {
		irc_err("Missing channel name(s)\n");
		return -1;
	}

	if (!VALID_CHANNEL_NAME(channel)) {
		irc_err("Channel name '%s' is invalid, must begin with a symbol\n", channel);
		return -1;
	}

	return irc_send(client, "PART %s", channel);
}

int irc_client_quit(struct irc_client *client, const char *msg)
{
	return irc_send(client, "QUIT :%s", msg ? msg : "");
}

int irc_client_msg(struct irc_client *client, const char *channel, const char *msg)
{
	/* When the last parameter is prefixed with a colon character,
	 * the value of that parameter will be the remainder of the message (including space characters)
	 * http://chi.cs.uchicago.edu/chirc/irc.html */
	return irc_send(client, "PRIVMSG %s :%s", channel, msg);
}

int irc_client_notice(struct irc_client *client, const char *channel, const char *msg)
{
	return irc_send(client, "NOTICE %s :%s", channel, msg);
}

int irc_client_pong(struct irc_client *client, struct irc_msg *msg)
{
	/* Reply with the same data that it sent us (some servers may actually require that) */
	return irc_send(client, "PONG :%s", irc_msg_body(msg) ? irc_msg_body(msg) + 1 : ""); /* If there's a body, skip the : and bounce the rest back */
}

const char *irc_ctcp_name(enum irc_ctcp_type ctcp)
{
	switch (ctcp) {
	case CTCP_ACTION:
		return "ACTION";
	case CTCP_VERSION:
		return "VERSION";
	case CTCP_TIME:
		return "TIME";
	case CTCP_PING:
		return "PING";
	case CTCP_DCC:
		return "DCC";
	default:
		break;
	}
	return NULL;
}

enum irc_ctcp_type irc_ctcp_from_string(const char *s)
{
	if (!strcasecmp(s, "ACTION")) {
		return CTCP_ACTION;
	} else if (!strcasecmp(s, "VERSION")) {
		return CTCP_VERSION;
	} else if (!strcasecmp(s, "TIME")) {
		return CTCP_TIME;
	} else if (!strcasecmp(s, "PING")) {
		return CTCP_PING;
	} else if (!strcasecmp(s, "DCC")) {
		return CTCP_DCC;
	} else {
		irc_warn("Unknown CTCP code: %s\n", s);
		return CTCP_UNKNOWN;
	}
}

int irc_client_ctcp_request(struct irc_client *client, const char *user, enum irc_ctcp_type ctcp)
{
	const char *msg, *ctcp_name = irc_ctcp_name(ctcp);

	if (!ctcp_name) {
		irc_err("Unknown CTCP command\n");
		return -1;
	}

	switch (ctcp) {
		case CTCP_ACTION:
			irc_err("Use irc_client_action instead\n");
			return -1;
		case CTCP_PING:
			msg = "123456789";
			break;
		case CTCP_TIME:
		case CTCP_VERSION:
		case CTCP_DCC:
		default:
			msg = NULL;
			break;
	}

	return irc_send(client, "PRIVMSG %s :" "\x01" "%s%s%s" "\x01", user, ctcp_name, msg ? " " : "", msg ? msg : "");
}

int irc_client_ctcp_reply(struct irc_client *client, const char *username, enum irc_ctcp_type ctcp, const char *data)
{
	const char *ctcp_name = irc_ctcp_name(ctcp);

	if (!ctcp_name) {
		irc_err("Unknown CTCP command\n");
		return -1;
	}

	return irc_send(client, "NOTICE %s :" "\x01" "%s%s%s" "\x01", username, ctcp_name, data ? " " : "", data ? data : "");
}

int irc_client_action(struct irc_client *client, const char *channel, const char *msg)
{
	/* CTCP ACTION command
	 * https://www.irchelp.org/protocol/ctcpspec.html */
	return irc_send(client, "PRIVMSG %s :" "\x01" "ACTION %s" "\x01", channel, msg); /* Keep the \001's separate to avoid escaping subsequent text */
}

int irc_client_change_nick(struct irc_client *client, const char *nick)
{
	return irc_send(client, "NICK %s", nick);
}

int irc_client_set_nick(struct irc_client *client, const char *nick)
{
	if (client->nickname) {
		free(client->nickname);
	}
	client->nickname = strdup(nick);
	return client->nickname ? 0 : -1;
}

int irc_client_set_channel_topic(struct irc_client *client, const char *channel, const char *topic)
{
	return irc_send(client, "TOPIC %s :%s", channel, topic);
}

int irc_client_list_channels(struct irc_client *client, const char *channels)
{
	return irc_send(client, "LIST %s%s", channels && *channels ? ":" : "", channels);
}

int irc_client_invite_user(struct irc_client *client, const char *nickname, const char *channel)
{
	return irc_send(client, "INVITE %s %s", nickname, channel);
}

#define PARSE_CHANNEL() \
	/* Format of msg->body here is CHANNEL :BODY */ \
	msg->channel = strsep(&msg->body, " "); \
	if (msg->body && *msg->body == ':') { \
		msg->body++; /* Skip : */ \
	}

int irc_parse_msg_type(struct irc_msg *msg)
{
	const char *c;

	/* We start off with msg->type as IRC_UNPARSED */

	if (msg->numeric) {
		msg->type = IRC_NUMERIC;
		return 0;
	}

	/* else, it's a command... or it should be.
	 * If it's not, the caller probably failed to call irc_parse_msg first. */
	if (!msg->command) {
		irc_err("Improper usage of %s\n", __func__);
		return -1;
	}

	c = msg->command;
	if (!strcasecmp(c, "PRIVMSG")) { /* This is intentionally first, as it's the most common one. */
		msg->type = IRC_CMD_PRIVMSG;
		PARSE_CHANNEL();
		if (*msg->body == 0x01) {
			msg->ctcp = 1;
		}
	} else if (!strcasecmp(c, "NOTICE")) {
		msg->type = IRC_CMD_NOTICE;
		PARSE_CHANNEL();
		if (*msg->body == 0x01) {
			msg->ctcp = 1;
		}
	} else if (!strcasecmp(c, "PING")) {
		msg->type = IRC_CMD_PING;
	} else if (!strcasecmp(c, "JOIN")) {
		msg->type = IRC_CMD_JOIN;
		PARSE_CHANNEL();
	} else if (!strcasecmp(c, "PART")) {
		msg->type = IRC_CMD_PART;
		PARSE_CHANNEL();
	} else if (!strcasecmp(c, "QUIT")) {
		msg->type = IRC_CMD_QUIT;
	} else if (!strcasecmp(c, "KICK")) {
		msg->type = IRC_CMD_KICK;
		PARSE_CHANNEL();
	} else if (!strcasecmp(c, "NICK")) {
		msg->type = IRC_CMD_NICK;
	} else if (!strcasecmp(c, "MODE")) {
		msg->type = IRC_CMD_MODE;
		PARSE_CHANNEL();
	} else if (!strcasecmp(c, "TOPIC")) {
		msg->type = IRC_CMD_TOPIC;
		PARSE_CHANNEL();
	} else if (!strcasecmp(c, "ERROR")) {
		msg->type = IRC_CMD_ERROR;
	} else {
		irc_debug(1, "Unhandled message type: %s\n", c);
		msg->type = IRC_CMD_OTHER;
	}
	return 0;
}

int irc_parse_msg_ctcp(struct irc_msg *msg)
{
	char *tmp, *ctcp_name;

	if (*msg->body != 0x01) {
		irc_err("Not a CTCP message\n");
		return -1;
	}

	if (!*++msg->body) {
		irc_err("Empty CTCP message\n");
		return -1;
	}

	tmp = strchr(msg->body, 0x01);
	if (!tmp) {
		irc_err("Unterminated CTCP message\n");
		return -1;
	}

	*tmp = '\0';

	ctcp_name = strsep(&msg->body, " ");
	if (!ctcp_name || !*ctcp_name) {
		return -1;
	}
	msg->ctcp_type = irc_ctcp_from_string(ctcp_name);
	if (msg->ctcp_type == CTCP_UNKNOWN) {
		irc_warn("Unsupported CTCP extended data type: %s\n", ctcp_name);
		return -1;
	}

	return 0;
}

/*! \brief Zero allocation message parsing */
int irc_parse_msg(struct irc_msg *msg, char *s)
{
	/* e.g. :tantalum.libera.chat 001 username :Welcome to the Libera.Chat Internet Relay Chat Network username */
	char *cur;
	int num;

	/* Parse message according to RFC 1459 2.3 */

	if (!s) {
		irc_err("Empty message?\n");
		return -1;
	}

	if (*s == ':') {
		/* Message begins with a prefix */
		cur = strsep(&s, " ");
		msg->prefix = cur + 1; /* Skip leading : */
	}

	if (!s) {
		irc_err("Missing command\n");
		return -1;
	} else if (isdigit(*s)) {
		cur = strsep(&s, " ");
		num = atoi(cur);
		msg->numeric = num;
	} else {
		/* Not a numeric message */
		cur = strsep(&s, " ");
		msg->command = cur;
	}
	/* Any parameters */
	if (s) {
		char *end;
		msg->body = s;
		end = strchr(s, '\0'); /* Presumably EOM */
		/* Trim trailing CR LF */
		if (end && end > s + 3) {
		/* OR, not AND, in case the LF is NUL terminated due to multiple message read */
			if (*(end - 1) == '\n' || *(end - 2) == '\r') {
				*(end - 2) = '\0';
			}
		}
	}
	return 0;
}

/* Accessor functions */

/*! \note Not const as callers may want to mutate it */
char *irc_msg_prefix(struct irc_msg *msg)
{
	return msg->prefix;
}

int irc_msg_numeric(struct irc_msg *msg)
{
	return msg->numeric;
}

const char *irc_msg_command(struct irc_msg *msg)
{
	return msg->command;
}

enum irc_msg_type irc_msg_type(struct irc_msg *msg)
{
	return msg->type;
}

int irc_msg_is_ctcp(struct irc_msg *msg)
{
	return msg->ctcp;
}

enum irc_ctcp_type irc_msg_ctcp_type(struct irc_msg *msg)
{
	return msg->ctcp_type;
}

const char *irc_msg_channel(struct irc_msg *msg)
{
	return msg->channel;
}

/*! \note Not const, because it's the caller's memory, and the caller
 * might want to mutate the body for ease of further parsing */
char *irc_msg_body(struct irc_msg *msg)
{
	return msg->body;
}
