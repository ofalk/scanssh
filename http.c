/*
 * Copyright 2000-2004 (c) Niels Provos <provos@citi.umich.edu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/tree.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include <event.h>
#include <dnet.h>

#include "scanssh.h"
#include "socks.h"

#ifdef DEBUG
extern int debug;
#define DFPRINTF(x)	if (debug) fprintf x
#else
#define DFPRINTF(x)
#endif

extern rand_t *ss_rand;

void http_init(struct bufferevent *bev, struct argument *arg);
void http_finalize(struct bufferevent *bev, struct argument *arg);
void http_readcb(struct bufferevent *bev, void *parameter);
void http_writecb(struct bufferevent *bev, void *parameter);
void http_errorcb(struct bufferevent *bev, short what, void *parameter);

#define HTTP_WAITING_RESPONSE	0x0001
#define HTTP_WAITING_CONNECT	0x0002
#define HTTP_READING_CONNECT	0x0004
#define HTTP_WRITING_COMMAND	0x0008
#define HTTP_GOT_HEADERS	0x0100
#define HTTP_GOT_OK		0x0200

#define HTTP10_OK "HTTP/1.0 200 "
#define HTTP11_OK "HTTP/1.1 200 "

int
http_response(char *line)
{
	if (strncasecmp(line, HTTP10_OK, strlen(HTTP10_OK)) &&
	    strncasecmp(line, HTTP11_OK, strlen(HTTP11_OK)))
		return (-1);
	return (0);
}


int
http_getheaders(struct bufferevent *bev, struct argument *arg)
{
	struct evbuffer *input = EVBUFFER_INPUT(bev);
	size_t off;
	char *p;

	while ((p = evbuffer_find(input, "\n", 1)) != NULL) {
		off = (size_t)p - (size_t)EVBUFFER_DATA(input) + 1;
		if (off > 1 && *(p-1) == '\r')
			*(p-1) = '\0';
		*p = '\0';

		if (strlen(EVBUFFER_DATA(input)) == 0) {
			arg->a_flags |= HTTP_GOT_HEADERS;
			evbuffer_drain(input, off);
			break;
		} else {
			DFPRINTF((stderr, "Header: %s\n",
				     EVBUFFER_DATA(input)));
		}

		/* Check that we got an okay */
		if (!(arg->a_flags & HTTP_GOT_OK)) {
			if (http_response(EVBUFFER_DATA(input)) == -1) {
				return (-1);
			}
			arg->a_flags |= HTTP_GOT_OK;
		}
		evbuffer_drain(input, off);
	}

	if ((arg->a_flags & HTTP_GOT_HEADERS) &&
	    !(arg->a_flags & HTTP_GOT_OK))
		return (-1);

	return (0);
}

int
http_bufferanalyse(struct bufferevent *bev, struct argument *arg)
{
	struct evbuffer *input = EVBUFFER_INPUT(bev);
	
	if (!(arg->a_flags & HTTP_GOT_HEADERS)) {
		if (http_getheaders(bev, arg) == -1) {
			postres(arg, "<error: response code>");
			scanhost_return(bev, arg, 0);
			return (-1);
		}
	}

	if (arg->a_flags & HTTP_GOT_HEADERS) {
		if (evbuffer_find(input, "\r\n", 2) == NULL)
			return (0);
	
		return (1);
	}

	return (0);
}

void
http_makerequest(struct bufferevent *bev, struct argument *arg,
    const char *word, int fqdn)
{
	extern struct addr *socks_dst_addr;
	ip_addr_t address;

	socks_resolveaddress("www.google.com", &address);
	evbuffer_add_printf(EVBUFFER_OUTPUT(bev),
	    "GET %s%s/search?hl=en&ie=UTF-8&oe=UTF-8&q=%s&btnG=Google+Search HTTP/1.0\r\n"
	    "Host: www.google.com\r\n"
	    "User-Agent: %s\r\n"
	    "\r\n", 
	    fqdn ? "http://" : "",
	    fqdn ? addr_ntoa(socks_dst_addr) : "",
	    word, SSHUSERAGENT);
	bufferevent_enable(bev, EV_WRITE);
}

void
http_makeconnect(struct bufferevent *bev, struct argument *arg)
{
	extern struct addr *socks_dst_addr;
	ip_addr_t address;

	socks_resolveaddress("www.google.com", &address);

	evbuffer_add_printf(EVBUFFER_OUTPUT(bev),
	    "CONNECT %s:80 HTTP/1.0\r\n"
	    "\r\n", addr_ntoa(socks_dst_addr), SSHUSERAGENT);
	bufferevent_enable(bev, EV_WRITE);
}

/* Scanner related functions */

void 
http_init(struct bufferevent *bev, struct argument *arg)
{
	arg->a_flags = 0;
}

void 
http_finalize(struct bufferevent *bev, struct argument *arg)
{
	arg->a_flags = 0;
}

void
http_readcb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	if (arg->a_flags & HTTP_WAITING_RESPONSE) {
		int res = http_bufferanalyse(bev, arg);
		if (res == -1)
			return;
		if (res == 1) {
			postres(arg, "http proxy");
			scanhost_return(bev, arg, 1);
		}
	}

	return;

	scanhost_return(bev, arg, 0);
}

void
http_writecb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	switch (arg->a_flags) {
	case 0:
		arg->a_flags = HTTP_WAITING_RESPONSE;
		http_makerequest(bev, arg, socks_getword(), 1);
		break;
	}
}

void
http_errorcb(struct bufferevent *bev, short what, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	postres(arg, "<http proxy error>");
	scanhost_return(bev, arg, 0);
}

/* HTTP Connect method */

void
http_connect_readcb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	if (arg->a_flags & HTTP_READING_CONNECT) {
		if (!(arg->a_flags & HTTP_GOT_HEADERS)) {
			if (http_getheaders(bev, arg) == -1) {
				postres(arg, "<error: response code>");
				scanhost_return(bev, arg, 0);
				return;
			}
		}

		if (arg->a_flags & HTTP_GOT_HEADERS) {
			arg->a_flags = HTTP_WRITING_COMMAND;
			http_makerequest(bev, arg, socks_getword(), 0);
			bufferevent_disable(bev, EV_READ);
			return;
		}
	} else if (arg->a_flags & HTTP_WAITING_RESPONSE) {
		int res = http_bufferanalyse(bev, arg);
		if (res == -1)
			return;
		if (res == -1) {
			postres(arg, "http connect proxy");
			scanhost_return(bev, arg, 1);
		}
	}

	return;

	scanhost_return(bev, arg, 0);
}

void
http_connect_writecb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	if (arg->a_flags == 0) {
		arg->a_flags = HTTP_WAITING_CONNECT;
		http_makeconnect(bev, arg);
		bufferevent_disable(bev, EV_READ);
	} else if (arg->a_flags & HTTP_WAITING_CONNECT) {
		bufferevent_enable(bev, EV_READ);
		arg->a_flags = HTTP_READING_CONNECT;
	} else if (arg->a_flags & HTTP_WRITING_COMMAND) {
		bufferevent_enable(bev, EV_READ);
		arg->a_flags = HTTP_WAITING_RESPONSE;
	}
}

