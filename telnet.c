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
#include <err.h>

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

void telnet_init(struct bufferevent *bev, struct argument *arg);
void telnet_finalize(struct bufferevent *bev, struct argument *arg);
void telnet_readcb(struct bufferevent *bev, void *parameter);
void telnet_writecb(struct bufferevent *bev, void *parameter);
void telnet_errorcb(struct bufferevent *bev, short what, void *parameter);

#define TELNET_WAITING_RESPONSE	0x0001
#define TELNET_WAITING_CONNECT	0x0002
#define TELNET_READING_CONNECT	0x0004
#define TELNET_WRITING_COMMAND	0x0008

int http_bufferanalyse(struct bufferevent *bev, struct argument *arg);

struct telnet_state {
	char *response;
	char *connect_wait;
};

#define CCPROXY		"CCProxy Telnet>"
#define GATEWAY1	"host_name:port"
#define GATEWAY2	"host[:port]:"
#define WINGATE		"WinGate>"

int
telnet_makeconnect(struct bufferevent *bev, struct argument *arg)
{
	extern struct addr *socks_dst_addr;
	struct evbuffer *input = EVBUFFER_INPUT(bev);
	struct telnet_state *state = arg->a_state;
	ip_addr_t address;

	socks_resolveaddress("www.google.com", &address);

	if (evbuffer_find(input, CCPROXY, strlen(CCPROXY)) != NULL) {
		state->response = "telnet-proxy: CCproxy";
		state->connect_wait = "OK!";
		evbuffer_add_printf(EVBUFFER_OUTPUT(bev),
		    "open %s:80\r\n", addr_ntoa(socks_dst_addr));
		bufferevent_enable(bev, EV_WRITE);
		return (1);
	} else if (evbuffer_find(input, GATEWAY1, strlen(GATEWAY1)) != NULL) {
		state->response = "telnet-proxy: Gateway";
		state->connect_wait = "Connected to:";
		evbuffer_add_printf(EVBUFFER_OUTPUT(bev),
		    "%s:80\r\n", addr_ntoa(socks_dst_addr));
		bufferevent_enable(bev, EV_WRITE);
		return (1);
	} else if (evbuffer_find(input, GATEWAY2, strlen(GATEWAY2)) != NULL) {
		state->response = "telnet-proxy: Gateway";
		/* 
		 * We do not get a connection confirmation, just the echoed
		 * string.  So, we wait for the echo and then send our command.
		 */
		state->connect_wait = ":80";
		evbuffer_add_printf(EVBUFFER_OUTPUT(bev),
		    "%s:80\r\n", addr_ntoa(socks_dst_addr));
		bufferevent_enable(bev, EV_WRITE);
		return (1);
	} else if (evbuffer_find(input, WINGATE, strlen(WINGATE)) != NULL) {
		state->response = "telnet-proxy: WinGate";
		state->connect_wait = "...Connected";
		evbuffer_add_printf(EVBUFFER_OUTPUT(bev),
		    "%s:80\r\n", addr_ntoa(socks_dst_addr));
		bufferevent_enable(bev, EV_WRITE);
		return (1);
	} else if (EVBUFFER_LENGTH(input) > 512) {
		return (-1);
	}

	return (0);
}

/* Scanner related functions */

void 
telnet_init(struct bufferevent *bev, struct argument *arg)
{
	if ((arg->a_state = calloc(1, sizeof(struct telnet_state))) == NULL)
		err(1, "%s: calloc", __func__);
	arg->a_flags = 0;
}

void 
telnet_finalize(struct bufferevent *bev, struct argument *arg)
{
	free(arg->a_state);
	arg->a_state = NULL;
	arg->a_flags = 0;
}

void
telnet_errorcb(struct bufferevent *bev, short what, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	postres(arg, "<telnet proxy error>");
	scanhost_return(bev, arg, 0);
}

/* TELNET Connect method */

void
telnet_readcb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;
	struct evbuffer *input = EVBUFFER_INPUT(bev);
	struct telnet_state *state = arg->a_state;

	DFPRINTF((stderr, "%s: called\n", __func__));

	if (arg->a_flags == 0) {
		int res = telnet_makeconnect(bev, arg);
		if (res == -1) {
			evbuffer_add(input, "", 1);
			printres(arg, arg->a_ports[0].port, 
			    EVBUFFER_DATA(input));
			scanhost_return(bev, arg, 0);
			return;
		} else if (res == 1) {
			arg->a_flags = TELNET_WAITING_CONNECT;
			bufferevent_disable(bev, EV_READ);
		}
	} else if (arg->a_flags & TELNET_READING_CONNECT) {
		if (evbuffer_find(input, state->connect_wait,
			strlen(state->connect_wait)) == NULL)
			return;
		evbuffer_drain(input, EVBUFFER_LENGTH(input));

		arg->a_flags = TELNET_WRITING_COMMAND;
		bufferevent_disable(bev, EV_READ);
		http_makerequest(bev, arg, socks_getword(), 0);
	} else if (arg->a_flags & TELNET_WAITING_RESPONSE) {
		int res = http_bufferanalyse(bev, arg);
		if (res == -1)
			return;
		if (res == 1) {
			postres(arg, state->response);
			scanhost_return(bev, arg, 1);
		}
	}

	return;
}

void
telnet_writecb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	if (arg->a_flags == 0) {
		return;
	} else if (arg->a_flags & TELNET_WAITING_CONNECT) {
		bufferevent_enable(bev, EV_READ);
		arg->a_flags = TELNET_READING_CONNECT;
	} else if (arg->a_flags & TELNET_WRITING_COMMAND) {
		bufferevent_enable(bev, EV_READ);
		arg->a_flags = TELNET_WAITING_RESPONSE;
	}
}

