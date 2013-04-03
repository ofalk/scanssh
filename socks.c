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

void socks_init(struct bufferevent *bev, struct argument *arg);
void socks_finalize(struct bufferevent *bev, struct argument *arg);

void socks5_readcb(struct bufferevent *bev, void *parameter);
void socks5_writecb(struct bufferevent *bev, void *parameter);
void socks5_errorcb(struct bufferevent *bev, short what, void *parameter);

void socks4_readcb(struct bufferevent *bev, void *parameter);
void socks4_writecb(struct bufferevent *bev, void *parameter);
void socks4_errorcb(struct bufferevent *bev, short what, void *parameter);

char *words[] = {
	"eerily",
	"bloodthirster",
	"negligence",
	"uncooping",
	"outsubtle",
	"saturnize",
	"unconclusiveness",
	"optological",
	"malabathrum",
	"leiomyosarcoma",
	"gristmill",
	"offendible",
	"pretyphoid",
	"banjo",
	"cossaean",
	"panhuman",
	"relive",
	"unquakerlike",
	"stupefier",
	"unkilled"
};

struct addr *socks_dst_addr = NULL;

void
socks_resolveaddress(char *name, ip_addr_t *address)
{
	struct addrinfo ai, *aitop;

	if (socks_dst_addr != NULL) {
		memcpy(address, &socks_dst_addr->addr_ip, sizeof(ip_addr_t));
		return;
	}

	memset(&ai, 0, sizeof (ai));
	ai.ai_family = AF_INET;
	ai.ai_socktype = 0;
	ai.ai_flags = 0;

	if (getaddrinfo(name, NULL, &ai, &aitop) != 0)
		err(1, "%s: getaddrinfo failed: %s", __func__, name);

	if ((socks_dst_addr = calloc(1, sizeof(struct addr))) == NULL)
		err(1, "%s: calloc", __func__);

	addr_ston(aitop->ai_addr, socks_dst_addr);
	freeaddrinfo(aitop);

	memcpy(address, &socks_dst_addr->addr_ip, sizeof(ip_addr_t));
}

char *
socks_getword(void)
{
	int off = rand_uint16(ss_rand) % (sizeof(words)/sizeof(char *));

	return words[off];
}

void
socks_makeurl(struct socks_state *socks)
{
	char *word = socks_getword();

	socks->port = 80;
	socks->word = word;
	snprintf(socks->domain, sizeof(socks->domain), "www.google.com");
}

int
socks_getaddress(struct bufferevent *bev, uint8_t type)
{
	uint8_t length;
	char *name;

	switch (type) {
	case SOCKS_ADDR_IPV4:
		if (EVBUFFER_LENGTH(bev->input) < 4)
			return (-1);
		evbuffer_drain(bev->input, 4);
		break;

	case SOCKS_ADDR_NAME:
		bufferevent_read(bev, &length, sizeof(length));
		if (EVBUFFER_LENGTH(bev->input) < length)
			return (-1);
		if ((name = malloc(length + 1)) == NULL)
			err(1, "%s: malloc", __func__);
		bufferevent_read(bev, name, length);
		name[length] = '\0';
		DFPRINTF((stderr, "Got: %s\n", name));
		free(name);
		break;

	default:
		return (-1);
	}

	/* Now get the port number */
	if (EVBUFFER_LENGTH(bev->input) < 2)
		return (-1);

	evbuffer_drain(bev->input, 2);
	return (0);
}

void
socks_bufferanalyse(struct bufferevent *bev, struct argument *arg)
{
	struct evbuffer *input = EVBUFFER_INPUT(bev);
	struct socks_state *socks = arg->a_state;
	size_t off;
	char response[32];
	char *p;
	
	if (!socks->gotheaders) {
		while ((p = evbuffer_find(input, "\n", 1)) != NULL) {
			off = (size_t)p - (size_t)EVBUFFER_DATA(input) + 1;
			if (off > 0 && *(p-1) == '\r')
				*(p-1) = '\0';
			*p = '\0';

			if (strlen(EVBUFFER_DATA(input)) == 0) {
				socks->gotheaders = 1;
				evbuffer_drain(input, off);
				break;
			} else {
				DFPRINTF((stderr, "Header: %s\n",
					     EVBUFFER_DATA(input)));
			}
			evbuffer_drain(input, off);
		}
	}

	if (!socks->gotheaders)
		return;

	if (evbuffer_find(input, "\r\n", 2) == NULL)
		return;

	if (evbuffer_find(input, socks->word, strlen(socks->word)) != NULL) {
		snprintf(response, sizeof(response),
		    "SOCKS v%d", socks->version);
		socks->success = 1;
		       
	} else {
		snprintf(response, sizeof(response),
		    "bad SOCKS v%d", socks->version);
	}
	postres(arg, response);
	scanhost_return(bev, arg, 1);
}

/* Scanner related functions */

void 
socks_init(struct bufferevent *bev, struct argument *arg)
{
	arg->a_flags = 0;
	if ((arg->a_state = calloc(1, sizeof(struct socks_state))) == NULL)
		err(1, "%s: calloc", __func__);
}

void 
socks_finalize(struct bufferevent *bev, struct argument *arg)
{
	free(arg->a_state);
	arg->a_state = NULL;
	arg->a_flags = 0;
}

void
socks5_readcb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;
	struct socks_state *socks = arg->a_state;
	uint8_t version[2];
	struct socks5_cmd cmd;
	uint8_t reply[4];
	
	DFPRINTF((stderr, "%s: called\n", __func__));

	switch (arg->a_flags) {
	case SOCKS_WAITING_RESPONSE:
		if (EVBUFFER_LENGTH(bev->input) != 2)
			goto error;

		bufferevent_read(bev, version, sizeof(version));
		DFPRINTF((stderr, "version: %d, response: %d\n",
		    version[0], version[1]));

		socks->version = version[0];
		socks->method = version[1];
		if (socks->version != 4 && socks->version != 5)
			goto error;
		if (socks->method != 0)
			goto error;
		
		socks_makeurl(socks);

		/* Now write our request */
		cmd.version = SOCKS_VERSION5;
		cmd.command = SOCKS_CMD_CONNECT;
		cmd.reserved = 0;
		cmd.addrtype = SOCKS_ADDR_IPV4;
		socks_resolveaddress(socks->domain, &cmd.address.s_addr);
		cmd.dstport = htons(socks->port);
		bufferevent_write(bev, &cmd, 4 + 4 + 2);

		bufferevent_disable(bev, EV_READ);
		arg->a_flags = SOCKS_SENDING_COMMAND;
		break;

	case SOCKS_WAITING_COMMANDRESPONSE:
		if (EVBUFFER_LENGTH(bev->input) < sizeof(reply))
			goto error;
		bufferevent_read(bev, reply, sizeof(reply));
		DFPRINTF((stderr, "Version: %d, Reply: %d\n",
		    reply[0], reply[1]));

		if (socks->version != reply[0])
			goto error;

		switch (reply[1]) {
		case SOCKS5_RESP_SUCCESS:
			break;
		case SOCKS5_RESP_FAILURE:
			postres(arg, "<error: server failure>");
			goto done;
		case SOCKS5_RESP_FORBIDDEN:
			postres(arg, "<error: forbidden>");
			goto done;
		case SOCKS5_RESP_NETUNREACH:
		case SOCKS5_RESP_HOSTUNREACH:
			postres(arg, "<error: unreachable>");
			goto done;
		default:
			postres(arg, "<error: response>");
			goto done;
		}

		/* Success, now look at address type */
		if (socks_getaddress(bev, reply[3]) == -1)
			goto error;

		arg->a_flags = SOCKS_SENDING_WEBREQUEST;
		bufferevent_disable(bev, EV_READ);

		http_makerequest(bev, arg, socks->word, 0);
		break;

	case SOCKS_READING_RESPONSE:
		socks_bufferanalyse(bev, arg);
		break;

	default:
		break;
	}

	return;

 error:
	postres(arg, "<socks5 proxy read error>");
 done:
	scanhost_return(bev, arg, 0);
}

void
socks5_writecb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;
	uint8_t version[3] = { 0x05, 0x01, 0x00 };

	DFPRINTF((stderr, "%s: called\n", __func__));

	switch (arg->a_flags) {
	case 0:
		arg->a_flags = SOCKS_WAITING_RESPONSE;
		bufferevent_write(bev, version, sizeof(version));
		break;
	case SOCKS_SENDING_COMMAND:
		arg->a_flags = SOCKS_WAITING_COMMANDRESPONSE;
		bufferevent_enable(bev, EV_READ);
		break;
	case SOCKS_SENDING_WEBREQUEST:
		arg->a_flags = SOCKS_READING_RESPONSE;
		bufferevent_enable(bev, EV_READ);
		break;
	default:
		break;
	}
}

void
socks5_errorcb(struct bufferevent *bev, short what, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	postres(arg, "<socks5 proxy error>");
	scanhost_return(bev, arg, 0);
}

void
socks4_readcb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;
	struct socks_state *socks = arg->a_state;
	struct socks4_cmd reply;
	
	DFPRINTF((stderr, "%s: called\n", __func__));

	switch (arg->a_flags) {
	case SOCKS_WAITING_COMMANDRESPONSE:
		if (EVBUFFER_LENGTH(bev->input) < sizeof(reply))
			goto error;
		bufferevent_read(bev, &reply, sizeof(reply));
		DFPRINTF((stderr, "Version: %d, Reply: %d\n",
		    reply.version, reply.command));

		if (0 != reply.version)
			goto error;

		switch (reply.command) {
		case SOCKS4_RESP_SUCCESS:
			break;
		case SOCKS4_RESP_FAILURE:
			postres(arg, "<socks4 proxy error: server failure>");
			goto done;
		case SOCKS4_RESP_NOIDENT:
			postres(arg, "<socks4 proxy error: no ident>");
			goto done;
		case SOCKS4_RESP_BADIDENT:
			postres(arg, "<socks4 proxy error: bad ident>");
			goto done;
		default:
			postres(arg, "<socks4 proxy error: response>");
			goto done;
		}

		arg->a_flags = SOCKS_SENDING_WEBREQUEST;
		bufferevent_disable(bev, EV_READ);

		http_makerequest(bev, arg, socks->word, 0);
		break;

	case SOCKS_READING_RESPONSE:
		socks_bufferanalyse(bev, arg);
		break;

	default:
		break;
	}

	return;

 error:
	postres(arg, "<socks4 proxy error>");
 done:
	scanhost_return(bev, arg, 0);
}

void
socks4_writecb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;
	struct socks_state *socks = arg->a_state;
	struct socks4_cmd cmd;

	socks->version = 4;
	socks->method = 0;
	
	DFPRINTF((stderr, "%s: called\n", __func__));

	switch (arg->a_flags) {
	case 0:
		/* Request the connection to be made */
		socks_makeurl(socks);

		cmd.version = SOCKS_VERSION4;
		cmd.command = SOCKS_CMD_CONNECT;
		cmd.dstport = htons(socks->port);
		socks_resolveaddress(socks->domain, &cmd.address.s_addr);

		bufferevent_write(bev, &cmd, sizeof(cmd));
		bufferevent_write(bev, socks->word, strlen(socks->word) + 1);

		arg->a_flags = SOCKS_WAITING_COMMANDRESPONSE;
		bufferevent_enable(bev, EV_READ);
		break;
	case SOCKS_SENDING_WEBREQUEST:
		arg->a_flags = SOCKS_READING_RESPONSE;
		bufferevent_enable(bev, EV_READ);
		break;
	default:
		break;
	}
}

void
socks4_errorcb(struct bufferevent *bev, short what, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	postres(arg, "<socks4 proxy error>");
	scanhost_return(bev, arg, 0);
}
