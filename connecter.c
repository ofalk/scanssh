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
#include <unistd.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <ctype.h>
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


/* Global imports */

extern struct queue_list readyqueue;
extern int ssh_sendident;
extern char *ssh_ipalias;

extern struct scanner **ss_scanners;
extern int ss_nscanners;

extern struct socksq socks_host;

extern rand_t *ss_rand;

/* Local globals */
int scan_nhosts;		/* Number of hosts that we are scanning */

#define HTTP_SCAN	"HEAD /index.html HTTP/1.0\n\n"

void ssh_init(struct bufferevent *bev, struct argument *arg);
void ssh_finalize(struct bufferevent *bev, struct argument *arg);
void ssh_readcb(struct bufferevent *bev, void *parameter);
void ssh_writecb(struct bufferevent *bev, void *parameter);
void ssh_errorcb(struct bufferevent *bev, short what, void *parameter);

void socks_init(struct bufferevent *bev, struct argument *arg);
void socks_finalize(struct bufferevent *bev, struct argument *arg);

void socks5_readcb(struct bufferevent *bev, void *parameter);
void socks5_writecb(struct bufferevent *bev, void *parameter);
void socks5_errorcb(struct bufferevent *bev, short what, void *parameter);

void socks4_readcb(struct bufferevent *bev, void *parameter);
void socks4_writecb(struct bufferevent *bev, void *parameter);
void socks4_errorcb(struct bufferevent *bev, short what, void *parameter);

void http_init(struct bufferevent *bev, struct argument *arg);
void http_finalize(struct bufferevent *bev, struct argument *arg);
void http_readcb(struct bufferevent *bev, void *parameter);
void http_writecb(struct bufferevent *bev, void *parameter);
void http_errorcb(struct bufferevent *bev, short what, void *parameter);

void http_connect_readcb(struct bufferevent *bev, void *parameter);
void http_connect_writecb(struct bufferevent *bev, void *parameter);

void telnet_init(struct bufferevent *bev, struct argument *arg);
void telnet_finalize(struct bufferevent *bev, struct argument *arg);
void telnet_readcb(struct bufferevent *bev, void *parameter);
void telnet_writecb(struct bufferevent *bev, void *parameter);
void telnet_errorcb(struct bufferevent *bev, short what, void *parameter);

struct scanner scanners[] = {
	{
		"ssh",
		"finds versions for SSH, Web and SMTP servers",
		ssh_init,
		ssh_finalize,
		ssh_readcb,
		ssh_writecb,
		ssh_errorcb
	},
	{
		"socks5",
		"detects SOCKS v5 proxy",
		socks_init,
		socks_finalize,
		socks5_readcb,
		socks5_writecb,
		socks5_errorcb
	},
	{
		"socks4",
		"detects SOCKS v4 proxy",
		socks_init,
		socks_finalize,
		socks4_readcb,
		socks4_writecb,
		socks4_errorcb
	},
	{
		"http-proxy",
		"detects HTTP get proxy",
		http_init,
		http_finalize,
		http_readcb,
		http_writecb,
		http_errorcb
	},
	{
		"http-connect",
		"detects HTTP connect proxy",
		http_init,
		http_finalize,
		http_connect_readcb,
		http_connect_writecb,
		http_errorcb
	},
	{
		"telnet-proxy",
		"detects telnet proxy",
		telnet_init,
		telnet_finalize,
		telnet_readcb,
		telnet_writecb,
		telnet_errorcb
	},
	{
		NULL, NULL, NULL, NULL
	}
};

void
scanner_print(char *pre)
{
	struct scanner *myscan = &scanners[0];

	while (myscan->name != NULL) {
		fprintf(stderr, "%s%12s\t%s\n",
		    pre, myscan->name, myscan->description);
		myscan++;
	}
}

struct scanner *
scanner_find(char *scanner)
{
	struct scanner *myscan = &scanners[0];

	while (myscan->name != NULL) {
		if (strcmp(myscan->name, scanner) == 0)
			return (myscan);
		myscan++;
	}

	return (NULL);
}

#define SSH_DIDWRITE	0x0001
#define SSH_GOTREAD	0x0002

struct ssh_state {
	int nlines;
	char *firstline;
};

void 
ssh_init(struct bufferevent *bev, struct argument *arg)
{
	if ((arg->a_state = calloc(1, sizeof(struct ssh_state))) == NULL)
		err(1, "%s: calloc", __func__);

	arg->a_flags = 0;
}

void 
ssh_finalize(struct bufferevent *bev, struct argument *arg)
{
	struct ssh_state *state = arg->a_state;

	if (state->firstline)
		free(state->firstline);
	free(arg->a_state);
	arg->a_state = NULL;
	arg->a_flags = 0;
}

int
ssh_process_line(struct evbuffer *input, struct argument *arg)
{
	struct ssh_state *state = arg->a_state;
	while (1) {
		size_t off = 0;
		char *p = EVBUFFER_DATA(input);

		while (off < EVBUFFER_LENGTH(input)) {
			if (*p == '\r') {
				*p = '\0';
			} else if (*p == '\n') {
				*p = '\0';
				break;
			}
			p++;
			off++;
		}

		if (off == EVBUFFER_LENGTH(input))
			return (-1);

		off++;
		p = EVBUFFER_DATA(input);

		state->nlines++;
		if (state->firstline == NULL && isprint(*p))
			state->firstline = strdup(p);

		if (strncmp(p, "SSH-", 4) == 0) {
			postres(arg, p);
			return (1);
		} else if (strncasecmp(p, "Server: ", 8) == 0) {
			postres(arg, p + 8);
			return (1);
		}

		if (state->nlines > 50) {
			postres(arg, "<error: too many lines>");
			return (0);
		}

		evbuffer_drain(input, off);
	}
}

void
ssh_readcb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;
	int res;

	DFPRINTF((stderr, "%s: called\n", __func__));

	if ((res = ssh_process_line(EVBUFFER_INPUT(bev), arg)) == -1)
		return;

	if (res == 0) {
		ssh_errorcb(bev, EVBUFFER_READ | EVBUFFER_TIMEOUT, arg);
		return;
	}

	arg->a_flags |= SSH_GOTREAD;
	if (!ssh_sendident || (arg->a_flags & SSH_DIDWRITE))
		scanhost_return(bev, arg, 1);
	return;
}

void
ssh_writecb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	if (!ssh_sendident || (arg->a_flags & SSH_DIDWRITE)) {
		if (arg->a_flags & SSH_GOTREAD)
			scanhost_return(bev, arg, 1);
		return;
	}

	if (arg->a_ports[0].port == 80)
		bufferevent_write(bev, HTTP_SCAN, strlen(HTTP_SCAN));
	else
		bufferevent_write(bev, SSHMAPVERSION, sizeof(SSHMAPVERSION));
	arg->a_flags |= SSH_DIDWRITE;
}

void
ssh_errorcb(struct bufferevent *bev, short what, void *parameter)
{
	struct argument *arg = parameter;
	struct ssh_state *state = arg->a_state;
	int success = 0;

	if (state->firstline) {
		postres(arg, state->firstline);
		success = 1;
	} else {
		postres(arg, "<ssh error on %s:%s%s%s: %s>",
		    what & EV_READ ? "read" : "write",
		    what & EVBUFFER_ERROR ? " EV_ERROR" : "",
		    what & EVBUFFER_EOF ? " EV_EOF" : "",
		    what & EVBUFFER_TIMEOUT ? " EV_TIMEOUT" : "",
		    strerror(errno));
		success = 0;
	}
	scanhost_return(bev, arg, success);
}

/* Either connect or bind */

int
make_socket_ai(int (*f)(int, const struct sockaddr *, socklen_t),
    struct addrinfo *ai)
{
        struct linger linger;
        int fd, on = 1;

        /* Create listen socket */
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) {
                warn("socket");
                return (-1);
        }

        if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
                warn("fcntl(O_NONBLOCK)");
                goto out;
        }

        if (fcntl(fd, F_SETFD, 1) == -1) {
                warn("fcntl(F_SETFD)");
                goto out;
        }

        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof(on));
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &on, sizeof(on));
        linger.l_onoff = 1;
        linger.l_linger = 5;
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));

        if ((f)(fd, ai->ai_addr, ai->ai_addrlen) == -1) {
		if (errno != EINPROGRESS) {
			warn("%s", __func__);
			goto out;
		}
        }

	return (fd);

 out:
	close(fd);
	return (-1);
}

int
make_socket(int (*f)(int, const struct sockaddr *, socklen_t),
    char *address, uint16_t port)
{
        struct addrinfo ai, *aitop;
        char strport[NI_MAXSERV];
	int fd;
	
        memset(&ai, 0, sizeof (ai));
        ai.ai_family = AF_INET;
        ai.ai_socktype = SOCK_STREAM;
        ai.ai_flags = f != connect ? AI_PASSIVE : 0;
        snprintf(strport, sizeof (strport), "%d", port);
        if (getaddrinfo(address, strport, &ai, &aitop) != 0) {
                warn("getaddrinfo");
                return (-1);
        }
        
	fd = make_socket_ai(f, aitop);

	freeaddrinfo(aitop);

	return (fd);
}

int
scanhost_check_socketerror(struct argument *arg, short what)
{
	int error;
	socklen_t errsz = sizeof(error);
	int fd = arg->a_fd;

	if (what == EV_TIMEOUT) {
		postres(arg, "<timeout>");
		goto error;
	}

	/* Check if the connection completed */
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &errsz) == -1) {
		warn("%s: getsockopt for %d", __func__, fd);
		postres(arg, "<error: getsockopt>");
		goto error;
	}

	if (error) {
		if (error == ECONNREFUSED) {
			postres(arg, "<refused>");
		} else {
			warnx("%s: getsockopt: %s", __func__, strerror(error));
			postres(arg, "<errror: getsockopt>");
		}
		goto error;
	}

	return (0);

 error:
	scanhost_return(NULL, arg, 0);
	return (-1);
}

struct bufferevent *
scanhost_postconnect_setup(struct argument *arg)
{
	struct bufferevent *bev = NULL;
	int fuzz;

	/* We successfully connected to the host */

	bev = bufferevent_new(arg->a_fd,
	    arg->a_scanner->readcb,
	    arg->a_scanner->writecb,
	    arg->a_scanner->errorcb, arg);
	if (bev == NULL) {
		warnx("%s: bufferevent_new", __func__);
		postres(arg, "<error: memory>");
		goto error;
	}

	fuzz = rand_uint16(ss_rand) % 10;
	bufferevent_settimeout(bev, SHORTWAIT + fuzz, SHORTWAIT + fuzz);
	bufferevent_enable(bev, EV_READ|EV_WRITE);

	(*arg->a_scanner->init)(bev, arg);

	return (bev);

 error:
	scanhost_return(NULL, arg, 0);
	return (NULL);
}

void
scanhost_connectcb(int fd, short what, void *parameter)
{
	struct argument *arg = parameter;

	if (scanhost_check_socketerror(arg, what) == -1)
		return;

	scanhost_postconnect_setup(arg);
}

static void
socks_readcb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;
	struct bufferevent *newbev = NULL;
	struct socks4_cmd reply;
	
	DFPRINTF((stderr, "%s: called\n", __func__));

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
		postres(arg, "<socks error: server failure>");
		goto done;
	case SOCKS4_RESP_NOIDENT:
		postres(arg, "<socks error: no ident>");
		goto done;
	case SOCKS4_RESP_BADIDENT:
		postres(arg, "<socks error: bad ident>");
		goto done;
	default:
		postres(arg, "<socks error: response>");
		goto done;
	}

	/* We need to unregister the event's first due to a bug in libevent */
	bufferevent_disable(bev, EV_READ|EV_WRITE);

	/* Call the original connect callback to take care of the rest */
	if ((newbev = scanhost_postconnect_setup(arg)) != NULL) {
		evbuffer_add_buffer(newbev->input, bev->input);
		/*
		 * If we have more data buffered, the we need to append it
		 * to the new read buffer and if necessary call the read
		 * callback.
		 * Unfortunately, this assumes a lot about the internals of
		 * libevent.
		 */
		if (EVBUFFER_LENGTH(newbev->input))
			newbev->readcb(newbev, newbev->cbarg);
	}

	bufferevent_free(bev);
	return;

 error:
	postres(arg, "<socks read error>");

 done:
	bufferevent_free(bev);
	scanhost_return(NULL, arg, 0);
}

static void
socks_writecb(struct bufferevent *bev, void *parameter)
{
	struct argument *arg = parameter;
	struct socks4_cmd cmd;

	DFPRINTF((stderr, "%s: called\n", __func__));

	if (arg->a_flags != 0)
		return;

	/* Connect to the remote server */
	memset(&cmd, 0, sizeof(cmd));
	cmd.version = SOCKS_VERSION4;
	cmd.command = SOCKS_CMD_CONNECT;
	cmd.dstport = htons(arg->a_ports[0].port);
	memcpy(&cmd.address.s_addr, &arg->addr.addr_ip,
	    sizeof(struct in_addr));

	bufferevent_write(bev, &cmd, sizeof(cmd));
	bufferevent_write(bev, SSHUSERAGENT, sizeof(SSHUSERAGENT));

	arg->a_flags = SOCKS_WAITING_COMMANDRESPONSE;
	bufferevent_enable(bev, EV_READ);
}

void
socks_errorcb(struct bufferevent *bev, short what, void *parameter)
{
	struct argument *arg = parameter;

	DFPRINTF((stderr, "%s: called\n", __func__));

	postres(arg, "<socks error on %s:%s%s%s: %s>",
	    what & EV_READ ? "read" : "write",
	    what & EVBUFFER_ERROR ? " EV_ERROR" : "",
	    what & EVBUFFER_EOF ? " EV_EOF" : "",
	    what & EVBUFFER_TIMEOUT ? " EV_TIMEOUT" : "",
	    strerror(errno));
	bufferevent_free(bev),
	scanhost_return(NULL, arg, -1);
}

void
scanhost_socks_connectcb(int fd, short what, void *parameter)
{
	struct argument *arg = parameter;
	struct bufferevent *bev = NULL;

	if (scanhost_check_socketerror(arg, what) == -1)
		return;

	/* We successfully connected to the host */

	bev = bufferevent_new(arg->a_fd, socks_readcb, socks_writecb,
	    socks_errorcb, arg);
	if (bev == NULL) {
		warnx("%s: bufferevent_new", __func__);
		postres(arg, "<error: memory>");
		goto error;
	}

	bufferevent_settimeout(bev, 30, 30);
	bufferevent_disable(bev, EV_READ);
	bufferevent_enable(bev, EV_WRITE);

	arg->a_flags = 0;	

	return;

 error:
	scanhost_return(NULL, arg, 0);
	return;
}

int
scanhost(struct argument *arg)
{
	struct timeval tv;
	uint16_t port = arg->a_ports[0].port;
	void (*cb)(int, short, void *);

	arg->a_flags = 0;
	if (TAILQ_FIRST(&socks_host) == NULL) {
		arg->a_fd = make_socket(connect, addr_ntoa(&arg->addr), port);
		if (arg->a_fd == -1)
			return (-1);

		cb = scanhost_connectcb;
	} else {
		struct socks_host *single_host = TAILQ_FIRST(&socks_host);

		/* Rotate the entries around */
		TAILQ_REMOVE(&socks_host, single_host, next);
		TAILQ_INSERT_TAIL(&socks_host, single_host, next);

		arg->a_fd = make_socket(connect,
		    addr_ntoa(&single_host->host), single_host->port);
		if (arg->a_fd == -1)
			return (-1);
		cb = scanhost_socks_connectcb;
	}

	event_set(&arg->ev, arg->a_fd, EV_WRITE, cb, arg);

	timerclear(&tv);
	tv.tv_sec = LONGWAIT;
	event_add(&arg->ev, &tv);

	return (0);
}

/*
 * Success parameter:
 * -2 - scanner timeout, stop scanning and go to next host.
 * -1 - scanner reset?, stop scanning, go to next port.
 *  0 - current scanner failed, continue with next scanner
 *  1 - current scanner succeeded, stop scanning and report success
 */

void
scanhost_return(struct bufferevent *bev, struct argument *arg, int success)
{
	int done = 0;

	if (bev != NULL) {
		(*arg->a_scanner->finalize)(bev, arg);
		bufferevent_free(bev);
	}

	close(arg->a_fd);
	arg->a_fd = -1;
	scan_nhosts--;

	/*
	 * If we had success we remove the port, otherwise we attempt to
	 * use a different scanner on it.
	 */
	arg->a_scanneroff++;
	if (success == -2) {
		printres(arg, arg->a_ports[0].port, "<timeout>");

		/* timeout - host is down */
		while (arg->a_nports)
			ports_remove(arg, arg->a_ports[0].port);

	} else if (success == -1) {
		/* reset? */
		printres(arg, arg->a_ports[0].port, "<refused>");
		done = 1;

	} else if (bev != NULL && !success &&
	    arg->a_scanneroff < ss_nscanners) {
		arg->a_scanner = ss_scanners[arg->a_scanneroff];
	} else {
		printres(arg, arg->a_ports[0].port, arg->a_res);
		done = 1;
	}

	if (done) {
		arg->a_scanneroff = 0;
		arg->a_scanner = ss_scanners[0];
		ports_remove(arg, arg->a_ports[0].port);
	}

	if (arg->a_nports == 0) {
		argument_free(arg);
		if (TAILQ_FIRST(&readyqueue) == NULL && 
		    !probe_haswork() && !scan_nhosts) {
			struct timeval tv;
			timerclear(&tv);
			event_loopexit(&tv);
			return;
		}
		goto done;
	}

	/* 
	 * Insert at the beginning of the list, so that hosts get completed
	 * faster.  Otherwise, insertion at the end of a list causes the list
	 * to grow longer and longer without completing hosts.
	 */
	TAILQ_INSERT_HEAD(&readyqueue, arg, a_next);

 done:
	/* Cause another host to be contacted */
	scanhost_fromlist();
}

void
scanhost_ready(struct argument *arg)
{
	TAILQ_INSERT_TAIL(&readyqueue, arg, a_next);
	scanhost_fromlist();
}

void
scanhost_fromlist(void)
{
	extern int max_scanqueue_size;
	struct argument *arg;
	while (scan_nhosts < max_scanqueue_size &&
	    (arg = TAILQ_FIRST(&readyqueue)) != NULL) {

		/* Out of file descriptors, we need to try again later */
		if (scanhost(arg) == -1) {
			TAILQ_REMOVE(&readyqueue, arg, a_next);
			TAILQ_INSERT_TAIL(&readyqueue, arg, a_next);
			break;
		}

		TAILQ_REMOVE(&readyqueue, arg, a_next);
		scan_nhosts++;
	}
}
