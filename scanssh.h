/*
 * Copyright 2000 Niels Provos <provos@citi.umich.edu>
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

#ifndef _SCANSSH_H_
#define _SCANSSH_H_

#include <sys/queue.h>

#define SSHMAPVERSION	"SSH-1.0-SSH_Version_Mapper\n"
#define SSHUSERAGENT	"ScanSSH/2.0"
#define MAXITER		10
#define LONGWAIT	50
#define SHORTWAIT	30
#define CONNECTWAIT	20
#define SYNWAIT		1
#define SYNRETRIES	7
#define MAXBUF		2048
#define MAXSYNQUEUESZ	4096
#define MAXSCANQUEUESZ	100
#define MAXBURST	256
#define SEEDLEN		4
#define EXPANDEDARGS	32000	/* number of expanded addresses */
#define MAXSLOTS	8	/* number of slots addrs are alloced from */

#define FLAGS_USERANDOM		0x01
#define FLAGS_SUBTRACTEXCLUDE	0x02

struct socks_host {
	TAILQ_ENTRY(socks_host) next;
	struct addr host;
	uint16_t port;
};

TAILQ_HEAD(socksq, socks_host);

struct argument;

struct address_slot {
	struct argument *slot_base;
	uint32_t slot_size;
	uint32_t slot_ref;
};

struct argument;

struct port_scan {
	struct argument *arg;
	uint16_t port;
	uint8_t count;
	uint8_t flags;
	
	struct event ev;
};

#define PORT_CHECKED	0x0001

/* Bloated port structure */

struct port {
	uint16_t port;
	struct port_scan *scan;
};

struct argument {
	SPLAY_ENTRY (argument) a_node;
	TAILQ_ENTRY (argument) a_next;

	uint16_t a_retry;		/* what a waste of memory */

	struct port *a_ports;		/* list of ports to scan */
	uint16_t a_nports;		/* number of ports left to scan */
	uint16_t a_hasports;

	uint32_t a_seqnr;

	struct addr addr;
	int a_fd;

	uint16_t a_flags;		/* state that scanners can use */
	void *a_state;			/* opaque state for scanners */

	struct scanner *a_scanner;	/* which scanner to use */
	int a_scanneroff;		/* offset into scan structure */

	struct address_slot *a_slot;

	char *a_res;			/* last posted result */

	struct event ev;
};

TAILQ_HEAD (queue_list, argument);

struct scanner {
	char *name;
	char *description;
	void (*init)(struct bufferevent *, struct argument *);
	void (*finalize)(struct bufferevent *, struct argument *);
	evbuffercb readcb;
	evbuffercb writecb;
	everrorcb  errorcb;
};

int synprobe_send(struct addr *, struct addr *, uint16_t, uint32_t *);

ssize_t atomicio(ssize_t (*)(), int, void *, size_t);
int ipv4toa(char *, size_t, void *);
void waitforcommands(int, int);

void argument_free(struct argument *);
void postres(struct argument *, const char *fmt, ...);
void printres(struct argument *, uint16_t, char *);

int probe_haswork(void);

int ports_parse(char *, struct port **, int *);
int ports_setup(struct argument *, struct port *, int);
int ports_remove(struct argument *, uint16_t);
struct port *ports_find(struct argument *, uint16_t);
int ports_isalive(struct argument *);
void ports_markchecked(struct argument *, struct port *);

void scanhost_ready(struct argument *);

void scanhost_return(struct bufferevent *bev, struct argument *, int success);
void scanhost_fromlist(void);

int scanner_parse(char *);
struct scanner *scanner_find(char *);
void scanner_print(char *);

void http_makerequest(struct bufferevent *, struct argument *, const char *,
    int);

#endif /* _SCANSSH_H_ */
