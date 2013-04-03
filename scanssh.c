/*
 * ScanSSH - simple SSH version scanner
 *
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

#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <pcap.h>
#include <unistd.h>
#include <md5.h>
#include <stdarg.h>
#include <assert.h>

#include <event.h>
#include <dnet.h>

#include "scanssh.h"
#include "exclude.h"
#include "xmalloc.h"
#include "interface.h"

#ifndef howmany
#define howmany(x,y)	(((x) + ((y) - 1)) / (y))
#endif

#ifdef DEBUG
int debug = 0;
#define DFPRINTF(x)	if (debug) fprintf x
#define DNFPRINTF(y, x)	if (debug >= y) fprintf x
#else
#define DFPRINTF(x)
#define DNFPRINTF(y, x)
#endif

struct address_node {
	TAILQ_ENTRY (address_node) an_next;

	struct addr an_start;
	struct addr an_end;
	int an_bits;
};

struct generate {
	TAILQ_ENTRY (generate) gen_next;

	TAILQ_HEAD (an_list, address_node) gen_anqueue;

	int gen_flags;

	uint32_t gen_seed;		/* Seed for PRNG */

	uint32_t gen_bits;
	uint32_t gen_start;
	uint32_t gen_iterate;
	uint32_t gen_end;
	uint32_t gen_current;
	uint32_t gen_n;		/* successful generations */
	uint32_t gen_max;


	struct port *gen_ports;
	int gen_nports;
};

int populate(struct argument **, int *);
int next_address(struct generate *, struct addr *);

/* Globals */
struct interface *ss_inter;
rand_t *ss_rand;
ip_t   *ss_ip;

/* SOCKS servers via which we can scan */
struct socksq socks_host;

struct scanner **ss_scanners = NULL;
int ss_nscanners = 0;

struct argument *args;		/* global list of addresses */
int entries;			/* number of remaining addresses */

int ssh_sendident;		/* should we send ident to ssh server? */

struct port *ss_ports = NULL;	/* global list of ports to be scanned */
int ss_nports = 0;

int ss_nhosts = 0;		/* Number of addresses generated */

pcap_t *pd;
int rndexclude = 1;
struct timeval syn_start;
int syn_rate = 100;
int syn_nsent = 0;

int max_scanqueue_size = MAXSCANQUEUESZ;

struct address_slot slots[MAXSLOTS];

#define MAX_PROCESSES	30

int commands[MAX_PROCESSES];
int results[MAX_PROCESSES];

TAILQ_HEAD (gen_list, generate) genqueue;
struct queue_list readyqueue;

/* Structure for probes */
static SPLAY_HEAD(syntree, argument) synqueue;

int
argumentcompare(struct argument *a, struct argument *b)
{
	return (addr_cmp(&a->addr, &b->addr));
}

SPLAY_PROTOTYPE(syntree, argument, a_node, argumentcompare);
SPLAY_GENERATE(syntree, argument, a_node, argumentcompare);

#define synlist_empty()		(synqueuesz == 0)

int synqueuesz;

struct address_slot *
slot_get(void)
{
	int i;
	struct address_slot *slot;

	for (i = 0; i < MAXSLOTS; i++)
		if (slots[i].slot_base == NULL)
			break;

	if (i >= MAXSLOTS)
		return (NULL);
	
	slot = &slots[i];

	if (slot->slot_base == NULL) {
		slot->slot_size = EXPANDEDARGS;
		slot->slot_base = xmalloc(EXPANDEDARGS * sizeof(struct argument));
		memset(slot->slot_base, 0,
		       slot->slot_size * sizeof(struct argument));
	}

	return (slot);
}

/* We need to call this to free up our memory */

void
slot_free(struct address_slot *slot)
{
	slot->slot_ref--;
	if (slot->slot_ref)
		return;

	slot->slot_size = 0;
	free(slot->slot_base);
	slot->slot_base = NULL;
}

void
argument_free(struct argument *arg)
{
	if (arg->a_ports != NULL && arg->a_hasports) {
		int i;

		for (i = 0; i < arg->a_nports; i++) {
			struct port_scan *ps = arg->a_ports[i].scan;
			if (ps != NULL) {
				event_del(&ps->ev);
				free(ps);
			}
		}
		free(arg->a_ports);
		arg->a_ports = NULL;
	}

	if (arg->a_res != NULL) {
		free(arg->a_res);
		arg->a_res = NULL;
	}

	slot_free(arg->a_slot);
}

void
synlist_init(void)
{
	SPLAY_INIT(&synqueue);
	synqueuesz = 0;
}

/* Inserts an address into the syn tree and schedules a retransmit */

int
synlist_insert(struct argument *arg)
{
	struct timeval tv;

	timerclear(&tv);
	tv.tv_sec = (arg->a_retry/2 + 1) * SYNWAIT;
	tv.tv_usec = rand_uint32(ss_rand) % 1000000L;

	evtimer_add(&arg->ev, &tv);

	/* Insert the node into our tree */
	assert(SPLAY_FIND(syntree, &synqueue, arg) == NULL);
	SPLAY_INSERT(syntree, &synqueue, arg);

	synqueuesz++;

	return (0);
}

void
synlist_remove(struct argument *arg)
{
	SPLAY_REMOVE(syntree, &synqueue, arg);
	evtimer_del(&arg->ev);
	synqueuesz--;
}

int
synlist_probe(struct argument *arg, uint16_t port)
{
        return (synprobe_send(&ss_inter->if_ent.intf_addr,
		    &arg->addr, port, &arg->a_seqnr));
}

int
synprobe_send(struct addr *src, struct addr *dst,
    uint16_t port, uint32_t *seqnr)
{
	static uint8_t pkt[1500];
	struct tcp_hdr *tcp;
	uint iplen;
	int res;

	DFPRINTF((stderr, "Sending probe to %s:%d\n", addr_ntoa(dst), port));

	tcp = (struct tcp_hdr *)(pkt + IP_HDR_LEN);
	tcp_pack_hdr(tcp, rand_uint16(ss_rand), port, 
	    *seqnr, 0, 
	    TH_SYN, 0x8000, 0);

	iplen = IP_HDR_LEN + (tcp->th_off << 2);

	/* Src and Dst are reversed both for ip and tcp */
	ip_pack_hdr(pkt, 0, iplen,
	    rand_uint16(ss_rand),
	    IP_DF, 64,
	    IP_PROTO_TCP, src->addr_ip, dst->addr_ip);

	ip_checksum(pkt, iplen);
	
	if ((res = ip_send(ss_ip, pkt, iplen)) != iplen) {
		warn("%s: ip_send(%d): %s", __func__, res, addr_ntoa(dst));
		return (-1);
	}

	return (0);
}

void
sigchld_handler(int sig)
{
        int save_errno = errno;
	int status;
	wait(&status);
        signal(SIGCHLD, sigchld_handler);
        errno = save_errno;
}

void
printres(struct argument *exp, uint16_t port, char *result)
{
	fprintf(stdout, "%s:%d %s\n",
	    addr_ntoa(&exp->addr), port, result);
	fflush(stdout);
}

void
postres(struct argument *arg, const char *fmt, ...)
{
	static char buffer[1024];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buffer, sizeof(buffer), fmt, ap);
	va_end(ap);

	if (arg->a_res != NULL)
		free(arg->a_res);
	if ((arg->a_res = strdup(buffer)) == NULL)
		err(1, "%s: strdup", __func__);
}

/*
 * Called when a syn probe times out and we might have to repeat it
 */

void
ss_timeout(int fd, short what, void *parameter)
{
	struct argument *arg = parameter;
	struct timeval tv;

	if (arg->a_retry < SYNRETRIES) {
		arg->a_retry++;
		/*
		 * If this probe fails we are not reducing the retry counter,
		 * as some of the failures might repeat always, like a host
		 * on the local network not being reachable or some unrouteable
		 * address space.
		 */
		if (synlist_probe(arg, arg->a_ports[0].port) == 0)
			syn_nsent++;
	} else {
		printres(arg, arg->a_ports[0].port, "<timeout>");
		synlist_remove(arg);
		argument_free(arg);
		return;
	}

	timerclear(&tv);
	tv.tv_sec = (arg->a_retry/2 + 1) * SYNWAIT;
	tv.tv_usec = rand_uint32(ss_rand) % 1000000L;
	
	evtimer_add(&arg->ev, &tv);
}

void
ss_recv_cb(uint8_t *ag, const struct pcap_pkthdr *pkthdr, const uint8_t *pkt)
{
	struct interface *inter = (struct interface *)ag;
	struct ip_hdr *ip;
	struct tcp_hdr *tcp = NULL;
	struct addr addr;
	struct argument *arg, tmp;
	ushort iplen, iphlen;

	/* Everything below assumes that the packet is IPv4 */
	if (pkthdr->caplen < inter->if_dloff + IP_HDR_LEN)
		return;

	pkt += inter->if_dloff;
	ip = (struct ip_hdr *)pkt;

	iplen = ntohs(ip->ip_len);
	if (pkthdr->caplen - inter->if_dloff < iplen)
		return;

	iphlen = ip->ip_hl << 2;
	if (iphlen > iplen)
		return;
	if (iphlen < sizeof(struct ip_hdr))
		return;

	addr_pack(&addr, ADDR_TYPE_IP, IP_ADDR_BITS, &ip->ip_src, IP_ADDR_LEN);

	if (iplen < iphlen + TCP_HDR_LEN)
		return;

	tcp = (struct tcp_hdr *)(pkt + iphlen);

	/* See if we get results from our syn probe */
	tmp.addr = addr;
	if ((arg = SPLAY_FIND(syntree, &synqueue, &tmp)) != NULL) {
		struct port *port;
		/* Check if the result is coming from the right port */
		port = ports_find(arg, ntohs(tcp->th_sport));
		if (port == NULL)
			return;

		if (!arg->a_hasports)
			ports_setup(arg, arg->a_ports, arg->a_nports);

		if (tcp->th_flags & TH_RST) {
			printres(arg, port->port, "<refused>");
			ports_remove(arg, port->port);
			if (arg->a_nports == 0) {
				synlist_remove(arg);
				argument_free(arg);
				return;
			}
		} else {
			ports_markchecked(arg, port);
		}

		if (ports_isalive(arg) == 1) {
			synlist_remove(arg);
			scanhost_ready(arg);
		}
	}
}

void
scanssh_init(void)
{
	TAILQ_INIT(&readyqueue);
	synlist_init();
}

void
usage(char *name)
{
	fprintf(stderr, 
	    "%s: [-VIERhp] [-s scanners] [-n ports] [-e excludefile] [-i if] [-b alias] <IP address|network>...\n\n"
	    "\t-V          print version number of scanssh,\n"
	    "\t-I          do not send identification string,\n"
	    "\t-E          exit if exclude file is missing,\n"
	    "\t-R          do not honor exclude file for random addresses,\n"
	    "\t-p	       proxy detection mode; set scanners and ports,\n"
	    "\t-n <port>   the port number to scan.\n"
	    "\t-e <file>   exclude the IP addresses and networks in <file>,\n"
	    "\t-b <alias>  specifies the IP alias to connect from,\n"
	    "\t-i <if>     specifies the local interface,\n"
	    "\t-h          this message.\n"
	    "\t-s <modes>  uses the following modules for scanning:\n",
	    name);
	scanner_print("\t\t");
}

void
generate_free(struct generate *gen)
{
	struct address_node *node;

	/* Remove generator and attached addr nodes */
	for (node = TAILQ_FIRST(&gen->gen_anqueue);
	     node;
	     node = TAILQ_FIRST(&gen->gen_anqueue)) {
		TAILQ_REMOVE(&gen->gen_anqueue, node, an_next);
		xfree(node);
	}

	TAILQ_REMOVE(&genqueue, gen, gen_next);
	xfree(gen);
}

/*
 * Given an IP prefix and mask create all addresses contained
 * excluding any addresses specified in the exclude queues.
 */

int
populate(struct argument **pargs, int *nargs)
{
	struct generate *gen;
	struct addr addr;
	struct address_slot *slot = NULL;
	struct argument *args;
	int count;

	uint32_t i = 0;

	if (!TAILQ_FIRST(&genqueue))
		return (-1);

	if ((slot = slot_get()) == NULL)
		return (-1);

	args = slot->slot_base;
	count = slot->slot_size;

	while (TAILQ_FIRST(&genqueue) && count) {
		struct port *ports;
		int nports;

		gen = TAILQ_FIRST(&genqueue);
		ports = gen->gen_ports;
		nports = gen->gen_nports;

		
		/* Initalize generator */
		if (!gen->gen_current) {
			if (gen->gen_flags & FLAGS_USERANDOM)
				rndsboxinit(gen->gen_seed);

			gen->gen_current = gen->gen_start;
		}

		while (count) {
			if (next_address(gen, &addr) == -1) {
				generate_free(gen);
				break;
			}

			DFPRINTF((stderr, "New address: %s\n",
				     addr_ntoa(&addr)));

			/* Set up a new address for scanning */
			memset(&args[i], 0, sizeof(struct argument));
			args[i].addr = addr;
			args[i].a_slot = slot;
			args[i].a_scanner = ss_scanners[0];
			args[i].a_scanneroff = 0;
			args[i].a_seqnr = rand_uint32(ss_rand);

			/*
			 * If we have a local port range from the generator
			 * use that.  Otherwise, use the ports that have
			 * been supplied globally.
			 */
			if (ports != NULL) {
				args[i].a_ports = ports;
				args[i].a_nports = nports;
			} else {
				args[i].a_ports = ss_ports;
				args[i].a_nports = ss_nports;
			}

			evtimer_set(&args[i].ev, ss_timeout, &args[i]);

			slot->slot_ref++;
			ss_nhosts++;

			count--;
			i++;
		}
	}

	*pargs = args;
	*nargs = i;

	return (0);
}

int
address_from_offset(struct address_node *an, uint32_t offset,
    struct addr *addr)
{
	ip_addr_t start, end;
	for (; an; an = TAILQ_NEXT(an, an_next)) {
		*addr = an->an_start;
		start = ntohl(an->an_start.addr_ip);
		end = ntohl(an->an_end.addr_ip);
		if (start + offset <= end)
			break;
		offset -= end - start + 1;
	}

	if (an == NULL)
		return (-1);

	addr->addr_ip = htonl(start + offset);

	return (0);
}

/*
 * get the next address, keep state.
 */

int
next_address(struct generate *gen, struct addr *addr)
{
	struct addr ipv4addr, tmp;
	uint32_t offset;
	int done = 0, random;

	/* Check if generator has been exhausted */
	if (gen->gen_n >= gen->gen_max)
		return (-1);

	random = gen->gen_flags & FLAGS_USERANDOM;

	do {
		/* Get offset into address range */
		if (random)
			offset = rndgetaddr(gen->gen_bits,
			    gen->gen_current);
		else
			offset = gen->gen_current;
		
		gen->gen_current += gen->gen_iterate;
		
		if (address_from_offset(TAILQ_FIRST(&gen->gen_anqueue),
			offset, &ipv4addr) == -1)
			continue;
		
		if (!random || rndexclude) {
			tmp = exclude(ipv4addr, &excludequeue);
			if (addr_cmp(&ipv4addr, &tmp)) {
				if (random) {
					if (gen->gen_flags & FLAGS_SUBTRACTEXCLUDE)
						gen->gen_max--;

					continue;
				}

				/* In linear mode, we can skip these */
				offset = gen->gen_current;
				offset += ntohl(tmp.addr_ip) - ntohl(ipv4addr.addr_ip);
				if (offset < gen->gen_current) {
					gen->gen_current = gen->gen_end;
					break;
				}
				gen->gen_current = offset;
				
				if (gen->gen_iterate == 1)
					continue;

				/* Adjust for splits */
				offset /= gen->gen_iterate;
				offset *= gen->gen_iterate;

				offset += gen->gen_start;

				if (offset < gen->gen_current)
					offset += gen->gen_iterate;
				if (offset < gen->gen_current) {
					gen->gen_current = gen->gen_end;
					break;
				}

				gen->gen_current = offset;
				continue;
			}
		}
		
		if (random) {
			tmp = exclude(ipv4addr, &rndexclqueue);
			if (addr_cmp(&ipv4addr, &tmp)) {
				if (gen->gen_flags & FLAGS_SUBTRACTEXCLUDE)
					gen->gen_max--;
				continue;
			}
		}
		
		/* We have an address */
		done = 1;
	} while ((gen->gen_current < gen->gen_end) && 
	    (gen->gen_n < gen->gen_max) && !done);

	if (!done)
		return (-1);

	gen->gen_n += gen->gen_iterate;

	*addr = ipv4addr;

	return (0);
}

struct address_node *
address_node_get(char *line)
{
	struct address_node *an;

	/* Allocate an address node */
	an = xmalloc(sizeof(struct address_node));
	memset(an, 0, sizeof(struct address_node));
	if (addr_pton(line, &an->an_start) == -1) {
		fprintf(stderr, "Can not parse %s\n", line);
		goto error;
	}
	/* Working around libdnet bug */
	if (strcmp(line, "0.0.0.0/0") == 0)
		an->an_start.addr_bits = 0;

	an->an_bits = an->an_start.addr_bits;

	addr_bcast(&an->an_start, &an->an_end);
	an->an_start.addr_bits = IP_ADDR_BITS;
	an->an_end.addr_bits = IP_ADDR_BITS;

	return (an);

 error:
	free(an);
	return (NULL);
}

/*
 * Creates a generator from a command line
 * [split(x/n)/][random(x,s)/][(]<address/mask> .... [)]
 */

int
generate_split(struct generate *gen, char **pline)
{
	char *line, *end;

	line = *pline;

	if ((end = strstr(line, ")/")) == NULL ||
	    strchr(line, '/') < end) {
		fprintf(stderr, "Split not terminated correctly: %s\n", line);
		return (-1);
	}

	line = 	strsep(pline, "/");

	/* Generate a random scan entry */
	if (sscanf(line, "split(%d,%d)/",
		   &gen->gen_start, &gen->gen_iterate) != 2)
		return (-1);
		
	if (!gen->gen_start || gen->gen_start > gen->gen_iterate) {
		fprintf(stderr, "Invalid start/iterate pair: %d/%d\n",
			gen->gen_start, gen->gen_iterate);
		return (-1);
	}

	/* Internally, we start counting at 0 */
	gen->gen_start--;

	return (0);
}

/*
 * Creates a generator from a command line
 * [split(x/n)/][random(x,s)/][(]<address/mask> .... [)]
 */

int
generate_random(struct generate *gen, char **pline)
{
	int i;
	char seed[31], *line, *end;

	line = *pline;

	if ((end = strstr(line, ")/")) == NULL ||
	    strchr(line, '/') < end) {
		fprintf(stderr, "Random not terminated correctly: %s\n", line);
		return (-1);
	}

	line = strsep(pline, "/");

	/* Generate a random scan entry */
	seed[0] = '\0';
	if (sscanf(line, "random(%d,%30s)/", &gen->gen_max, seed) < 1)
		return (-1);
		
	/* Generate seed from string */
	if (strlen(seed)) {
		MD5_CTX ctx;
		uint8_t digest[16];
		uint32_t *tmp = (uint32_t *)digest;

		MD5Init(&ctx);
		MD5Update(&ctx, seed, strlen(seed));
		MD5Final(digest, &ctx);

		gen->gen_seed = 0;
		for (i = 0; i < 4; i ++)
			gen->gen_seed ^= *tmp++;
				
	} else
		gen->gen_seed = rand_uint32(ss_rand);

	gen->gen_flags |= FLAGS_USERANDOM;

	/* If the random numbers exhaust all possible addresses,
	 * we need to subtract those addresses from the count
	 * that can not be generated because they were excluded
	 */
	if (!gen->gen_max)
		gen->gen_flags |= FLAGS_SUBTRACTEXCLUDE;

	return (0);
}

int
generate(char *line)
{
	struct generate *gen;
	struct address_node *an;
	uint32_t count, tmp;
	char *p;
	int bits, i, done;

	gen = xmalloc(sizeof(struct generate));
	memset(gen, 0, sizeof(struct generate));
	TAILQ_INIT(&gen->gen_anqueue);

	/* Insert in generator queue, on failure generate_free removes it */
	TAILQ_INSERT_TAIL(&genqueue, gen, gen_next);

	/* Check for port ranges */
	p = strsep(&line, ":");
	if (line != NULL) {
		if (ports_parse(line,
			&gen->gen_ports, &gen->gen_nports) == -1) {
			fprintf(stderr, "Bad port range: %s\n", line);
			goto fail;
		}
	}
	line = p;

	done = 0;
	while (!done) {
		done = 1;
		if (strncmp(line, "random(", 7) == 0) {
			if (gen->gen_flags & FLAGS_USERANDOM) {
				fprintf(stderr,
					"Random already specified: %s\n",
					line);
				goto fail;
			}
			if (generate_random(gen, &line) == -1)
				goto fail;

			done = 0;
		} else if (strncmp(line, "split(", 6) == 0) {
			if (gen->gen_iterate) {
				fprintf(stderr,
					"Split already specified: %s\n",
					line);
				goto fail;
			}
			if (generate_split(gen, &line) == -1)
				goto fail;

			done = 0;
		}
	}

	/* If no special split is specified, always iterated by 1 */
	if (!gen->gen_iterate)
		gen->gen_iterate = 1;

	if (line[0] == '(') {
		char *end;
		
		line++;
		if ((end = strchr(line, ')')) == NULL) {
			fprintf(stderr, "Missing ')' in line: %s\n", line);
			goto fail;
		}
		*end = '\0';
		
	}

	while (line && (p = strsep(&line, " "))) {
		if ((an = address_node_get(p)) == NULL)
			goto fail;

		TAILQ_INSERT_TAIL(&gen->gen_anqueue, an, an_next);
	}

	/* Try to find out the effective bit range */
	count = 0;
	for (an = TAILQ_FIRST(&gen->gen_anqueue); an;
	     an = TAILQ_NEXT(an, an_next)) {
		bits = an->an_bits;
		if (bits == 0) {
			count = -1;
			break;
		}

		if (count + (1 << (32 - bits)) < count) {
			count = -1;
			break;
		}

		count += 1 << (32 - bits);
	}

	/* Try to convert count into a network mask */
	bits = 0;
	tmp = count;
	for (i = -1; tmp; tmp >>= 1, i++) {
		if (tmp & 1)
			bits++;
	}

	/* a count of 01100, results in bits = 29, but it should be 28 */
	gen->gen_bits = 32 - i;
	if (bits > 1)
		gen->gen_bits--;
	bits = gen->gen_bits;

	if (gen->gen_flags & FLAGS_USERANDOM) {
		if (bits == 0)
			gen->gen_end = -1;
		else 
			gen->gen_end = 1 << (32 - bits);
	} else
		gen->gen_end = count;

	if (gen->gen_max == 0)
		gen->gen_max = count;

	return (0);
 fail:
	if (gen)
		generate_free(gen);

	return (-1);
}

int
probe_haswork(void)
{
	return (TAILQ_FIRST(&genqueue) || entries || !synlist_empty());
}

void
probe_send(int fd, short what, void *parameter)
{
	struct event *ev = parameter;
	struct timeval tv;
	int ntotal, nprobes, nsent;
	extern int scan_nhosts;

	/* Schedule the next probe */
	if (probe_haswork()) {
		timerclear(&tv);
		tv.tv_usec = 1000000L / syn_rate;
		evtimer_add(ev, &tv);
	} else if (TAILQ_FIRST(&readyqueue) == NULL && !scan_nhosts) {
		struct timeval tv;

		/* Terminate the event loop */
		timerclear(&tv);
		tv.tv_sec = 2;
		event_loopexit(&tv);
	}

	gettimeofday(&tv, NULL);
	timersub(&tv, &syn_start, &tv);

	ntotal = tv.tv_sec * syn_rate + (tv.tv_usec * syn_rate) / 1000000L;
	nprobes = ntotal - syn_nsent;

	nsent = 0;
	while ((TAILQ_FIRST(&genqueue) || entries) && nsent < nprobes) {
		/* Create new entries, if we need them */
		if (!entries && TAILQ_FIRST(&genqueue)) {
			if (populate(&args, &entries) == -1) {
				/* 
				 * We fail if we have used up our memory.
				 * We also need to consume our number of
				 * sent packets.
				 */
				syn_nsent = ntotal;
				entries = 0;
				break;
			}
			continue;
		}

		entries--;
		args[entries].a_retry = 0;

		if (TAILQ_FIRST(&socks_host) == NULL) {
			synlist_insert(&args[entries]);

			/* 
			 * On failure, synlist_insert already scheduled
			 * a retransmit.
			 */
			synlist_probe(&args[entries],
			    args[entries].a_ports[0].port);
		} else {
			struct argument *arg = &args[entries];
			if (!arg->a_hasports)
				ports_setup(arg, arg->a_ports, arg->a_nports);
			scanhost_ready(arg);
		}

		nsent++;
		syn_nsent++;
	}
}

int
parse_socks_host(char *optarg)
{
	char *host;
	while ((host = strsep(&optarg, ",")) != NULL) {
		/*
		 * Parse the address of a SOCKS proxy that we are
		 * using for all connections.
		 */
		struct socks_host *single_host;

		char *address = strsep(&host, ":");
		if (host == NULL || *host == '\0')
			return (-1);

		single_host = calloc(1, sizeof(struct socks_host));
		if (single_host == NULL)
			err(1, "calloc");
		if (addr_pton(address, &single_host->host) == -1)
			return (-1);

		if ((single_host->port = atoi(host)) == 0)
			return (-1);

		TAILQ_INSERT_TAIL(&socks_host, single_host, next);
	}

	return (0);
}

int
main(int argc, char **argv)
{
	struct event ev_send;
	char *name, *dev = NULL, *scanner = "ssh";
	char *default_ports = "22";
	int ch;
	struct timeval tv, tv_start, tv_end;
	struct rlimit rl;
	int failonexclude = 0;
	int milliseconds;

	ssh_sendident = 1;

	TAILQ_INIT(&socks_host);

	name = argv[0];
	while ((ch = getopt(argc, argv, "VIhdpm:u:s:i:e:n:r:ER")) != -1)
		switch(ch) {
		case 'V':
			fprintf(stderr, "ScanSSH %s\n", VERSION);
			exit(0);
#ifdef DEBUG
		case 'd':
			debug++;
			break;
#endif
		case 'I':
			ssh_sendident = 0;
			break;
		case 'p':
			scanner = "http-proxy,http-connect,socks5,socks4,telnet-proxy,ssh";
			default_ports = "23,22,80,81,808,1080,1298,3128,6588,4480,8080,8081,8000,8100,9050";
			break;
		case 'm':
			max_scanqueue_size = atoi(optarg);
			if (max_scanqueue_size == 0) {
				usage(name);
				exit(1);
			}
			break;
		case 'u': 
			if (parse_socks_host(optarg) == -1) {
				usage(name);
				exit(1);
			}
			break;
		case 's':
			scanner = optarg;
			break;
		case 'i':
			dev = optarg;
			break;
		case 'n':
			if (ports_parse(optarg, &ss_ports, &ss_nports) == -1) {
				usage(name);
				exit(1);
			}
			break;
		case 'e':
			excludefile = optarg;
			/* FALLTHROUGH */
		case 'E':
			failonexclude = 1;
			break;
		case 'R':
			rndexclude=0;
			break;
		case 'r':
			syn_rate = atoi(optarg);
			if (syn_rate == 0) {
				fprintf(stderr, "Bad syn probe rate: %s\n",
				    optarg);
				usage(name);
				exit(1);
			}
			break;
		case 'h':
		default:
			usage(name);
			exit(1);
		}

	argc -= optind;
	argv += optind;

	if (scanner_parse(scanner) == -1)
		errx(1, "bad scanner: %s", scanner);

	if ((ss_rand = rand_open()) == NULL)
		err(1, "rand_open");

	if ((ss_ip = ip_open()) == NULL)
		err(1, "ip_open");

	scanssh_init();
	
	event_init();

	interface_initialize();

	/* Initialize the specified interfaces */
	interface_init(dev, 0, NULL,
	    "(tcp[13] & 18 = 18 or tcp[13] & 4 = 4)");

	/* Raising file descriptor limits */
	rl.rlim_max = RLIM_INFINITY;
	rl.rlim_cur = RLIM_INFINITY;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
		/* Linux does not seem to like this */
		if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
			err(1, "getrlimit: NOFILE");
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
			err(1, "setrlimit: NOFILE");
	}

	/* Raising the memory limits */
	rl.rlim_max = RLIM_INFINITY;
	rl.rlim_cur = MAXSLOTS * EXPANDEDARGS * sizeof(struct argument) * 2;
	if (setrlimit(RLIMIT_DATA, &rl) == -1) {
		/* Linux does not seem to like this */
		if (getrlimit(RLIMIT_DATA, &rl) == -1)
			err(1, "getrlimit: DATA");
		rl.rlim_cur = rl.rlim_max;
		if (setrlimit(RLIMIT_DATA, &rl) == -1)
			err(1, "setrlimit: DATA");
	}
	
       
	/* revoke privs */
#ifdef HAVE_SETEUID
        seteuid(getuid());
#endif /* HAVE_SETEUID */
        setuid(getuid());

	/* Set up our port ranges */
	if (ss_nports == 0) {
		if (ports_parse(default_ports, &ss_ports, &ss_nports) == -1)
			errx(1, "Error setting up port list");
	}

	if (setupexcludes() == -1 && failonexclude) {
		warn("fopen: %s", excludefile);
		exit(1);
	}

	memset(slots, 0, sizeof(slots));

	TAILQ_INIT(&genqueue);

	while (argc) {
		if (generate(argv[0]) == -1)
			warnx("generate failed on %s", argv[0]);

		argv++;
		argc--;
	}

	if (!TAILQ_FIRST(&genqueue))
		errx(1, "nothing to scan");

	gettimeofday(&syn_start, NULL);

	evtimer_set(&ev_send, probe_send, &ev_send);
	timerclear(&tv);
	tv.tv_usec = 1000000L / syn_rate;
	evtimer_add(&ev_send, &tv);

	gettimeofday(&tv_start, NULL);

	event_dispatch();

	/* Measure our effective host scan rate */

	gettimeofday(&tv_end, NULL);

	timersub(&tv_end, &tv_start, &tv_end);

	milliseconds = tv_end.tv_sec * 1000 + tv_end.tv_usec % 1000;

	fprintf(stderr, "Effective host scan rate: %.2f hosts/s\n",
	    (float)ss_nhosts / (float) milliseconds * 1000.0);

	return (1);
}

void
ports_timeout(int fd, short what, void *parameter)
{
	struct port_scan *ps = parameter;
	struct argument *arg = ps->arg;
	struct timeval tv;

	if (ps->count < SYNRETRIES) {
		ps->count++;
		/*
		 * If this probe fails we are not reducing the retry counter,
		 * as some of the failures might repeat always, like a host
		 * on the local network not being reachable or some unrouteable
		 * address space,
		 */
		if (synlist_probe(arg, ps->port) == -1)
			goto reschedule;

		syn_nsent++;
	} else {
		printres(arg, ps->port, "<timeout>");
		ports_remove(arg, ps->port);
		if (arg->a_nports == 0) {
			synlist_remove(arg);
			argument_free(arg);
			return;
		}
		return;
	}

 reschedule:
	timerclear(&tv);
	tv.tv_sec += (arg->a_retry/2 + 1) * SYNWAIT;
	tv.tv_usec = rand_uint32(ss_rand) % 1000000L;
	
	evtimer_add(&arg->ev, &tv);
}

/* Mark a port as checked - meaning that we can connect to it */

void
ports_markchecked(struct argument *arg, struct port *port)
{
	struct port_scan *ps = port->scan;

	DNFPRINTF(2, (stderr, "%s: %s:%d marked alive\n",
		      __func__, addr_ntoa(&arg->addr), port->port));

	if (ps == NULL) {
		/* Populates scan structures */
		ports_isalive(arg);

		/* This argument has a new memory area now */
		port = ports_find(arg, port->port);
		ps = port->scan;
	}

	event_del(&ps->ev);
	ps->flags |= PORT_CHECKED;
}

/* Checks if all ports for this host have been checked to be alive */

int
ports_isalive(struct argument *arg)
{
	struct port_scan *ps;
	int i;

	/* We already populated the structures */
	if (arg->a_ports[0].scan != NULL) {
		for (i = 0; i < arg->a_nports; i++)
			if (!(arg->a_ports[i].scan->flags & PORT_CHECKED))
				return (0);
		for (i = 0; i < arg->a_nports; i++) {
			ps = arg->a_ports[i].scan;
			event_del(&ps->ev);
			free(ps);
			arg->a_ports[i].scan = NULL;
		}
		return (1);
	}

	/* This host was newly detected as alive */
	for (i = 0; i < arg->a_nports; i++) {
		struct timeval tv;

		if ((ps = calloc(1, sizeof(struct port_scan))) == NULL)
			err(1, "%s: calloc");
		arg->a_ports[i].scan = ps;

		ps->arg = arg;
		ps->port = arg->a_ports[i].port;
		evtimer_set(&ps->ev, ports_timeout, ps);

		timerclear(&tv);
		tv.tv_usec = rand_uint32(ss_rand) % 1000000L;
		
		evtimer_add(&ps->ev, &tv);
	}

	return (0);
}

/* Copy the ports list to the argument and use it for scanning */

int
ports_setup(struct argument *arg, struct port *ports, int nports)
{
	arg->a_hasports = 1;
	arg->a_nports = nports;
	if ((arg->a_ports = calloc(nports, sizeof(struct port))) == NULL)
		err(1, "%s: calloc", __func__);

	memcpy(arg->a_ports, ports, nports * sizeof(struct port));

	return (0);
}

struct port *
ports_find(struct argument *arg, uint16_t port)
{
	int i;

	for (i = 0; i < arg->a_nports; i++)
		if (arg->a_ports[i].port == port)
			return (&arg->a_ports[i]);

	return (NULL);
}

/* Remove one port from the list and reduce the number of available ports */

int
ports_remove(struct argument *arg, uint16_t port)
{
	int i;

	for (i = 0; i < arg->a_nports; i++) {
		if (arg->a_ports[i].port == port) {
			/* Deallocate the scan structure if necessary */
			if (arg->a_ports[i].scan != NULL) {
				event_del(&arg->a_ports[i].scan->ev);
				free(arg->a_ports[i].scan);
			}
			arg->a_nports--;
			if (i < arg->a_nports) {
				arg->a_ports[i] = arg->a_ports[arg->a_nports];
			} else if (arg->a_nports == 0) {
				free (arg->a_ports);
				arg->a_ports = NULL;
			}
			return (0);
		}
	}

	return (-1);
}

/* Parse the list of ports and put them into an array */

int
ports_parse(char *argument, struct port **pports, int *pnports)
{
	char buf[1024], *line = buf;
	char *p, *e;
	int size, count, val;
	struct port *ports = *pports;
	struct port port;

	strlcpy(buf, argument, sizeof(buf));

	memset(&port, 0, sizeof(port));

	count = 0;
	size = 0;
	while ((p = strsep(&line, ",")) != NULL) {
		val = strtoul(p, &e, 10);
		if (p[0] == '\0' || *e != '\0')
			return (-1);
		if (val <= 0 || val > 65535)
			return (-1);

		if (count >= size) {
			struct port *tmpports;
			if (size == 0)
				size = 10;
			else
				size <<= 1;

			tmpports = realloc(ports, size*sizeof(struct port));
			if (tmpports == NULL)
				err(1, "realloc");
			ports = tmpports;
			memset(&ports[count], 0,
			    (size - count) * sizeof(struct port));
		}

		port.port = val;
		ports[count++] = port;
	}

	if (count == 0)
		return (-1);

	*pports = ports;
	*pnports = count;
	return (0);
}

/* Parse the list of scanners and put them into an array */

int
scanner_parse(char *argument)
{
	char buf[1024], *line = buf;
	char *p;
	int size, count;
	struct scanner *scanner;

	strlcpy(buf, argument, sizeof(buf));

	count = 0;
	size = 0;
	while ((p = strsep(&line, ",")) != NULL) {
		if ((scanner = scanner_find(p)) == NULL)
			return (-1);

		if (count >= size) {
			struct scanner **tmpscanners;
			if (size == 0)
				size = 10;
			else
				size <<= 1;

			tmpscanners = realloc(ss_scanners,
			    size * sizeof(struct scanner *));
			if (tmpscanners == NULL)
				err(1, "realloc");
			ss_scanners = tmpscanners;
			memset(&ss_scanners[count], 0,
			    (size - count) * sizeof(struct scanner *));
		}
		ss_scanners[count++] = scanner;
	}

	if (count == 0)
		return (-1);

	ss_nscanners = count;
	return (0);
}
