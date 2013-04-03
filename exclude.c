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

#include <sys/types.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/queue.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>
#include <err.h>

#include <dnet.h>

#include "exclude.h"

char *excludefile = "exclude.list";
struct exclude_list excludequeue;
struct exclude_list rndexclqueue;

#define RNDSBOXSIZE	128
#define RNDSBOXSHIFT	7
#define RNDROUNDS	32

uint32_t rndsbox[RNDSBOXSIZE];

char *unusednets[] = {
	"127.0.0.0/8",		/* local */
	"10.0.0.0/8",		/* rfc-1918 */
	"172.16.0.0/12",	/* rfc-1918 */
	"192.168.0.0/16",	/* rfc-1918 */
	"224.0.0.0/4",		/* rfc-1112 */
	"240.0.0.0/4",
	"0.0.0.0/8",
	"255.0.0.0/8",
	NULL
};

void
rndsboxinit(uint32_t seed)
{
	int i;

	/* We need repeatable random numbers here */
	srandom(seed);
	for (i = 0; i < RNDSBOXSIZE; i++) {
		rndsbox[i] = random();
	}
}

/*
 * We receive the prefix in host-order.
 * Use a modifed TEA to create a permutation of 2^(32-bits)
 * elements.
 */

uint32_t
rndgetaddr(int bits, uint32_t count)
{
	uint32_t sum = 0, mask, sboxmask;
	int i, left, right, kshift;

	if (bits == 32)
		return (0);

	left = (32 - bits) / 2;
	right = (32 - bits) - left;

	mask  = 0xffffffff >> bits;
	if (RNDSBOXSIZE < (1 << left)) {
		sboxmask = RNDSBOXSIZE - 1;
		kshift = RNDSBOXSHIFT;
	} else {
		sboxmask = (1 << left) - 1;
		kshift = left;
	}

	for (i = 0; i < RNDROUNDS; i++) {
		sum += 0x9e3779b9;
		count ^= rndsbox[(count^sum) & sboxmask]  << kshift;
		count += sum;
		count &= mask;
		count = ((count << left) | (count >> right)) & mask;
	}

	return (count);
}

void
excludeinsert(struct addr *addr, struct exclude_list *queue)
{
	struct exclude *entry;

	if ((entry = malloc(sizeof(*entry))) == NULL)
		err(1, "malloc");

	/* Set up the addresses; still IPv4 dependent */
	entry->e_net = *addr;
	TAILQ_INSERT_HEAD(queue, entry, e_next);
}

int
setupexcludes(void)
{
	FILE *stream;
	char line[BUFSIZ];
	size_t len;
	struct addr addr;
	int i;

	TAILQ_INIT(&excludequeue);
	TAILQ_INIT(&rndexclqueue);

	for (i = 0; unusednets[i]; i++) {
		if (addr_pton(unusednets[i], &addr) == -1)
			errx(1, "addr_pton for unused %s", unusednets[i]);
		excludeinsert(&addr, &rndexclqueue);
	}

	if ((stream = fopen(excludefile, "r")) == NULL)
		return (-1);

	while (fgets(line, sizeof(line), stream) != NULL) {
		len = strlen(line);
		if (line[len - 1] != '\n') {
			fprintf(stderr, "Ignoring line without newline\n");
			continue;
		}
		line[len - 1] = '\0';
		if (addr_pton(line, &addr) == -1) {
			fprintf(stderr, "Can't parse <%s> in exclude file.\n",
				line);
			exit (1);
		}
		excludeinsert(&addr, &excludequeue);
	}

	fclose(stream);

	return (0);
}

struct addr
exclude(struct addr address, struct exclude_list *queue)
{
	struct addr addr_a, addr_aend;
	struct exclude *entry;

	/* Check for overflow */
	if (address.addr_ip == INADDR_ANY)
		return (address);

	TAILQ_FOREACH(entry, queue, e_next) {
		/* Set up the addresses; still IPv4 dependent */
		addr_a = entry->e_net;
		addr_a.addr_bits = IP_ADDR_BITS;

		addr_bcast(&entry->e_net, &addr_aend);
		addr_aend.addr_bits = IP_ADDR_BITS;

		if (addr_cmp(&address, &addr_a) >= 0 &&
		    addr_cmp(&address, &addr_aend) <= 0) {
			/* Increment and check overflow */
			ip_addr_t ip = ntohl(addr_aend.addr_ip) + 1;
			address.addr_ip = htonl(ip);
			return (exclude(address, queue));
		}
	}

	return (address);
}
