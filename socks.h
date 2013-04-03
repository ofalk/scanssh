/*
 * Copyright 2004 Niels Provos <provos@citi.umich.edu>
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

#ifndef _SOCKS_H_
#define _SOCKS_H_

#define SOCKS_VERSION4		0x04
#define SOCKS_VERSION5		0x05

#define SOCKS_CMD_CONNECT	0x01

#define SOCKS_ADDR_IPV4		0x01
#define SOCKS_ADDR_NAME		0x03
#define SOCKS_ADDR_IPV6		0x04

#define SOCKS5_RESP_SUCCESS	0x00
#define SOCKS5_RESP_FAILURE	0x01
#define SOCKS5_RESP_FORBIDDEN	0x02
#define SOCKS5_RESP_NETUNREACH	0x03
#define SOCKS5_RESP_HOSTUNREACH	0x04
#define SOCKS5_RESP_REFUSED	0x05
#define SOCKS5_RESP_TTLEXPIRE	0x06
#define SOCKS5_RESP_NOSUPPORT	0x07
#define SOCKS5_RESP_BADADDRESS	0x08

#define SOCKS4_RESP_SUCCESS	90
#define SOCKS4_RESP_FAILURE	91
#define SOCKS4_RESP_NOIDENT	92
#define SOCKS4_RESP_BADIDENT	93

/* Our little state machine */

#define SOCKS_WAITING_RESPONSE		0x01
#define SOCKS_SENDING_COMMAND		0x02
#define SOCKS_WAITING_COMMANDRESPONSE	0x03
#define SOCKS_SENDING_WEBREQUEST	0x04
#define SOCKS_READING_RESPONSE		0x05

struct socks_state {
	uint8_t version;
	uint8_t method;
	uint8_t gotheaders;
	uint8_t success;

	uint16_t port;

	char domain[64];	/* the host where it lives */
	char *word;		/* which word to search at google */
};

struct socks4_cmd {
	uint8_t version;
	uint8_t command;
	uint16_t dstport;
	struct in_addr address;
};

struct socks5_cmd {
	uint8_t version;
	uint8_t command;
	uint8_t reserved;
	uint8_t addrtype;
	struct in_addr address;
	uint16_t dstport;
};

char *socks_getword(void);
void socks_bufferanalyse(struct bufferevent *, struct argument *);
void socks_resolveaddress(char *name, ip_addr_t *address);


#endif /* _SOCKS_H_ */
