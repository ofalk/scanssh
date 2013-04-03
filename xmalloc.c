/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Versions of malloc and friends that check their results, and never return
 * failure (they call fatal if they encounter an error).
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <string.h>

#include "config.h"

void *
xmalloc(size_t size)
{
	void *ptr;

	if (size == 0)
		err(1,"xmalloc: zero size");
	ptr = malloc(size);
	if (ptr == NULL) {
		fprintf(stderr, 
		    "xmalloc: out of memory (allocating %lu bytes)",
		    (u_long) size);
		abort();
	}
	return ptr;
}

void *
xrealloc(void *ptr, size_t new_size)
{
	void *new_ptr;

	if (new_size == 0)
		err(1,"xrealloc: zero size");
	if (ptr == NULL)
		err(1,"xrealloc: NULL pointer given as argument");
	new_ptr = realloc(ptr, new_size);
	if (new_ptr == NULL)
		err(1,"xrealloc: out of memory (new_size %lu bytes)", (u_long) new_size);
	return new_ptr;
}

void
xfree(void *ptr)
{
	if (ptr == NULL)
		err(1,"xfree: NULL pointer given as argument");
	free(ptr);
}

char *
xstrdup(const char *str)
{
	size_t len = strlen(str) + 1;
	char *cp;

	if (len == 0)
		err(1,"xstrdup: zero size");
	cp = xmalloc(len);
	strlcpy(cp, str, len);
	return cp;
}
