#include <sys/types.h>
#include <stdlib.h>

#include "config.h"

/*
 * For those poor operating systems, that do not have a PRNG in their
 * libc.  We do not require cryptographic random numbers for this
 * application anyway.  Screw you, hippy!
 */

u_int32_t
arc4random(void)
{
	static int init;

	if (!init) {
		init = 1;
		srandom(time(NULL));
	}
	return (random());
}
