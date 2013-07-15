/*
 * random.c
 *		Acquire randomness from system.  For seeding RNG.
 *
 * Copyright (c) 2001 Marko Kreen
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in the
 *	  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * contrib/pgcrypto/random.c
 */

#include <errno.h>
#include "c.h"
#include "px.h"

/* how many bytes to ask from system random provider */
#define RND_BYTES  32

/*
 * Try to read from /dev/urandom or /dev/random on these OS'es.
 *
 * The list can be pretty liberal, as the device not existing
 * is expected event.
 */

#define TRY_DEV_RANDOM

#include <fcntl.h>
#include <unistd.h>

int
safe_read(int fd, void *buf, size_t count)
{
	int			done = 0;
	char	   *p = buf;
	int			res;

	while (count)
	{
		res = read(fd, p, count);
		if (res <= 0)
		{
			if (errno == EINTR)
				continue;
			return PXE_DEV_READ_ERROR;
		}
		p += res;
		done += res;
		count -= res;
	}
	return done;
}

uint8 *
try_dev_random(uint8 *dst)
{
	int			fd;
	int			res;

	fd = open("/dev/urandom", O_RDONLY, 0);
	if (fd == -1)
	{
		fd = open("/dev/random", O_RDONLY, 0);
		if (fd == -1)
			return dst;
	}
	res = safe_read(fd, dst, RND_BYTES);
	close(fd);
	if (res > 0)
		dst += res;
	return dst;
}

/*
 * try to extract some randomness for initial seeding
 *
 * dst should have room for 1024 bytes.
 */
unsigned
px_acquire_system_randomness(uint8 *dst)
{
	uint8	   *p = dst;

	p = try_dev_random(p);
	return p - dst;
}
