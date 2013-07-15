/*
 * internal.c
 *		Wrapper for builtin functions
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
 * contrib/pgcrypto/internal.c
 */

#ifndef __INTERNAL_H
#define __INTERNAL_H

#include <time.h>

#include "px.h"
#include "md5.h"
#include "sha1.h"
#include "blf.h"
#include "rijndael.h"
#include "fortuna.h"

/*
 * System reseeds should be separated at least this much.
 */
#define SYSTEM_RESEED_MIN			(20*60)		/* 20 min */
/*
 * How often to roll dice.
 */
#define SYSTEM_RESEED_CHECK_TIME	(10*60)		/* 10 min */
/*
 * The chance is x/256 that the reseed happens.
 */
#define SYSTEM_RESEED_CHANCE		(4) /* 256/4 * 10min ~ 10h */

/*
 * If this much time has passed, force reseed.
 */
#define SYSTEM_RESEED_MAX			(12*60*60)	/* 12h */


#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

#ifndef SHA1_DIGEST_LENGTH
#ifdef SHA1_RESULTLEN
#define SHA1_DIGEST_LENGTH SHA1_RESULTLEN
#else
#define SHA1_DIGEST_LENGTH 20
#endif
#endif

#define SHA1_BLOCK_SIZE 64
#define MD5_BLOCK_SIZE 64

void init_md5(PX_MD *h);
void init_sha1(PX_MD *h);

void		init_sha224(PX_MD *h);
void		init_sha256(PX_MD *h);
void		init_sha384(PX_MD *h);
void		init_sha512(PX_MD *h);

struct int_digest
{
	char	   *name;
	void		(*init) (PX_MD *h);
};

const struct int_digest
			int_digest_list[] = {
	{"md5", init_md5},
	{"sha1", init_sha1},
	{"sha224", init_sha224},
	{"sha256", init_sha256},
	{"sha384", init_sha384},
	{"sha512", init_sha512},
	{NULL, NULL}
};

/* MD5 */

unsigned int_md5_len(PX_MD *h);
unsigned int_md5_block_len(PX_MD *h);
void int_md5_update(PX_MD *h, const uint8 *data, unsigned dlen);
void int_md5_reset(PX_MD *h);
void int_md5_finish(PX_MD *h, uint8 *dst);
void int_md5_free(PX_MD *h);

unsigned int_sha1_len(PX_MD *h);
unsigned int_sha1_block_len(PX_MD *h);
void int_sha1_update(PX_MD *h, const uint8 *data, unsigned dlen);
void int_sha1_reset(PX_MD *h);
void int_sha1_finish(PX_MD *h, uint8 *dst);
void int_sha1_free(PX_MD *h);
void init_md5(PX_MD *md);
void init_sha1(PX_MD *md);

#define INT_MAX_KEY		(512/8)
#define INT_MAX_IV		(128/8)

struct int_ctx
{
	uint8		keybuf[INT_MAX_KEY];
	uint8		iv[INT_MAX_IV];
	union
	{
		BlowfishContext bf;
		rijndael_ctx rj;
	}			ctx;
	unsigned	keylen;
	int			is_init;
	int			mode;
};

void intctx_free(PX_Cipher *c);

#define MODE_ECB 0
#define MODE_CBC 1

unsigned rj_block_size(PX_Cipher *c);
unsigned rj_key_size(PX_Cipher *c);
unsigned rj_iv_size(PX_Cipher *c);
int rj_init(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv);
int rj_real_init(struct int_ctx * cx, int dir);
int rj_encrypt(PX_Cipher *c, const uint8 *data, unsigned dlen, uint8 *res);
int rj_decrypt(PX_Cipher *c, const uint8 *data, unsigned dlen, uint8 *res);
PX_Cipher *rj_load(int mode);
unsigned bf_block_size(PX_Cipher *c);
unsigned bf_key_size(PX_Cipher *c);
unsigned bf_iv_size(PX_Cipher *c);
int bf_init(PX_Cipher *c, const uint8 *key, unsigned klen, const uint8 *iv);
int bf_encrypt(PX_Cipher *c, const uint8 *data, unsigned dlen, uint8 *res);
int bf_decrypt(PX_Cipher *c, const uint8 *data, unsigned dlen, uint8 *res);
PX_Cipher *bf_load(int mode);
PX_Cipher *rj_128_ecb(void);
PX_Cipher *rj_128_cbc(void);
PX_Cipher *bf_ecb_load(void);
PX_Cipher *bf_cbc_load(void);

struct int_cipher
{
	char	   *name;
	PX_Cipher  *(*load) (void);
};

const struct int_cipher
			int_ciphers[] = {
	{"bf-cbc", bf_cbc_load},
	{"bf-ecb", bf_ecb_load},
	{"aes-128-cbc", rj_128_cbc},
	{"aes-128-ecb", rj_128_ecb},
	{NULL, NULL}
};

const PX_Alias int_aliases[] = {
	{"bf", "bf-cbc"},
	{"blowfish", "bf-cbc"},
	{"aes", "aes-128-cbc"},
	{"aes-ecb", "aes-128-ecb"},
	{"aes-cbc", "aes-128-cbc"},
	{"aes-128", "aes-128-cbc"},
	{"rijndael", "aes-128-cbc"},
	{"rijndael-128", "aes-128-cbc"},
	{NULL, NULL}
};

int px_find_digest(const char *name, PX_MD **res);

int px_find_cipher(const char *name, PX_Cipher **res);

int px_get_pseudo_random_bytes(uint8 *dst, unsigned count);

time_t seed_time = 0;
time_t check_time = 0;

void system_reseed(void);

int px_get_random_bytes(uint8 *dst, unsigned count);

int px_add_entropy(const uint8 *data, unsigned count);

unsigned int_sha224_len(PX_MD *h);
unsigned int_sha224_block_len(PX_MD *h);
void int_sha224_update(PX_MD *h, const uint8 *data, unsigned dlen);
void int_sha224_reset(PX_MD *h);
void int_sha224_finish(PX_MD *h, uint8 *dst);
void int_sha224_free(PX_MD *h);
unsigned int_sha256_len(PX_MD *h);
unsigned int_sha256_block_len(PX_MD *h);
void int_sha256_update(PX_MD *h, const uint8 *data, unsigned dlen);
void int_sha256_reset(PX_MD *h);
void int_sha256_finish(PX_MD *h, uint8 *dst);
void int_sha256_free(PX_MD *h);
unsigned int_sha384_len(PX_MD *h);
unsigned int_sha384_block_len(PX_MD *h);
void int_sha384_update(PX_MD *h, const uint8 *data, unsigned dlen);
void int_sha384_reset(PX_MD *h);
void int_sha384_finish(PX_MD *h, uint8 *dst);
void int_sha384_free(PX_MD *h);
unsigned int_sha512_len(PX_MD *h);
unsigned int_sha512_block_len(PX_MD *h);
void int_sha512_update(PX_MD *h, const uint8 *data, unsigned dlen);
void int_sha512_reset(PX_MD *h);
void int_sha512_finish(PX_MD *h, uint8 *dst);
void int_sha512_free(PX_MD *h);
void init_sha224(PX_MD *md);
void init_sha256(PX_MD *md);
void init_sha384(PX_MD *md);
void init_sha512(PX_MD *md);

#endif
