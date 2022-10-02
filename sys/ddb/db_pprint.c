/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 1983, 1991, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/ctype.h>
#include <ddb/ddb.h>
#include <ddb/db_lex.h>

#include <sys/linker.h>

#include <sys/types.h>
#include <sys/systm.h>


static linker_ctf_t kernel_ctf;
static bool ctf_loaded = false;

static void
db_initctf(void *dummy __unused)
{
  int err;

  err = linker_ctf_get(linker_kernel_file, &kernel_ctf);
  if(err){
    printf("%s: linker_ctf_get error: %d\n", __func__, err);
    return;
  }

  printf("%s: loaded kernel CTF info\n", __func__);
  ctf_loaded = true;
}
SYSINIT(ddb_initctf, SI_SUB_TUNABLES, SI_ORDER_ANY, db_initctf, NULL);

DB_COMMAND_FLAGS(pprint, db_pprint_cmd, CS_OWN)
{
  int t;//, err;
  db_expr_t e;

  if(!ctf_loaded){
    db_error("Kernel CTF data not present\n");
  }

  t = db_read_token();
  if (t != tIDENT){
    db_error("Invalid argument");
  }

  db_printf("Arg: %s\n", db_tok_string);

  if(!db_value_of_name(db_tok_string, &e)){
    db_error("Symbol not found\n");
  }

  db_printf("Addr: %p\n", (void*)e);
}
