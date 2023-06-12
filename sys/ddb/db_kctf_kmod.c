/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023, Bojan Novković <bnovkov@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/linker.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <ddb/ddb.h>
#include <ddb/db_ctf.h>

extern int _kctf_start;
extern int _kctf_end;

static linker_ctf_t klc;

static int
db_kctf_modevent(module_t mod, int type, void *unused)
{
  int error;
  size_t kctf_size;
        switch (type) {
        case MOD_LOAD:
          kctf_size = (vm_offset_t)&_kctf_end - (vm_offset_t)&_kctf_start;
          error = linker_init_kernel_ctf(linker_kernel_file, (const char*)&_kctf_start, kctf_size);
          if(error){
            return (EINVAL);
          }
          linker_ctf_get(linker_kernel_file, &klc);
          db_ctf_register(linker_kernel_file->filename, &klc);


                return (0);
        case MOD_UNLOAD:

          db_ctf_unregister(linker_kernel_file->filename);

                return (0);
        }
        return (EINVAL);
}

static moduledata_t db_kctf_mod = {
  "db_kctf",
  db_kctf_modevent,
  0
};
DECLARE_MODULE(db_kctf, db_kctf_mod, SI_SUB_DRIVERS, SI_ORDER_ANY);
MODULE_VERSION(db_kctf, 1);
