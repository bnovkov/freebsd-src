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

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ctf.h>
#include <sys/ctype.h>
#include <sys/linker.h>
#include <sys/malloc.h>

#include <ddb/ddb.h>
#include <ddb/db_lex.h>

#define CTFOFF_INVALID 0xffffffff

static linker_ctf_t kernel_ctf;
static bool ctf_loaded = false;

static int
db_ctfoff_init(linker_ctf_t *lc)
{
	const Elf_Sym *symp = lc->symtab;
	const ctf_header_t *hp = (const ctf_header_t *)lc->ctftab;
	// const uint8_t *ctfdata = lc->ctftab + sizeof(ctf_header_t);
	const size_t idwidth = 4;

	uint32_t *ctfoff;
	uint32_t objtoff = hp->cth_objtoff;

	/* Sanity check. */
	if (hp->cth_magic != CTF_MAGIC) {
		printf("%s: Bad magic value in CTF data in the kernel\n",
		    __func__);
		return (EINVAL);
	}

	if (lc->symtab == NULL) {
		printf("%s: No symbol table in the kernel image\n", __func__);
		return (EINVAL);
	}

	if (hp->cth_version != CTF_VERSION_3) {
		printf("%s: CTF V2 data encountered\n", __func__);
		return (EINVAL);
	}

	ctfoff = malloc(sizeof(uint32_t) * lc->nsym, M_TEMP, M_WAITOK);
	*lc->ctfoffp = ctfoff;

	for (int i = 0; i < lc->nsym; i++, ctfoff++, symp++) {
		if (symp->st_name == 0 || symp->st_shndx == SHN_UNDEF) {
			*ctfoff = CTFOFF_INVALID;
			continue;
		}

		switch (ELF_ST_TYPE(symp->st_info)) {
		case STT_OBJECT:
			if (objtoff >= hp->cth_funcoff ||
			    (symp->st_shndx == SHN_ABS &&
				symp->st_value == 0)) {
				*ctfoff = CTFOFF_INVALID;
				break;
			}

			*ctfoff = objtoff;
			objtoff += idwidth;
			break;

		default:
			*ctfoff = CTFOFF_INVALID;
			break;
		}
	}

	return (0);
}

static void
db_initctf(void *dummy __unused)
{
	int err;

	memset((void *)&kernel_ctf, 0, sizeof(linker_ctf_t));

	err = linker_ctf_get(linker_kernel_file, &kernel_ctf);
	if (err) {
		printf("%s: linker_ctf_get error: %d\n", __func__, err);
		return;
	}

	/* Initialize mapping of symbols to object offsets */
	err = db_ctfoff_init(&kernel_ctf);
	if (err) {
		printf("%s: db_ctfoff_init error: %d\n", __func__, err);
		return;
	}

	printf("%s: loaded kernel CTF info\n", __func__);

	ctf_loaded = true;
}

static void
db_freectf(void *dummy __unused)
{
	if (!ctf_loaded) {
		return;
	}

	free(*kernel_ctf.ctfoffp, M_TEMP);

	printf("%s: freed kernel CTF info\n", __func__);
}

SYSINIT(ddb_initctf, SI_SUB_TUNABLES, SI_ORDER_ANY, db_initctf, NULL);
SYSUNINIT(ddb_freectf, SI_SUB_TUNABLES, SI_ORDER_ANY, db_freectf, NULL);



static int
db_pprint_symbol(const Elf_Sym *sym)
{
  const size_t off = sym - kernel_ctf.symtab;
  uint32_t objtoff = (*kernel_ctf.ctfoffp)[off];

  /* Sanity check - should not happen */
  if(objtoff == CTFOFF_INVALID){
    // 	db_printf("Error");
    return -1;
  }


	return 0;
}

static Elf_Sym *
lookup_symbol(const char *name)
{
	Elf_Sym *sp;
	const Elf_Sym *endp = kernel_ctf.symtab + kernel_ctf.nsym;

	for (sp = __DECONST(Elf_Sym *, kernel_ctf.symtab); sp < endp; sp++) {
		if (sp->st_name &&
		    (strcmp(kernel_ctf.strtab + sp->st_name, name) == 0)) {
			return sp;
		}
	}

	return (NULL);
}

DB_COMMAND_FLAGS(pprint, db_pprint_cmd, CS_OWN)
{
	int t; //, err;
	Elf_Sym *sym;

	if (!ctf_loaded) {
		db_error("Kernel CTF data not present\n");
	}

	t = db_read_token();
	if (t != tIDENT) {
		db_error("Invalid argument");
	}

	db_printf("Arg: %s\n", db_tok_string);

	sym = lookup_symbol(db_tok_string);
	if (sym == NULL) {
		db_error("Symbol not found\n");
	}

  if(ELF_ST_TYPE(sym->st_info) != STT_OBJECT){
    db_error("Symbol is not a variable\n");
  }

	db_printf("Addr: %p\n", (void *)sym->st_value);
  db_pprint_symbol(sym);
}
