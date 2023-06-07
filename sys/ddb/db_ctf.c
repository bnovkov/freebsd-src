/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022  <bojan.novkovic@kset.org>
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
#include <sys/ctype.h>
#include <sys/linker.h>
#include <sys/mutex.h>
#include <sys/malloc.h>

#include <ddb/db_ctf.h>
#include <ddb/ddb.h>

struct db_ctf {
	linker_ctf_t *lc;
  char *modname;
  LIST_ENTRY(db_ctf) link;
};

static LIST_HEAD(, db_ctf) ctf_table;
static struct mtx db_ctf_mtx;
MTX_SYSINIT(db_ctf, &db_ctf_mtx, "ddb module CTF data registry", MTX_DEF);

static MALLOC_DEFINE(M_DBCTF, "ddb ctf", "ddb module ctf data");

static struct db_ctf *
db_ctf_lookup(char *modname)
{
  struct db_ctf *dcp;

  LIST_FOREACH(dcp, &ctf_table, link) {
		if (dcp->modname != NULL && strcmp(modname, dcp->modname) == 0)
			break;
	}

  return (dcp);
}

int
db_ctf_register(const char *modname, linker_ctf_t *lc)
{
  struct db_ctf *dcp;

  mtx_lock(&db_ctf_mtx);
  if(db_ctf_lookup(modname) != NULL){
    mtx_unlock(&db_ctf_mtx);
    printf("%s: ddb CTF data for module %s already loaded!\n",
           __func__, modname);

    return (EINVAL);
  }
  mtx_unlock(&db_ctf_mtx);

  dcp = malloc(sizeof(struct db_ctf), M_DBCTF, M_WAITOK);
  dcp->modname = strdup(modname, M_DBCTF);
  dcp->lc = lc;

  mtx_lock(&db_ctf_mtx);
  LIST_INSERT_HEAD(&ctf_table, dcp, link);
  mtx_unlock(&db_ctf_mtx);

  return (0);
}

const ctf_header_t *
db_ctf_fetch_cth(void)
{
	return (const ctf_header_t *)db_ctf.kernel_ctf.ctftab;
}

static uint32_t
sym_to_objtoff(const Elf_Sym *sym, const Elf_Sym *symtab,
    const Elf_Sym *symtab_end)
{
	const ctf_header_t *hp = db_ctf_fetch_cth();
	uint32_t objtoff = hp->cth_objtoff;
	const size_t idwidth = 4;

	/* Ignore non-object symbols */
	if (ELF_ST_TYPE(sym->st_info) != STT_OBJECT) {
		return DB_CTF_OBJTOFF_INVALID;
	}

	/* Sanity check */
	if (!(sym >= symtab && sym <= symtab_end)) {
		return DB_CTF_OBJTOFF_INVALID;
	}

	for (const Elf_Sym *symp = symtab; symp < symtab_end; symp++) {
		/* Make sure we do not go beyond the objtoff section */
		if (objtoff >= hp->cth_funcoff) {
			objtoff = DB_CTF_OBJTOFF_INVALID;
			break;
		}

		if (symp->st_name == 0 || symp->st_shndx == SHN_UNDEF) {
			continue;
		}

		if ((symp->st_shndx == SHN_ABS && symp->st_value == 0)) {
			continue;
		}

		/* Skip non-object symbols */
		if (ELF_ST_TYPE(symp->st_info) != STT_OBJECT) {
			continue;
		}

		if (symp == sym) {
			break;
		}

		objtoff += idwidth;
	}

	return objtoff;
}

struct ctf_type_v3 *
db_ctf_typeid_to_type(uint32_t typeid)
{
	const ctf_header_t *hp = db_ctf_fetch_cth();
	const uint8_t *ctfstart = (const uint8_t *)hp + sizeof(ctf_header_t);

	uint32_t typeoff = hp->cth_typeoff;
	uint32_t stroff = hp->cth_stroff;
	/* CTF typeids start at 0x1 */
	size_t cur_typeid = 1;

	/* Find corresponding type */
	while (typeoff < stroff) {
		u_int vlen, kind, size;
		size_t skiplen, type_struct_size;
		struct ctf_type_v3 *t =
		    (struct ctf_type_v3 *)(__DECONST(uint8_t *, ctfstart) +
			typeoff);

		vlen = CTF_V3_INFO_VLEN(t->ctt_info);
		kind = CTF_V3_INFO_KIND(t->ctt_info);
		size = ((t->ctt_size == CTF_V3_LSIZE_SENT) ? CTF_TYPE_LSIZE(t) :
							     t->ctt_size);
		type_struct_size = ((t->ctt_size == CTF_V3_LSIZE_SENT) ?
			sizeof(struct ctf_type_v3) :
			sizeof(struct ctf_stype_v3));

		switch (kind) {
		case CTF_K_INTEGER:
		case CTF_K_FLOAT:
			skiplen = sizeof(uint32_t);
			break;
		case CTF_K_ARRAY:
			skiplen = sizeof(struct ctf_array_v3);
			break;
		case CTF_K_UNION:
		case CTF_K_STRUCT:
			skiplen = vlen *
			    ((size < CTF_V3_LSTRUCT_THRESH) ?
				    sizeof(struct ctf_member_v3) :
				    sizeof(struct ctf_lmember_v3));
			break;
		case CTF_K_ENUM:
			skiplen = vlen * sizeof(struct ctf_enum);
			break;
		case CTF_K_FUNCTION:
			skiplen = vlen * sizeof(uint32_t);
			break;
		case CTF_K_UNKNOWN:
		case CTF_K_FORWARD:
		case CTF_K_POINTER:
		case CTF_K_TYPEDEF:
		case CTF_K_VOLATILE:
		case CTF_K_CONST:
		case CTF_K_RESTRICT:
			skiplen = 0;
			break;
		default:
			db_printf("Error: invalid CTF type kind encountered\n");
			return (NULL);
		}

		/* We found the type struct */
		if (cur_typeid == typeid) {
			break;
		}

		cur_typeid++;
		typeoff += type_struct_size + skiplen;
	}

	if (typeoff < stroff) {
		return (struct ctf_type_v3 *)(__DECONST(uint8_t *, ctfstart) +
		    typeoff);
	} else { /* A type struct was not found */
		return (NULL);
	}
}

const char *
db_ctf_stroff_to_str(uint32_t off)
{
	const ctf_header_t *hp = db_ctf_fetch_cth();
	uint32_t stroff = hp->cth_stroff + off;

	if (stroff >= (hp->cth_stroff + hp->cth_strlen)) {
		return "invalid";
	}

	const char *ret = ((const char *)hp + sizeof(ctf_header_t)) + stroff;
	if (*ret == '\0') {
		return NULL;
	}

	return ret;
}

struct ctf_type_v3 *
db_ctf_sym_to_type(const Elf_Sym *sym)
{
	uint32_t objtoff, typeid;
	const Elf_Sym *symtab, *symtab_end;

	if (sym == NULL) {
		return (NULL);
	}

	symtab = db_ctf.kernel_ctf.symtab;
	symtab_end = symtab + db_ctf.kernel_ctf.nsym;

	objtoff = sym_to_objtoff(sym, symtab, symtab_end);
	/* Sanity check - should not happen */
	if (objtoff == DB_CTF_OBJTOFF_INVALID) {
		db_printf("Could not find CTF object offset.");
		return (NULL);
	}

	typeid = *(const uint32_t *)(db_ctf.kernel_ctf.ctftab +
	    sizeof(ctf_header_t) + objtoff);

	return db_ctf_typeid_to_type(typeid);
}
