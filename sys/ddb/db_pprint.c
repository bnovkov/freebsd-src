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
#include <ddb/db_access.h>
#include <ddb/db_lex.h>

#define OBJTOFF_INVALID 0xffffffff

static linker_ctf_t kernel_ctf;
static bool ctf_loaded = false;

static int
init_typeoff(linker_ctf_t *lc, const ctf_header_t *hp)
{
	uint32_t *typoff;
	uint32_t typeoff = hp->cth_typeoff;
	uint32_t stroff = hp->cth_stroff;

	const uint8_t *ctfstart = lc->ctftab + sizeof(ctf_header_t);
	size_t typecnt = 0;

	/* Initialize type offsets */
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

		skiplen = 0;

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
			break;
		default:
			return (EINVAL);
		}

		typecnt++;
		typeoff += type_struct_size + skiplen;
	}

	typoff = malloc(sizeof(uint32_t) * (typecnt + 1), M_TEMP, M_WAITOK);
	*lc->typoffp = typoff;

	typeoff = hp->cth_typeoff;
	size_t cur_typeid = 0;

	/* Populate type offsets array */
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
			return (EINVAL);
		}

		typoff[cur_typeid + 1] = typeoff;
		cur_typeid++;
		typeoff += type_struct_size + skiplen;
	}

	printf("%s: total typeoff: %x, header stroff: %x, ntypes: %zu\n",
	    __func__, typeoff, stroff, typecnt);

	return (0);
}

/* Initialize object offsets*/
static int
init_objtoff(linker_ctf_t *lc, const ctf_header_t *hp)
{
	uint32_t *ctfoff;
	uint32_t objtoff = hp->cth_objtoff;
	const Elf_Sym *symp = lc->symtab;
	const size_t idwidth = 4;

	ctfoff = malloc(sizeof(uint32_t) * lc->nsym, M_TEMP, M_WAITOK);
	*lc->ctfoffp = ctfoff;

	for (int i = 0; i < lc->nsym; i++, ctfoff++, symp++) {
		if (symp->st_name == 0 || symp->st_shndx == SHN_UNDEF) {
			*ctfoff = OBJTOFF_INVALID;
			continue;
		}

		switch (ELF_ST_TYPE(symp->st_info)) {
		case STT_OBJECT:
			if (objtoff >= hp->cth_funcoff ||
			    (symp->st_shndx == SHN_ABS &&
				symp->st_value == 0)) {
				*ctfoff = OBJTOFF_INVALID;
				break;
			}

			*ctfoff = objtoff;
			objtoff += idwidth;
			break;

		default:
			*ctfoff = OBJTOFF_INVALID;
			break;
		}
	}

	return (0);
}

static int
db_offsets_init(linker_ctf_t *lc)
{
	const ctf_header_t *hp = (const ctf_header_t *)lc->ctftab;

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

	if (init_objtoff(lc, hp)) {
		return (EINVAL);
	}

	if (init_typeoff(lc, hp)) {
		return (EINVAL);
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

	/* Initialize mapping of ELF symbols to object offsets */
	err = db_offsets_init(&kernel_ctf);
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
	free(*kernel_ctf.typoffp, M_TEMP);

	printf("%s: freed kernel CTF info\n", __func__);
}

SYSINIT(ddb_initctf, SI_SUB_TUNABLES, SI_ORDER_ANY, db_initctf, NULL);
SYSUNINIT(ddb_freectf, SI_SUB_TUNABLES, SI_ORDER_ANY, db_freectf, NULL);

static uint32_t
sym_to_objtoff(const Elf_Sym *sym)
{
	size_t sym_idx = sym - kernel_ctf.symtab;
	return (*kernel_ctf.ctfoffp)[sym_idx];
}

static uint32_t
typeid_to_typeoff(uint32_t typeid)
{
	return (*kernel_ctf.typoffp)[typeid];
}

static struct ctf_type_v3 *
sym_to_type(const Elf_Sym *sym)
{
	uint32_t objtoff, typeid, typeoff;
	struct ctf_type_v3 *symtype = NULL;
	const ctf_header_t *hp = (const ctf_header_t *)kernel_ctf.ctftab;

	if (sym == NULL) {
		return (NULL);
	}

	objtoff = sym_to_objtoff(sym);
	/* Sanity check - should not happen */
	if (objtoff == OBJTOFF_INVALID) {
		// 	db_printf("Error");
		return (NULL);
	}
	typeid = *(const uint32_t *)(kernel_ctf.ctftab + sizeof(ctf_header_t) +
	    objtoff);
	typeoff = typeid_to_typeoff(typeid);
	symtype = (struct ctf_type_v3 *)(__DECONST(uint8_t *,
					     kernel_ctf.ctftab) +
	    sizeof(ctf_header_t) + typeoff);
	const char *name = __DECONST(uint8_t *, kernel_ctf.ctftab) +
	    sizeof(ctf_header_t) + hp->cth_stroff + symtype->ctt_name;

	db_printf("Obj offset: %x\n", objtoff);
	db_printf("Type ID: %d\n", typeid);
	db_printf("Type offset: %x\n", typeoff);
	db_printf("Type kind: %d\n", CTF_V3_INFO_KIND(symtype->ctt_info));
	db_printf("Type name: %s\n", name);

	return symtype;
}

#define INT_MODIFIER(ishex, size_modifier, issigned)                 \
	((ishex) ? "0x%" size_modifier "x" : ((issigned) ? "%ld" : "%lu"));

static inline void db_pprint_int(db_expr_t addr, struct ctf_type_v3 * type, boolean_t ishex){
  char *modifier;
  size_t type_struct_size = ((type->ctt_size == CTF_V3_LSIZE_SENT) ?
                             sizeof(struct ctf_type_v3) :
                             sizeof(struct ctf_stype_v3));
  uint32_t data = db_get_value((db_expr_t)type + type_struct_size,
                               sizeof(uint32_t), 0);

  u_int bits = CTF_INT_BITS(data);
  boolean_t sign = !!(CTF_INT_ENCODING(data) & CTF_INT_SIGNED);
  boolean_t ischar = !!(CTF_INT_ENCODING(data) & CTF_INT_CHAR);



  switch (bits) {
  case 64:
    modifier = INT_MODIFIER(ishex, "l", sign);
    break;
  case 32:
    modifier = INT_MODIFIER(ishex, "", sign);
    break;
  case 16:
    modifier = INT_MODIFIER(ishex, "h", sign);
    break;
  case 8:
    modifier = ischar ? "%c" :
      INT_MODIFIER(ishex, "hh", sign);
    break;
  default:
    db_printf("Invalid size found for integer type\n");
    break;
  }

  db_printf(modifier, db_get_value(addr, bits / 8, sign));

}

static int
db_pprint_symbol(const Elf_Sym *sym, boolean_t hex)
{
	struct ctf_type_v3 *type;
	u_int kind;
	db_expr_t addr = sym->st_value;

	type = sym_to_type(sym);
	if (!type) {
		db_printf("Cant find CTF type info\n");
		return -1;
	}

	kind = CTF_V3_INFO_KIND(type->ctt_info);

	switch (kind) {
	case CTF_K_INTEGER:
    db_pprint_int(addr, type, hex);
		break;

	case CTF_K_FLOAT:
		break;
	default:
		break;
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

/*
 * Pretty print a symbol.
 * Syntax: pprint [/dx] name
 */
DB_COMMAND_FLAGS(pprint, db_pprint_cmd, CS_OWN)
{
	int t; //, err;
	Elf_Sym *sym;
	boolean_t hex = false;

	if (!ctf_loaded) {
		db_error("Kernel CTF data not present\n");
	}

	/* Parse print modifiers */
	t = db_read_token();
	if (t == tSLASH) {
		t = db_read_token();
		if (t != tIDENT) {
			db_error("Invalid modifier\n");
		}

		if (!strcmp(db_tok_string, "x")) {
			hex = true;
		} else if (!strcmp(db_tok_string, "d")) {
			hex = false;
		} else {
			db_error("Invalid modifier\n");
		}
		/* Fetch next token */
		t = db_read_token();
	}

	if (t != tIDENT) {
		db_error("Invalid argument");
	}

	db_printf("Arg: %s\n", db_tok_string);

	sym = lookup_symbol(db_tok_string);
	if (sym == NULL) {
		db_error("Symbol not found\n");
	}

	if (ELF_ST_TYPE(sym->st_info) != STT_OBJECT) {
		db_error("Symbol is not a variable\n");
	}

	db_printf("Addr: %p\n", (void *)sym->st_value);
	db_pprint_symbol(sym, hex);
}
