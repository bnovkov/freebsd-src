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

static void db_pprint_type(db_expr_t addr, struct ctf_type_v3 *type);

static linker_ctf_t kernel_ctf;
static bool ctf_loaded = false;

/*
 * Command arguments.
 */
static bool ishex = false;

static __inline const ctf_header_t *fetch_ctf_hp(void){
  if(!ctf_loaded){
    return (NULL);
  }

  return (const ctf_header_t *)kernel_ctf.ctftab;
}

static void
db_initctf(void *dummy __unused)
{
	int err;
  const ctf_header_t *hp;

	memset((void *)&kernel_ctf, 0, sizeof(linker_ctf_t));

	err = linker_ctf_get(linker_kernel_file, &kernel_ctf);
	if (err) {
		printf("%s: linker_ctf_get error: %d\n", __func__, err);
		return;
	}

  hp = (const ctf_header_t *)kernel_ctf.ctftab;

  /* Sanity check. */
	if (hp->cth_magic != CTF_MAGIC) {
		printf("%s: bad kernel CTF magic value\n",
           __func__);
		return;
	}

  if (kernel_ctf.symtab == NULL) {
		printf("%s: kernel symbol table missing\n", __func__);
		return;
	}

	if (hp->cth_version != CTF_VERSION_3) {
		printf("%s: CTF V2 data encountered\n", __func__);
		return;
	}

	printf("%s: loaded kernel CTF info\n", __func__);

	ctf_loaded = true;
}

static void
db_freectf(void *dummy __unused)
{
	printf("%s: freed kernel CTF info\n", __func__);
}

SYSINIT(ddb_initctf, SI_SUB_TUNABLES, SI_ORDER_ANY, db_initctf, NULL);
SYSUNINIT(ddb_freectf, SI_SUB_TUNABLES, SI_ORDER_ANY, db_freectf, NULL);

static uint32_t
sym_to_objtoff(const Elf_Sym *sym, const Elf_Sym *symtab, const Elf_Sym *symtab_end)
{
  const ctf_header_t *hp = fetch_ctf_hp();
	uint32_t objtoff = hp->cth_objtoff;
	const size_t idwidth = 4;

  /* Ignore non-object symbols */
  if(ELF_ST_TYPE(sym->st_info) != STT_OBJECT){
    return OBJTOFF_INVALID;
  }

  /* Sanity check */
  if(!(sym >= symtab && sym <= symtab_end)){
    return OBJTOFF_INVALID;
  }

	for (const Elf_Sym *symp = symtab; symp < symtab_end; symp++) {
    /* Make sure we do not go beyond the objtoff section */
    if(objtoff >= hp->cth_funcoff){
      objtoff = OBJTOFF_INVALID;
      break;
    }

		if (symp->st_name == 0 || symp->st_shndx == SHN_UNDEF) {
  		continue;
		}

    if ((symp->st_shndx == SHN_ABS &&
         symp->st_value == 0)) {
      continue;
    }

    /* Skip scope symbols */
    /*
      char *name;

    // TODO: fetch elf symtab
    name = (const char	*)(strbase + sym.st_name);
    if	(strcmp(name, "_START_") == 0 || strcmp(name, "_END_") == 0){
      continue;
    }
    */

    /* Skip non-object symbols */
	  if (ELF_ST_TYPE(symp->st_info) != STT_OBJECT) {
			continue;
		}

    if(symp == sym){
      break;
    }

    objtoff += idwidth;
	}

  return objtoff;
}

static struct ctf_type_v3 *
typeid_to_type(uint32_t typeid)
{
  const ctf_header_t *hp = fetch_ctf_hp();
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
    if(cur_typeid == typeid){
      break;
    }

		cur_typeid++;
		typeoff += type_struct_size + skiplen;
	}

  if(typeoff < stroff){
    return (struct ctf_type_v3 *)(__DECONST(uint8_t *, ctfstart) + typeoff);
  } else { /* A type struct was not found */
    return (NULL);
  }
}

static const char *
stroff_to_str(uint32_t off)
{
  const ctf_header_t *hp = fetch_ctf_hp();
	uint32_t stroff = hp->cth_stroff + off;

	if (stroff >= (hp->cth_stroff + hp->cth_strlen)) {
		return "invalid";
	}

	const char *ret = ((const char *)hp + sizeof(ctf_header_t)) + stroff;
	if (*ret == '\0')
		return NULL;

	return ret;
}

#define type_to_name(ctf_type) stroff_to_str((ctf_type)->ctt_name)

static struct ctf_type_v3 *
sym_to_type(const Elf_Sym *sym, const Elf_Sym *symtab, const Elf_Sym *symtab_end)
{
	uint32_t objtoff, typeid;
	struct ctf_type_v3 *symtype = NULL;

	if (sym == NULL) {
		return (NULL);
	}

	objtoff = sym_to_objtoff(sym, symtab, symtab_end);
	/* Sanity check - should not happen */
	if (objtoff == OBJTOFF_INVALID) {
		db_printf("Could not find CTF object offset.");
		return (NULL);
	}

	typeid = *(const uint32_t *)(kernel_ctf.ctftab + sizeof(ctf_header_t) +
	    objtoff);
	symtype = typeid_to_type(typeid);
  if(!symtype){
    return (NULL);
  }

	const char *name = type_to_name(symtype);

	db_printf("Obj offset: %x\n", objtoff);
	db_printf("Type ID: %d\n", typeid);
	db_printf("Type kind: %d\n", CTF_V3_INFO_KIND(symtype->ctt_info));
	db_printf("Type name: %s\n", name);

	return symtype;
}

/*
 * Type printing helper routines.
 */

#define INT_MODIFIER(ishex, size_modifier, issigned) \
	((ishex) ? "0x%" size_modifier "x" : ((issigned) ? "%ld" : "%lu"));

static inline void
db_pprint_int(db_expr_t addr, struct ctf_type_v3 *type)
{
	char *modifier;

	if (db_pager_quit) {
		return;
	}

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
		modifier = ischar ? "%c" : INT_MODIFIER(ishex, "hh", sign);
		break;
	default:
		db_printf("Invalid size '%d' found for integer type\n", bits);
		return;
	}
  size_t nbytes = (bits / 8) ? (bits / 8) : 0;
	db_printf(modifier, db_get_value(addr, nbytes, sign));
}

static inline void
db_pprint_struct(db_expr_t addr, struct ctf_type_v3 *type)
{
	const char *mname;

	size_t type_struct_size = ((type->ctt_size == CTF_V3_LSIZE_SENT) ?
		sizeof(struct ctf_type_v3) :
		sizeof(struct ctf_stype_v3));
	ssize_t struct_size = ((type->ctt_size == CTF_V3_LSIZE_SENT) ?
		CTF_TYPE_LSIZE(type) :
		type->ctt_size);
	u_int vlen = CTF_V3_INFO_VLEN(type->ctt_info);

	if (db_pager_quit) {
		return;
	}

	db_printf("{\n");

	if (struct_size < CTF_V3_LSTRUCT_THRESH) {
		struct ctf_member_v3 *mp, *endp;

		mp = (struct ctf_member_v3 *)((db_expr_t)type +
		    type_struct_size);
		endp = mp + vlen;

		for (; mp < endp; mp++) {
			if (db_pager_quit) {
				return;
			}

			struct ctf_type_v3 *mtype = typeid_to_type(mp->ctm_type);
			db_expr_t maddr = addr + mp->ctm_offset;

			mname = stroff_to_str(mp->ctm_name);
			db_printf("%s = ", mname);

			db_pprint_type(maddr, mtype);
			db_printf(", ");
		}
	} else {
		struct ctf_lmember_v3 *mp, *endp;
		mp = (struct ctf_lmember_v3 *)((db_expr_t)type +
		    type_struct_size);
		endp = mp + vlen;

		for (; mp < endp; mp++) {
			if (db_pager_quit) {
				return;
			}

			struct ctf_type_v3 *mtype = typeid_to_type(
			    mp->ctlm_type);
			db_expr_t maddr = addr + CTF_LMEM_OFFSET(mp);

			mname = stroff_to_str(mp->ctlm_name);
			db_printf("%s = ", mname);

			db_pprint_type(maddr, mtype);
			db_printf(", ");
		}
	}

	db_printf("\n}");
}

static inline void
db_pprint_arr(db_expr_t addr, struct ctf_type_v3 *type)
{
	struct ctf_array_v3 *arr;
	struct ctf_type_v3 *elem_type;
	size_t elem_size;
	size_t type_struct_size = ((type->ctt_size == CTF_V3_LSIZE_SENT) ?
		sizeof(struct ctf_type_v3) :
		sizeof(struct ctf_stype_v3));

	arr = (struct ctf_array_v3 *)((db_expr_t)type + type_struct_size);
	elem_type = typeid_to_type(arr->cta_contents);
	elem_size = ((elem_type->ctt_size == CTF_V3_LSIZE_SENT) ?
		CTF_TYPE_LSIZE(elem_type) :
		elem_type->ctt_size);

	db_expr_t elem_addr = addr;
	db_expr_t end = addr + (arr->cta_nelems * elem_size);

	db_printf("[");
	for (; elem_addr < end; elem_addr += elem_size) {
		if (db_pager_quit) {
			return;
		}

		db_pprint_type(elem_addr, elem_type);

		if ((elem_addr + elem_size) < end)
			db_printf(", ");
	}
	db_printf("]\n");
}

static inline void
db_pprint_enum(db_expr_t addr, struct ctf_type_v3 *type)
{
	struct ctf_enum *ep, *endp;
	const char *valname;
	u_int vlen = CTF_V3_INFO_VLEN(type->ctt_info);
	int32_t val = db_get_value(addr, sizeof(int), 0);
	size_t type_struct_size = ((type->ctt_size == CTF_V3_LSIZE_SENT) ?
		sizeof(struct ctf_type_v3) :
		sizeof(struct ctf_stype_v3));

  if (db_pager_quit) {
		return;
	}


	ep = (struct ctf_enum *)((db_expr_t)type + type_struct_size);
	endp = ep + vlen;

	for (; ep < endp; ep++) {
		if (val == ep->cte_value) {
			valname = stroff_to_str(ep->cte_name);
			db_printf("%s ", valname);
			db_printf((ishex ? "(0x%x)" : "(%d)"), val);
			break;
		}
	}
}

static inline void
db_pprint_ptr(db_expr_t addr, struct ctf_type_v3 *type)
{
	const char *qual = "";
	const char *name;
	struct ctf_type_v3 *ref_type;
	u_int kind;
	db_expr_t val;

	ref_type = typeid_to_type(type->ctt_type);
	kind = CTF_V3_INFO_KIND(ref_type->ctt_info);

	switch (kind) {
	case CTF_K_STRUCT:
		qual = "struct ";
		break;
	case CTF_K_VOLATILE:
		qual = "volatile ";
		break;
	case CTF_K_CONST:
		qual = "const ";
		break;
	default:
		break;
	}

	val = db_get_value(addr, sizeof(db_expr_t), false);

	name = stroff_to_str(ref_type->ctt_name);
	if (name)
		db_printf("(%s%s *)", qual, name);

	db_printf("0x%lx", val);
}

static void
db_pprint_type(db_expr_t addr, struct ctf_type_v3 *type)
{

	if (db_pager_quit) {
		return;
	}

	u_int kind = CTF_V3_INFO_KIND(type->ctt_info);

	switch (kind) {
	case CTF_K_INTEGER:
		db_pprint_int(addr, type);
		break;
	case CTF_K_UNION:
	case CTF_K_STRUCT:
		db_pprint_struct(addr, type);
		break;
	case CTF_K_FUNCTION:
	case CTF_K_FLOAT:
		db_printf(ishex ? "0x%lx" : "%lu", addr);
		break;
	case CTF_K_POINTER:
		db_pprint_ptr(addr, type);
		break;
	case CTF_K_TYPEDEF:
	case CTF_K_VOLATILE:
	case CTF_K_RESTRICT:
	case CTF_K_CONST: {
		struct ctf_type_v3 *ref_type = typeid_to_type(type->ctt_type);
		db_pprint_type(addr, ref_type);
		break;
	}
	case CTF_K_ENUM:
		db_pprint_enum(addr, type);
		break;
	case CTF_K_ARRAY:
		db_pprint_arr(addr, type);
		break;
	case CTF_K_UNKNOWN:
	case CTF_K_FORWARD:
	default:
		break;
	}

	return;
}

static int
db_pprint_symbol(const Elf_Sym *sym)
{
	db_expr_t addr = sym->st_value;
	struct ctf_type_v3 *type;
  const Elf_Sym *symtab, *symtab_end;

	if (db_pager_quit) {
		return -1;
	}

  symtab = kernel_ctf.symtab;
  symtab_end = symtab + kernel_ctf.nsym;

	type = sym_to_type(sym, symtab, symtab_end);
	if (!type) {
		db_printf("Cant find CTF type info\n");
		return -1;
	}

	db_pprint_type(addr, type);

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
 * Pretty print an ELF object symbol.
 * Syntax: pprint [/dx] name
 */
DB_COMMAND_FLAGS(pprint, db_pprint_cmd, CS_OWN)
{
	int t; //, err;
	Elf_Sym *sym;

	ishex = false;

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
			ishex = true;
		} else if (!strcmp(db_tok_string, "d")) {
			ishex = false;
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
	if (db_pprint_symbol(sym)) {
		db_error("");
	}
}
