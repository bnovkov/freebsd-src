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
#include <sys/ctype.h>
#include <sys/linker.h>

#include <ddb/ddb.h>
#include <ddb/db_access.h>
#include <ddb/db_lex.h>
#include <ddb/db_sym.h>
#include <ddb/db_ctf.h>


static void db_pprint_type(db_expr_t addr, struct ctf_type_v3 *type);


/*
 * Command arguments.
 */
static bool ishex = false;


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
  size_t nbytes = (bits / 8) ? (bits / 8) : 1;
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

			struct ctf_type_v3 *mtype = db_ctf_typeid_to_type(mp->ctm_type);
			db_expr_t maddr = addr + mp->ctm_offset;

			mname = db_ctf_stroff_to_str(mp->ctm_name);
      if(mname)
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

			struct ctf_type_v3 *mtype = db_ctf_typeid_to_type(
			    mp->ctlm_type);
			db_expr_t maddr = addr + CTF_LMEM_OFFSET(mp);

			mname = db_ctf_stroff_to_str(mp->ctlm_name);
      if(mname)
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
	elem_type = db_ctf_typeid_to_type(arr->cta_contents);
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
			valname = db_ctf_stroff_to_str(ep->cte_name);
      if(valname)
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

	ref_type = db_ctf_typeid_to_type(type->ctt_type);
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

	name = db_ctf_stroff_to_str(ref_type->ctt_name);
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

  if (type == NULL){
    db_printf("unknown type");
    return;
  }

	switch (CTF_V3_INFO_KIND(type->ctt_info)) {
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
		struct ctf_type_v3 *ref_type = db_ctf_typeid_to_type(type->ctt_type);
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

	if (db_pager_quit) {
		return -1;
	}


	type = db_ctf_sym_to_type(sym);
	if (!type) {
		db_printf("Cant find CTF type info\n");
		return -1;
	}

	db_pprint_type(addr, type);

	return 0;
}

/*
 * Pretty print an address.
 * Syntax: pprint [/dx] addr
 */
void db_pprint_cmd(db_expr_t addr, bool have_addr, db_expr_t count, char *modif)
{
	int t; //, err;
	Elf_Sym *sym;
  db_expr_t off;

	ishex = false;

	if (!db_ctf_loaded()) {
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

	if (t != tNUMBER) {
		db_error("Invalid address");
	}

  addr = db_tok_number;
	db_printf("Addr: 0x%lx\n", addr);

	sym = __DECONST(Elf_Sym *, db_search_symbol(addr, DB_STGY_ANY, &off));
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
