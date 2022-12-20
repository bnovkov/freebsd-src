
#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ctype.h>
#include <sys/linker.h>

#include <ddb/ddb.h>
#include <ddb/db_ctf.h>



static struct ddb_ctf {
  linker_ctf_t kernel_ctf;
  bool loaded;
} db_ctf;

static
void db_ctf_init(void* arg)
{
	int err;

	memset((void *)&db_ctf, 0, sizeof(db_ctf));

	err = linker_ctf_get_ddb(linker_kernel_file, &db_ctf.kernel_ctf);
	if (err) {
		printf("%s: linker_ctf_get_ddb error: %d\n", __func__, err);
		return;
	}

	printf("%s: loaded kernel CTF info\n", __func__);

	db_ctf.loaded = true;
}

SYSINIT(db_ctf, SI_SUB_KLD, SI_ORDER_FOURTH, db_ctf_init, NULL);


bool db_ctf_loaded(void){
  return db_ctf.loaded;
}

const ctf_header_t *db_ctf_fetch_cth(void){
  return (const ctf_header_t *)db_ctf.kernel_ctf.ctftab;
}

static uint32_t
sym_to_objtoff(const Elf_Sym *sym, const Elf_Sym *symtab, const Elf_Sym *symtab_end)
{
  const ctf_header_t *hp = db_ctf_fetch_cth();
	uint32_t objtoff = hp->cth_objtoff;
	const size_t idwidth = 4;

  /* Ignore non-object symbols */
  if(ELF_ST_TYPE(sym->st_info) != STT_OBJECT){
    return DB_CTF_OBJTOFF_INVALID;
  }

  /* Sanity check */
  if(!(sym >= symtab && sym <= symtab_end)){
    return DB_CTF_OBJTOFF_INVALID;
  }

	for (const Elf_Sym *symp = symtab; symp < symtab_end; symp++) {
    /* Make sure we do not go beyond the objtoff section */
    if(objtoff >= hp->cth_funcoff){
      objtoff = DB_CTF_OBJTOFF_INVALID;
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

const char *
db_ctf_stroff_to_str(uint32_t off)
{
  const ctf_header_t *hp = db_ctf_fetch_cth();
	uint32_t stroff = hp->cth_stroff + off;

	if (stroff >= (hp->cth_stroff + hp->cth_strlen)) {
		return "invalid";
	}

	const char *ret = ((const char *)hp + sizeof(ctf_header_t)) + stroff;
	if (*ret == '\0'){
		return NULL;
  }

	return ret;
}


struct ctf_type_v3 *
db_ctf_sym_to_type(const Elf_Sym *sym)
{
	uint32_t objtoff, typeid;
	struct ctf_type_v3 *symtype = NULL;
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

	typeid = *(const uint32_t *)(db_ctf.kernel_ctf.ctftab + sizeof(ctf_header_t) +
	    objtoff);
	symtype = db_ctf_typeid_to_type(typeid);
  if(!symtype){
    return (NULL);
  }

	const char *name = db_ctf_stroff_to_str(symtype->ctt_name);

	db_printf("Obj offset: %x\n", objtoff);
	db_printf("Type ID: %d\n", typeid);
	db_printf("Type kind: %d\n", CTF_V3_INFO_KIND(symtype->ctt_info));
	db_printf("Type name: %s\n", name);

	return symtype;
}
