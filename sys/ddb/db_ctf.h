#ifndef _DDB_DB_CTF_H_
#define _DDB_DB_CTF_H_

#include <sys/types.h>
#include <sys/ctf.h>

#define DB_CTF_OBJTOFF_INVALID 0xffffffff


bool db_ctf_loaded(void);

const ctf_header_t * db_ctf_fetch_cth(void);
struct ctf_type_v3 * db_ctf_sym_to_type(const Elf_Sym *sym);
struct ctf_type_v3 * db_ctf_typeid_to_type(uint32_t typeid);
const char * db_ctf_stroff_to_str(uint32_t off);

#endif /* !_DDB_DB_CTF_H_ */


