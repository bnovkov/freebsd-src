#include <sys/types.h>
#include <err.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <gelf.h>
#include <libelf.h>
#include <string.h>
#include <stddef.h>

#include "../../../sys/sys/kpatch2.h"

#include "buildpatch.h"

static struct {
	int fd;
	Elf *elf;
	Elf_Scn *symtab_scn;
	GElf_Shdr symtab_shdr;
	Elf_Data *symtab_data;
	int symtab_count;
} kern;

static struct {
	int fd;
	Elf *elf;
	Elf_Scn *symtab_scn;
	Elf_Data *symtab_data;
	long shstrndx;
	Elf_Scn *shstr_scn;
	Elf_Data *shstr_data;
	Elf_Scn *relocs_scn;
	Elf_Scn *relocs_rela;
	Elf_Scn *funcs_scn;
	Elf_Scn *funcs_rela;
	Elf_Scn *sets_scn;
	Elf_Scn *sets_rela;
	struct set_metadata *sets_md;
	int sets_count;
	struct func_metadata *funcs_md;
	int funcs_count;
	struct reloc_metadata *relocs_md;
	int relocs_count;
} in_patch;

static struct {
	int fd;
	Elf *elf;
	unsigned *idx_map; 
	size_t idx_size;
	unsigned last_ndx;
} out_patch;

static void
open_kernel(const char *path)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;

	kern.fd = open(path, O_RDONLY);
	if (kern.fd < 0)
		errx(1, "Failed to open %s", path);

	kern.elf = elf_begin(kern.fd, ELF_C_READ, NULL);
	if (kern.elf == NULL)
		errx(1, "Failed to parse elf: %s", elf_errmsg(-1));

	if (elf_kind(kern.elf) != ELF_K_ELF)
		errx(1, "%s is not an ELF object", path);

	for (scn = NULL; (scn = elf_nextscn(kern.elf, scn)) != NULL; ) {
		if (gelf_getshdr(scn, &shdr) == NULL)
			errx(1, "gelf_getshdr failed: %s", elf_errmsg(-1));

		if (shdr.sh_type == SHT_SYMTAB)
			break;
	}

	if (scn == NULL)
		errx(1, "No .symtab section found in %s", path);

	if ((kern.symtab_data = elf_getdata(scn, NULL)) == NULL)
		errx(1, "elf_getdata failed: %s", elf_errmsg(-1));

	kern.symtab_scn = scn;
	kern.symtab_shdr = shdr;
	kern.symtab_count = shdr.sh_size / shdr.sh_entsize;
}

static void
close_kernel(void)
{
	elf_end(kern.elf);
	close(kern.fd);
}

static int
find_kernel_symbol(const char *func, const char *srcfile)
{
	int i, n;
	GElf_Sym sym;
	const char *name, *curfile;

	curfile = "";
	for (i = 0, n = 0; i < kern.symtab_count; i++) {
		if (gelf_getsym(kern.symtab_data, i, &sym) == NULL)
			errx(1, "gelf_getsym failed: %s", elf_errmsg(-1));

		name = elf_strptr(kern.elf, kern.symtab_shdr.sh_link, sym.st_name);
		if (name == NULL || *name == '\0')
			continue;

		if (GELF_ST_TYPE(sym.st_info) == STT_FILE) {
			curfile = name;
			continue;
		}

		if (GELF_ST_TYPE(sym.st_info) == STT_FUNC) {
			if (strcmp(name, func) != 0)
				continue;

			if (GELF_ST_BIND(sym.st_info) == STB_GLOBAL ||
				srcfile[0] == '\0' || !strcmp(curfile, srcfile)) {
				return (n);
			}

			n++;
			printf("Homonym of %s found at index %d\n", func, n);
		}
	}

	return (-1);
}

static void
open_patch(const char *in_path, const char *out_path)
{
	GElf_Ehdr ehdr;

	memset(&in_patch, 0, sizeof(in_patch));
	memset(&out_patch, 0, sizeof(out_patch));

	in_patch.fd = open(in_path, O_RDONLY);
	if (in_patch.fd < 0)
		errx(1, "Failed to open %s", in_path);

	in_patch.elf = elf_begin(in_patch.fd, ELF_C_READ, NULL);
	if (in_patch.elf == NULL)
		errx(1, "Failed to parse elf: %s", elf_errmsg(-1));

	out_patch.fd = open(out_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (out_patch.fd < 0)
		errx(1, "Failed to open %s", out_path);

	out_patch.elf = elf_begin(out_patch.fd, ELF_C_WRITE, NULL);
	if (out_patch.elf == NULL)
		errx(1, "Failed to parse elf: %s", elf_errmsg(-1));

	/* Copy ELF Header */
	gelf_getehdr(in_patch.elf, &ehdr);
	gelf_newehdr(out_patch.elf, gelf_getclass(in_patch.elf));
	gelf_update_ehdr(out_patch.elf, &ehdr);


	elf_getshdrstrndx(in_patch.elf, &in_patch.shstrndx);
	in_patch.shstr_scn = elf_getscn(in_patch.elf, in_patch.shstrndx);
	in_patch.shstr_data = elf_getdata(in_patch.shstr_scn, NULL);

	out_patch.idx_size = 1024;
	out_patch.idx_map = calloc(out_patch.idx_size, sizeof(unsigned));
}

static int
check_special_section(const char *name, Elf_Scn *scn)
{
	if (!strcmp(name, PATCH_RELOC_SECTION)) {
		in_patch.relocs_scn = scn;
		return (1);
	}

	if (!strcmp(name, ".rela" PATCH_RELOC_SECTION)) {
		in_patch.relocs_rela = scn;
		return (1);
	}

	if (!strcmp(name, PATCH_FUNC_SECTION)) {
		in_patch.funcs_scn = scn;
		return (1);
	}

	if (!strcmp(name, ".rela" PATCH_FUNC_SECTION)) {
		in_patch.funcs_rela = scn;
		return (1);
	}

	if (!strcmp(name, PATCH_SET_SECTION)) {
		in_patch.sets_scn = scn;
		return (1);
	}

	if (!strcmp(name, ".rela" PATCH_SET_SECTION)) {
		in_patch.sets_rela = scn;
		return (1);
	}

	return (0);
}

static inline void
index_map_set(unsigned ndx_in, unsigned ndx_out)
{
	if (ndx_in > out_patch.idx_size) {
		out_patch.idx_size++;
		out_patch.idx_map = realloc(out_patch.idx_map, sizeof(unsigned) * out_patch.idx_size);
	}

	out_patch.idx_map[ndx_in] = ndx_out;
}

static inline unsigned
index_map_get(unsigned ndx_in)
{
	if (ndx_in >= out_patch.idx_size)
		return 0;

	return out_patch.idx_map[ndx_in];
}

static size_t
add_shstrtab_string(const char *str)
{
	Elf_Scn *scn_out;
	GElf_Shdr shdr;
	Elf_Data *data_out;
	size_t str_len, offset;
	char *new_str;

	scn_out = elf_getscn(out_patch.elf, out_patch.idx_map[in_patch.shstrndx]);
	if (gelf_getshdr(scn_out, &shdr) == NULL)
		errx(1, "gelf_getshdr failed: %s", elf_errmsg(-1));

	offset = shdr.sh_size;
	str_len = strlen(str) + 1;
	new_str = strdup(str);

	data_out = elf_newdata(scn_out);
	if (data_out == NULL)
		errx(1, "elf_newdata failed: %s", elf_errmsg(-1));

	data_out->d_align = 1;
	data_out->d_buf = new_str;
	data_out->d_size = str_len;
	data_out->d_type = ELF_T_BYTE;
	data_out->d_version = EV_CURRENT;

	shdr.sh_size += str_len;
	if (gelf_update_shdr(scn_out, &shdr) == 0)
		errx(1, "gelf_update_shdr failed: %s", elf_errmsg(-1));

	return (offset);
}

static void
copy_patch_sections(void)
{
	Elf_Scn *scn_in, *scn_out;
	unsigned ndx_in, ndx_out;
	Elf_Data *data_in, *data_out;
        GElf_Shdr shdr;
	const char *name;

	scn_in = NULL;
	while ((scn_in = elf_nextscn(in_patch.elf, scn_in)) != NULL) {
		ndx_in = elf_ndxscn(scn_in);

		gelf_getshdr(scn_in, &shdr);
		name = elf_strptr(in_patch.elf, in_patch.shstrndx, shdr.sh_name);

		if (check_special_section(name, scn_in)) {
			printf("Dropping section %s\n", name);
			index_map_set(ndx_in, 0);
			continue;
		}

		scn_out = elf_newscn(out_patch.elf);
		ndx_out = elf_ndxscn(scn_out);
		index_map_set(ndx_in, ndx_out);
		printf("Copying section %s\n", name);

		if (ndx_out > out_patch.last_ndx)
			out_patch.last_ndx = ndx_out;

		data_in = NULL;
		while ((data_in = elf_getdata(scn_in, data_in)) != NULL) {
			data_out = elf_newdata(scn_out);
			*data_out = *data_in;
		}

		if (shdr.sh_type == SHT_SYMTAB) {
			in_patch.symtab_scn = scn_in;
			in_patch.symtab_data = elf_getdata(scn_in, NULL);
		}

		gelf_update_shdr(scn_out, &shdr);
	}
}

struct reloc_string {
	const char *str;
	GElf_Rela rela;
};

#define RELSTR_STR(rstr)	(((const struct reloc_string *)(const void *)rstr)->str)
#define RELSTR_RELA(rstr)	(((const struct reloc_string *)(const void *)rstr)->rela)

static const char * 
resolve_reloc_string(GElf_Rela rela)
{
	GElf_Sym sym;
	Elf_Scn *scn;
	Elf_Data *data;
	struct reloc_string *rstr;

	if (gelf_getsym(in_patch.symtab_data, GELF_R_SYM(rela.r_info), &sym) == NULL)
		errx(1, "gelf_getsym failed: %s", elf_errmsg(-1));

	scn = elf_getscn(in_patch.elf, sym.st_shndx);
	if (scn == NULL)
		return (NULL);

	data = elf_getdata(scn, NULL);
	if (data == NULL)
		return (NULL);

	rstr = malloc(sizeof(struct reloc_string));
	rstr->rela = rela;
	rstr->str = (const char *)data->d_buf + sym.st_value + rela.r_addend;

	return (const char *)rstr;
}

static void
parse_patch_sets(void)
{
	Elf_Data *data, *rela_data;
	GElf_Shdr rela_shdr;
	GElf_Rela rela;
	int i, nrelas;
	const char *str;

	data = elf_getdata(in_patch.sets_scn, NULL);
        rela_data = elf_getdata(in_patch.sets_rela, NULL);
        gelf_getshdr(in_patch.sets_rela, &rela_shdr);

        in_patch.sets_count = data->d_size / sizeof(struct set_metadata);
        in_patch.sets_md = malloc(data->d_size);
        memcpy(in_patch.sets_md, data->d_buf, data->d_size);

        nrelas = rela_shdr.sh_size / rela_shdr.sh_entsize;
        for (i = 0; i < nrelas; i++) {
		gelf_getrela(rela_data, i, &rela);
		str = resolve_reloc_string(rela);
		if (str == NULL)
			continue;

		memcpy((char *)in_patch.sets_md + rela.r_offset, &str, sizeof(const char *));
	}

	for (i = 0; i < in_patch.sets_count; i++) {
		printf("Parsed patch set:\n");
		printf("\tName: %s\n", RELSTR_STR(in_patch.sets_md[i].name));
		printf("\tFlags: %lx\n", in_patch.sets_md[i].flags);
	}
}

static void
parse_patch_funcs(void)
{
	Elf_Data *data, *rela_data;
	GElf_Shdr rela_shdr;
	GElf_Rela rela;
	int i, nrelas;
	const char *str;

	data = elf_getdata(in_patch.funcs_scn, NULL);
	rela_data = elf_getdata(in_patch.funcs_rela, NULL);
	gelf_getshdr(in_patch.funcs_rela, &rela_shdr);

	in_patch.funcs_count = data->d_size / sizeof(struct func_metadata);
	in_patch.funcs_md = malloc(data->d_size);
	memcpy(in_patch.funcs_md, data->d_buf, data->d_size);

	nrelas = rela_shdr.sh_size / rela_shdr.sh_entsize;
	for (i = 0; i < nrelas; i++) {
		gelf_getrela(rela_data, i, &rela);
		str = resolve_reloc_string(rela);
		if (str == NULL)
			continue;

		memcpy((char *)in_patch.funcs_md + rela.r_offset, &str, sizeof(const char *));
	}

	for (i = 0; i < in_patch.funcs_count; i++) {
		printf("Parsed patch func:\n");
		printf("\tPatch: %s\n", RELSTR_STR(in_patch.funcs_md[i].patch));
		printf("\tNew: %s\n", RELSTR_STR(in_patch.funcs_md[i].new_sym));
		printf("\tOld: %s\n", RELSTR_STR(in_patch.funcs_md[i].old_sym));
		printf("\tObj: %s\n", RELSTR_STR(in_patch.funcs_md[i].old_obj));
		if (in_patch.funcs_md[i].flags & PATCH_USING_SYMPOS) {
			printf("\tSympos: %ld\n", in_patch.funcs_md[i].uniquifier.sympos);
		} else {
			printf("\tFile: %s\n", RELSTR_STR(in_patch.funcs_md[i].uniquifier.old_file));
		}
		printf("\tFlags: %lx\n", in_patch.funcs_md[i].flags);
	}
}

static void
parse_patch_relocs(void)
{
	Elf_Data *data, *rela_data;
	GElf_Shdr rela_shdr;
	GElf_Rela rela;
	int i, nrelas;
	const char *str;

	data = elf_getdata(in_patch.relocs_scn, NULL);
	rela_data = elf_getdata(in_patch.relocs_rela, NULL);
	gelf_getshdr(in_patch.relocs_rela, &rela_shdr);

	in_patch.relocs_count = data->d_size / sizeof(struct reloc_metadata);
	in_patch.relocs_md = malloc(data->d_size);
	memcpy(in_patch.relocs_md, data->d_buf, data->d_size);

	nrelas = rela_shdr.sh_size / rela_shdr.sh_entsize;
	for (i = 0; i < nrelas; i++) {
		gelf_getrela(rela_data, i, &rela);
		str = resolve_reloc_string(rela);
		if (str == NULL)
			continue;

		memcpy((char *)in_patch.relocs_md + rela.r_offset, &str, sizeof(const char *));
	}

	for (i = 0; i < in_patch.relocs_count; i++) {
		printf("Parsed patch reloc:\n");
		printf("\tLocal: %s\n", RELSTR_STR(in_patch.relocs_md[i].local_sym));
		printf("\tReal: %s\n", RELSTR_STR(in_patch.relocs_md[i].real_sym));
		printf("\tObj: %s\n", RELSTR_STR(in_patch.relocs_md[i].real_obj));
		if (in_patch.relocs_md[i].flags & PATCH_USING_SYMPOS) {
			printf("\tSympos: %ld\n", in_patch.relocs_md[i].uniquifier.sympos);
		} else {
			printf("\tFile: %s\n", RELSTR_STR(in_patch.relocs_md[i].uniquifier.real_file));
		}
		printf("\tFlags: %lx\n", in_patch.relocs_md[i].flags);
	}
}

static void
parse_patch_metadata(void)
{
	if (!in_patch.sets_scn || !in_patch.sets_rela) 
		errx(1, "Invalid patch sets metadata section");

	parse_patch_sets();

	if (in_patch.funcs_scn && !in_patch.funcs_rela) 
		errx(1, "Invalid patch funcs metadata section");

	parse_patch_funcs();

	if (in_patch.relocs_scn && !in_patch.relocs_rela) 
		errx(1, "Invalid patch relocs metadata section");

	if (in_patch.relocs_scn && in_patch.relocs_rela) 
		parse_patch_relocs();
}

static Elf_Scn *
create_section(const char *name, uint32_t type, uint64_t flags,
    uint64_t addralign, uint64_t entsize, void *buf, size_t size)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	Elf_Data *data;

	size_t name_idx = add_shstrtab_string(name);
	scn = elf_newscn(out_patch.elf);
	if (scn == NULL)
		errx(1, "elf_newscn failed: %s", elf_errmsg(-1));

	if (gelf_getshdr(scn, &shdr) == NULL)
		errx(1, "gelf_getshdr failed: %s", elf_errmsg(-1));

	shdr.sh_name = name_idx;
	shdr.sh_type = type;
	shdr.sh_flags = flags;
	shdr.sh_addralign = addralign;
	shdr.sh_entsize = entsize;
	shdr.sh_size = size;
	gelf_update_shdr(scn, &shdr);

	data = elf_newdata(scn);
	if (data == NULL)
		errx(1, "elf_newdata failed: %s", elf_errmsg(-1));

	data->d_buf = buf;
	data->d_size = size;
	data->d_align = addralign;
	data->d_type = (type == SHT_RELA) ? ELF_T_RELA : ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	return (scn);
}

static Elf_Scn *
create_rela_section(const char *name, Elf_Scn *target_scn, GElf_Rela *relas, int count)
{
	Elf_Scn *rela_scn, *symtab_scn;
	GElf_Shdr shdr;

	symtab_scn = elf_getscn(out_patch.elf, index_map_get(elf_ndxscn(in_patch.symtab_scn)));

	rela_scn = create_section(name, SHT_RELA, SHF_INFO_LINK, 8,
				sizeof(GElf_Rela), relas, count * sizeof(GElf_Rela));

	gelf_getshdr(rela_scn, &shdr);
	shdr.sh_link = elf_ndxscn(symtab_scn);
	shdr.sh_info = elf_ndxscn(target_scn);
	gelf_update_shdr(rela_scn, &shdr);

	return (rela_scn);
}

static Elf_Scn *
create_kpatch_funcs(void)
{
	struct kpatch_func_metadata *funcs_buf;
	GElf_Rela *relas;
	Elf_Scn *scn;
	size_t total_size, f_off;
	const char *old_file;
	int i, relocs_count;

	total_size = in_patch.funcs_count * sizeof(struct kpatch_func_metadata);
	funcs_buf = calloc(in_patch.funcs_count, sizeof(struct kpatch_func_metadata));

	// Current number of relas for each func is 3
	relas = calloc(in_patch.funcs_count * 3, sizeof(GElf_Rela));

	for (i = 0; i < in_patch.funcs_count; i++) {
		f_off = i * sizeof(struct kpatch_func_metadata);

		if (in_patch.funcs_md[i].flags & PATCH_USING_SYMPOS) {
			funcs_buf[i].sympos = in_patch.funcs_md[i].uniquifier.sympos;
		} else {
			old_file = in_patch.funcs_md[i].uniquifier.old_file ? 
				RELSTR_STR(in_patch.funcs_md[i].uniquifier.old_file) : "";

			funcs_buf[i].sympos = find_kernel_symbol(
					RELSTR_STR(in_patch.funcs_md[i].old_sym), old_file);
		}

		funcs_buf[i].flags = in_patch.funcs_md[i].flags;

		/* Reuse old relocations from RELSTR_RELA */
		relocs_count = 0;
		if (in_patch.funcs_md[i].new_addr) {
			relas[relocs_count] = RELSTR_RELA(in_patch.funcs_md[i].new_addr);
			relas[relocs_count].r_offset = f_off + offsetof(struct kpatch_func_metadata, new_addr);
			relocs_count++;
		}
		if (in_patch.funcs_md[i].old_sym) {
			relas[relocs_count] = RELSTR_RELA(in_patch.funcs_md[i].old_sym);
			relas[relocs_count].r_offset = f_off + offsetof(struct kpatch_func_metadata, old_sym);
			relocs_count++;
		}
		if (in_patch.funcs_md[i].old_obj) {
			relas[relocs_count] = RELSTR_RELA(in_patch.funcs_md[i].old_obj);
			relas[relocs_count].r_offset = f_off + offsetof(struct kpatch_func_metadata, old_obj);
			relocs_count++;
		}
	}

	scn = create_section(".kpatch.funcs", SHT_PROGBITS, SHF_ALLOC, 8,
			sizeof(struct kpatch_func_metadata), funcs_buf, total_size);

	if (relocs_count > 0)
		create_rela_section(".rela.kpatch.funcs", scn, relas, relocs_count);

	printf("Created .kpatch.funcs (%zu bytes, %d relocations)\n", total_size, relocs_count);
	return (scn);
}

static Elf_Scn *
create_kpatch_sets(Elf_Scn *funcs __unused)
{
	return (NULL);
}

static void
create_linker_set(Elf_Scn *sets_scn __unused)
{
}

static void
new_patch_sections(void)
{
	Elf_Scn *funcs_scn, *sets_scn;

	funcs_scn = create_kpatch_funcs();
	sets_scn = create_kpatch_sets(funcs_scn);
	create_linker_set(sets_scn);
}

static void
fix_patch_relocations(void)
{
	Elf_Scn *scn_out;
	GElf_Shdr shdr;
	int dirty;

	scn_out = NULL;
	while ((scn_out = elf_nextscn(out_patch.elf, scn_out)) != NULL) {
		if (elf_ndxscn(scn_out) > out_patch.last_ndx)
			continue;

		gelf_getshdr(scn_out, &shdr);
		dirty = 0;

		if (shdr.sh_link != 0) {
			shdr.sh_link = index_map_get(shdr.sh_link);
			dirty = 1;
		}

		if (shdr.sh_info != 0 && (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA)) {
			shdr.sh_info = index_map_get(shdr.sh_info);
			dirty = 1;
		}

		if (dirty)
			gelf_update_shdr(scn_out, &shdr);
	}

	// Update the string table
	elf_setshstrndx(out_patch.elf, index_map_get(in_patch.shstrndx));
}

static int
close_patch(void)
{
	int ret;

	ret = elf_update(out_patch.elf, ELF_C_WRITE);
	if (ret < 0) 
		printf("elf_update failed: %s", elf_errmsg(-1));

	// TODO: Free shstrab data

	elf_end(out_patch.elf);
	elf_end(in_patch.elf);
	close(out_patch.fd);
	close(in_patch.fd);

	free(out_patch.idx_map);
	return (ret);
}

int
main(int argc, const char **argv)
{
	if (argc != 4)
		errx(1, "Usage: %s RAW_KMOD OUT_KMOD KERNEL", argv[0]);

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "Failed to init libelf: %s", elf_errmsg(-1));

	open_kernel(argv[3]);
	open_patch(argv[1], argv[2]);

	copy_patch_sections();

	parse_patch_metadata();

	new_patch_sections();

	fix_patch_relocations();

	close_kernel();
	return (close_patch() != 0);
}
