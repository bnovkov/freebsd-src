#include <sys/types.h>
#include <err.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <gelf.h>
#include <libelf.h>
#include <string.h>

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
	long shstrndx;
	Elf_Scn *shstr_scn;
	Elf_Data *shstr_data;
} in_patch;

static struct {
	int fd;
	Elf *elf;
	unsigned *idx_map; 
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
find_kernel_symbol(const char *srcfile, const char *func)
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

			if (strcmp(curfile, srcfile) == 0)
				return (n);

			n++;
			printf("Homonym found at index %d\n", n);
		}
	}

	return (-1);
}

static void
open_patch(const char *in_path, const char *out_path)
{
	GElf_Ehdr ehdr;

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

	out_patch.idx_map = calloc(2048, sizeof(unsigned));
}

static int
process_section(const char *name, Elf_Scn *scn __unused)
{
	// Strip these sections from the final ELF
	if (!strcmp(name, ".buildpatch.relocs") || !strcmp(name, ".rela.buildpatch.relocs")) 
		return (0);

	// Copy normally all other sections
	return (1);
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

		if (!process_section(name, scn_in)) {
			printf("Dropping section %s\n", name);
			out_patch.idx_map[ndx_in] = 0;
			continue;
		}

		// TODO: Rename sections here

		scn_out = elf_newscn(out_patch.elf);
		ndx_out = elf_ndxscn(scn_out);
		out_patch.idx_map[ndx_in] = ndx_out;

		//if (ndx_in == in_patch.shstrndx)
		// else
		{
			printf("Copying section %s\n", name);

			data_in = NULL;
			while ((data_in = elf_getdata(scn_in, data_in)) != NULL) {
				data_out = elf_newdata(scn_out);
				*data_out = *data_in;
			}
		}

		gelf_update_shdr(scn_out, &shdr);
	}
}

static void
fix_patch_relocations(void)
{
	Elf_Scn *scn_out;
	GElf_Shdr shdr;
	int dirty;

	scn_out = NULL;
	while ((scn_out = elf_nextscn(out_patch.elf, scn_out)) != NULL) {
		gelf_getshdr(scn_out, &shdr);
		dirty = 0;

		if (shdr.sh_link != 0) {
			shdr.sh_link = out_patch.idx_map[shdr.sh_link];
			dirty = 1;
		}

		if (shdr.sh_info != 0 && (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA)) {
			shdr.sh_info = out_patch.idx_map[shdr.sh_info];
			dirty = 1;
		}

		if (dirty)
			gelf_update_shdr(scn_out, &shdr);
	}

	// Update the string table
	elf_setshstrndx(out_patch.elf, out_patch.idx_map[in_patch.shstrndx]);
}

static int
close_patch(void)
{
	int ret;

	ret = elf_update(out_patch.elf, ELF_C_WRITE);
	if (ret < 0) 
		printf("elf_update failed: %s", elf_errmsg(-1));

	elf_end(out_patch.elf);
	elf_end(in_patch.elf);
	close(out_patch.fd);
	close(in_patch.fd);

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

	find_kernel_symbol("", "");
	
	copy_patch_sections();
	fix_patch_relocations();

	close_kernel();
	return (close_patch() != 0);
}
