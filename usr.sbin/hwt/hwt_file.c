#include <sys/hwt_record.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syslimits.h>
#include <sys/tree.h>
#include <sys/uio.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <sha256.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hwt.h"
#include "hwt_elf.h"
#include "hwt_file.h"

static int hwt_file_exec_region_entry_compare(const void *n1, const void *n2);
RB_GENERATE(exec_tree, hwt_file_exec_region_entry, link,
    hwt_file_exec_region_entry_compare);

static uint32_t region_id = 0;
static char hwt_magic[MAGIC_NBYTES] = {'H', 'W', 'T', 0xf};

static int
pwrite_all(int fd, uint64_t foffset, uint8_t *buff, size_t size)
{
	ssize_t ccw;

	while (size > 0) {
		ccw = pwrite(fd, buff, size, foffset);
		if (ccw < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		size -= ccw;
		buff += ccw;
	}

	return (0);
}

static int
pwritev_all(int fd, struct iovec *iov, int cnt, off_t off)
{
	ssize_t n;
	int i;

	i = 0;
	while (i < cnt) {
		struct iovec *curiov = &iov[i];
		n = pwritev(fd, curiov, cnt, off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return (-1);
		}
		off += n;
		while (i < cnt && (size_t)n >= curiov->iov_len) {
			curiov = &iov[i];
			n -= curiov->iov_len;
			i++;
		}
		if (i >= cnt)
			break;
		curiov->iov_base = curiov->iov_base + n;
		curiov->iov_len -= n;
	}

	return (0);
}

static int
hash_file_exec_region(struct hwt_file_exec_region *exec_region)
{
	uint64_t mapoff, maplen;
	uint64_t foffset;
	SHA256_CTX ctx;
	int fd, serrno;
	void *base;

	fd = open(exec_region->path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (-1);

	foffset = exec_region->foffset;
	mapoff = foffset & (uint64_t)PAGE_MASK;
	maplen = (foffset - mapoff) + exec_region->size;
	base = mmap(NULL, maplen, PROT_READ,
	    MAP_PRIVATE | MAP_PREFAULT_READ | MAP_ALIGNED_SUPER,
	    fd, mapoff);
	if (base == MAP_FAILED) {
		serrno = errno;
		close(fd);
		errno = serrno;
		return (-1);
	}

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, (char *)base + (foffset - mapoff),
	    exec_region->size);
	SHA256_Final(exec_region->hval, &ctx);

	munmap(base, maplen);
	close(fd);
	return (0);
}

static int hwt_file_exec_region_compare(const void *n1, const void *n2)
{
	struct hwt_file_exec_region_entry *e1, *e2;
	int cmpres;

	e1 = (struct hwt_file_exec_region_entry *)n1;
	e2 = (struct hwt_file_exec_region_entry *)n2;

	cmpres = strcmp(e1->img.path, e2->img.path);
	if (cmpres != 0)
		return (cmpres);
	// TODO: refine
	return (e1->img.foffset < e2->img.foffset ? -1 :
	    e1->img.foffset > e2->img.foffset);
}

int
hwt_file_add_exec_region(struct hwt_file *file,
    const struct hwt_elf_img *elf_img)
{
	struct hwt_file_exec_region_entry *entry, find;
	size_t pathlen;

	pathlen = strlcpy(find.img.path, elf_img->path, PATH_MAX);
	if (pathlen >= PATH_MAX) {
		warnx("%s: executable image path '%s' is too long\n",
		    __func__, elf_img->path);
		free(entry);
		return (-1);
	}
	entry = RB_FIND(exec_tree, &file->exec_regions, &find);
	if (entry != NULL)
		return (entry->img.id);

	entry = malloc(sizeof(*entry));
	if (entry == NULL)
		return (-1);

	memcpy(entry->img.path, find.img.path, pathlen);
	entry->img.foffset = elf_img->offs;
	entry->img.size = elf_img->size;
	entry->img.id = region_id++;

	return (entry->img.id);
}

int
hwt_file_open(struct hwt_file *f, const char *path,
    enum hwt_action action, enum hwt_backend_type backend,
    int tracing_mode)
{
	int flags;
	struct hwt_file_hdr *hdr;
	struct hwt_file_metadata *mdata;

	if (path == NULL) {
		warnx("Missing trace file name");
		return (-1);
	}

	switch (action) {
	case HWT_ACTION_SAVE_FILE:
		flags = O_CREAT | O_EXCL | O_WRONLY;
		f->decoding = true;
		break;
	case HWT_ACTION_DECODE_FILE:
		flags = O_RDONLY;
		f->decoding = false;
		break;
	default:
		errx(1, "Unsupported tracing action");
	}

	f->fd = open(path, flags);
	if (f->fd < 0)
		err(1, "Failed to open trace file '%s'\n", path);

	hdr = &f->hdr;
	mdata = &hdr->mdata;
	if (!f->decoding) {
		bzero(&hdr, sizeof(*hdr));
		memcpy(&hdr->magic, hwt_magic, MAGIC_NBYTES);
		hdr->version_major = HWT_FILE_VERSION_MAJOR;
		hdr->version_minor = HWT_FILE_VERSION_MINOR;
		mdata->backend = backend;
		mdata->tracing_mode = tracing_mode;
		f->cursor = 0;
	} else {
		// TODO;
		return (-1);
	}

	return (0);
}

int
hwt_file_add_trace(struct hwt_file *f, uint32_t thread_id,
    const uint8_t *start, size_t len)
{
	struct hwt_file_event_hdr evhdr;
	struct iovec iov[2];

	bzero(&evhdr, sizeof(evhdr));
	evhdr.type = HWT_RECORD_BUFFER;
	evhdr.size = len;
	evhdr.data.thread_id = thread_id;
	evhdr.data.foffset = f->cursor + sizeof(evhdr);

	iov[0].iov_base = &evhdr;
	iov[0].iov_len = sizeof(evhdr);
	iov[1].iov_base = __DECONST(void *, start);
	iov[1].iov_len = len;

	if (pwritev_all(f->fd, iov, 2, f->cursor) < 0)
		return (-1);
	f->cursor += sizeof(evhdr) + len;

	return (0);
}

int
hwt_file_add_map_event(struct hwt_file *f, enum hwt_record_type type,
    uint32_t imgref, const struct hwt_elf_img *elf_img)
{
	struct hwt_file_event_hdr evhdr;

	bzero(&evhdr, sizeof(evhdr));
	evhdr.type = type;
	evhdr.map.imgref = imgref;
	evhdr.map.vaddr = elf_img->addr;
	evhdr.map.size = elf_img->size;
	evhdr.map.foffset = elf_img->offs;

	if (pwrite_all(f->fd, f->cursor, (uint8_t *)&evhdr, sizeof(evhdr)))
		return (-1);
	f->cursor += sizeof(evhdr);

	return (0);
}

int
hwt_file_close(struct hwt_file *f)
{
	struct hwt_file_exec_region_entry *exec_entry;
	struct hwt_file_hdr *hdr;

	hdr = &f->hdr;
	hdr->events.size = f->cursor - hdr->events.offset;
	hdr->manifest.size = 0;
	hdr->manifest.offset = f->cursor;
	RB_FOREACH(exec_entry, exec_tree, &f->exec_regions) {
		if (hash_file_exec_region(&exec_entry->img) != 0)
			warn("%s: failed to save checksum for '%s'\n",
			    __func__, exec_entry->img.path);

		if (pwrite_all(f->fd, f->cursor, (uint8_t *)&exec_entry->img,
		    sizeof(exec_entry->img)) != 0)
			err(1, "Failed to write trace file manifest\n");

		hdr->manifest.size += sizeof(exec_entry->img);
		f->cursor += sizeof(exec_entry->img);
	}

	/* Write the header and finalize the trace file. */
	if (pwrite_all(f->fd, 0, (uint8_t *)&f->hdr, sizeof(f->hdr)) != 0)
		err(1, "Failed to write trace file header\n");
	fsync(f->fd);
	close(f->fd);

	return (0);
}
