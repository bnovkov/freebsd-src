#ifndef HWT_FILE_H_
#define HWT_FILE_H_

#include <sys/hwt_record.h>
#include <sys/syslimits.h>
#include <sys/tree.h>
#include <sys/types.h>

#include "hwt_elf.h"
#include "pt/file.h"
#include "spe/file.h"
#include "coresight/file.h"

#define MAGIC "HWT\x0f"
#define MAGIC_NBYTES 4
#define SHA256_NBYTES 32

#define HWT_FILE_VERSION_MAJOR 0
#define HWT_FILE_VERSION_MINOR 1

struct hwt_file_map_record {
	uint32_t imgref;
	uint64_t foffset;
	uint64_t vaddr;
	uint64_t size;
};

struct hwt_file_trace_record {
	uint32_t thread_id;
	uint64_t foffset;
};

struct hwt_file_event_hdr {
	uint32_t type;
	uint32_t _pad;
	uint64_t size;
	union {
		struct hwt_file_map_record map;
		struct hwt_file_trace_record data;
	};
};

struct hwt_file_metadata {
	uint32_t backend; /* enum hwt_backend_type */
	uint32_t tracing_mode;	  /* enum hwt_mode_type */
	union {
		struct hwt_pt_metadata pt_mdata;
		struct hwt_spe_metadata spe_mdata;
		struct hwt_coresight_metadata coresight_mdata;
	};
};

struct hwt_file_exec_region {
	uint64_t foffset;
	uint64_t size;
	uint32_t id;
	uint8_t hval[SHA256_NBYTES];
	char path[PATH_MAX];
};

struct hwt_file_manifest_hdr {
	uint64_t count;
};

struct hwt_file_section {
	uint64_t offset;
	uint64_t size;
};

/* Trace file header. */
struct hwt_file_hdr {
	char magic[MAGIC_NBYTES];
	uint16_t version_major;
	uint16_t version_minor;
	uint32_t flags;
	uint32_t header_size;
	struct hwt_file_metadata mdata; /* Platform-specific metadata. */
	struct hwt_file_section
	    manifest; /* List of traced executables and checksums. */
	struct hwt_file_section events; /* Tracing events. */
};

struct hwt_file_exec_region_entry {
	struct hwt_file_exec_region img;
	RB_ENTRY(hwt_file_exec_region_entry) link;
};

struct hwt_file {
	int fd;
	bool decoding;
	uint64_t cursor;
	struct hwt_file_hdr hdr;
	RB_HEAD(exec_tree, hwt_file_exec_region_entry) exec_regions;
};

int
hwt_file_open(struct hwt_file *f, const char *path,
    enum hwt_action action, enum hwt_backend_type backend,
    int tracing_mode);
int hwt_file_close(struct hwt_file *f);

int hwt_file_add_map_event(struct hwt_file *f, enum hwt_record_type type,
    uint32_t imgref, const struct hwt_elf_img *);
int hwt_file_add_trace(struct hwt_file *f, uint32_t thread_id,
    const uint8_t *start, size_t len);
#endif // HWT_FILE_H_
