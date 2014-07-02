/* radare - LGPL - Copyright 2014 - The Lemon Man */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

typedef struct bflt_header {
	ut8  magic[4];
	ut32 version;
	ut32 text_start;
	ut32 data_start;
	ut32 bss_start;
	ut32 bss_end;
	ut32 stack_size;
	ut32 reloc_start;
	ut32 reloc_count;
	ut32 flags;
	ut32 build_date;
	ut32 pad[5];
} __attribute__((packed)) bflt_header;

#define BFLT_FLAG_RAM		0x1
#define BFLT_FLAT_GOTPIC	0x2
#define BFLT_FLAT_GZIP		0x4

static Sdb* get_sdb (RBinObject *o) {
	return NULL;
}

static int check_bytes(const ut8 *buf, ut64 size) {
	const bflt_header *hdr = (bflt_header *)buf;

	return (size > sizeof (bflt_header) &&
			!memcmp(hdr->magic, "bFLT", 4) &&
			ntohl (hdr->version) == 4 && 
			!(ntohl (hdr->flags)&BFLT_FLAT_GZIP));
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	const ut64 size = arch ? r_buf_size (arch->buf) : 0;

	if (!arch || !arch->o || !bytes)
		return R_FALSE;

	return check_bytes(bytes, size);
}

static int load(RBinFile *arch) {
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0;
}

static RBinInfo *info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);

	if (!ret) 
		return NULL;

	strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->type, "bFLT binary", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->os, "any", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->subsystem, "any", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->arch, "arm", R_BIN_SIZEOF_STRINGS);
	strncpy (ret->bclass, "program", R_BIN_SIZEOF_STRINGS);

	ret->has_va = R_FALSE;
	ret->has_pi = R_TRUE;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;

	return ret;
}

static RList* entries(RBinFile *arch) {
	const bflt_header *hdr = (bflt_header *)arch->buf->buf;
	RBinAddr *ptr;
	RList *ret;

	ret = r_list_new ();
	if (!ret)
		return NULL;

	ptr = R_NEW0 (RBinAddr);
	if (!ptr) {
		free (ret);
		return NULL;
	}

	ptr->paddr = ntohl (hdr->text_start);

	r_list_append (ret, ptr);

	return ret;
}

static RList* sections(RBinFile *arch) {
	const bflt_header *hdr = (bflt_header *)arch->buf->buf;
	RBinSection *ptr;
	RList *ret;

	ret = r_list_new ();
	if (!ret)
		return NULL;

	ptr = R_NEW0 (RBinSection);
	strncpy (ptr->name, ".text", R_BIN_SIZEOF_STRINGS);
	ptr->paddr = ntohl (hdr->text_start);
	ptr->size = ntohl (hdr->data_start) - ntohl (hdr->text_start);
	ptr->srwx = r_str_rwx ("rwx");
	r_list_append (ret, ptr);

	ptr = R_NEW0 (RBinSection);
	strncpy (ptr->name, ".data", R_BIN_SIZEOF_STRINGS);
	ptr->paddr = ntohl (hdr->data_start);
	ptr->size = ntohl (hdr->bss_start) - ntohl (hdr->data_start);
	ptr->srwx = r_str_rwx ("rw");
	r_list_append (ret, ptr);

	ptr = R_NEW0 (RBinSection);
	strncpy (ptr->name, ".bss", R_BIN_SIZEOF_STRINGS);
	ptr->paddr = ntohl (hdr->bss_start);
	ptr->size = ntohl (hdr->bss_end) - ntohl (hdr->bss_start);
	ptr->srwx = r_str_rwx ("rw");
	r_list_append (ret, ptr);

	return ret;
}

static RList* relocs(RBinFile *arch) {
	const bflt_header *hdr = (bflt_header *)arch->buf->buf;
	RList *ret;
	RBinReloc *ptr;
	ut32 *rel;
	int i;

	ret = r_list_new ();
	if (!ret)
		return NULL;
	ret->free = free;

	rel = (ut32 *)(arch->buf->buf + ntohl (hdr->reloc_start));

	/* Parse the relocations */
	for (i = 0; i < ntohl (hdr->reloc_count); i++) {
		ptr = R_NEW0 (RBinReloc);
		ptr->type = R_BIN_RELOC_32;
		ptr->additive = R_TRUE;
		ptr->addend = sizeof (bflt_header);
		ptr->paddr = ntohl (rel[i]) + sizeof (bflt_header);

		r_list_append (ret, ptr);
	}

	/* Parse the GOT table at the beginning of .data */
	if (ntohl (hdr->flags)&BFLT_FLAT_GOTPIC) {
		rel = (ut32 *)(arch->buf->buf + ntohl (hdr->data_start));
		for (i = 0; rel[i] != 0xffffffff; i++) {
			if (rel[i]) {
				ptr = R_NEW0 (RBinReloc);
				ptr->type = R_BIN_RELOC_32;
				ptr->additive = R_TRUE;
				ptr->addend = sizeof (bflt_header);
				ptr->paddr = rel[i];

				r_list_append (ret, ptr);
			}
		}
	}

	return ret;
}


struct r_bin_plugin_t r_bin_plugin_bflt = {
	.name = "bflt",
	.desc = "bFLT loader",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.entries = entries,
	.sections = sections,
	.info = &info,
	.relocs = &relocs,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bflt
};
#endif
