/* radare - LGPL - Copyright 2009-2014 - nibble, pancake */

#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "elf/elf.h"

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static Sdb* get_sdb (RBinObject *o) {
	struct Elf_(r_bin_elf_obj_t) *bin;
	if (!o) return NULL;
	bin = (struct Elf_(r_bin_elf_obj_t) *) o->bin_obj;
	if (bin && bin->kv) return bin->kv;
	return NULL;
}

static void * load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	struct Elf_(r_bin_elf_obj_t) *res;
	RBuffer *tbuf;
	if (!buf || sz == 0 || sz == UT64_MAX)
		return NULL;
	tbuf = r_buf_new ();
	r_buf_set_bytes (tbuf, buf, sz);
	res = Elf_(r_bin_elf_new_buf) (tbuf);
	if (res)
		sdb_ns_set (sdb, "info", res->kv);
	r_buf_free (tbuf);
	return res;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
 	if (!arch || !arch->o) return R_FALSE;
	arch->o->bin_obj = load_bytes (bytes, sz, 
		arch->o->loadaddr, arch->sdb);
	if (!(arch->o->bin_obj))
		return R_FALSE;
	return R_TRUE;
}

static int destroy(RBinFile *arch) {
	Elf_(r_bin_elf_free) ((struct Elf_(r_bin_elf_obj_t)*)arch->o->bin_obj);
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return Elf_(r_bin_elf_get_baddr) (arch->o->bin_obj);
}

static ut64 boffset(RBinFile *arch) {
	return Elf_(r_bin_elf_get_boffset) (arch->o->bin_obj);
}

static RBinAddr* binsym(RBinFile *arch, int sym) {
	struct Elf_(r_bin_elf_obj_t)* obj = arch->o->bin_obj;
	ut64 addr = 0LL;
	RBinAddr *ret = NULL;
	switch (sym) {
	case R_BIN_SYM_ENTRY:
		addr = Elf_(r_bin_elf_get_entry_offset) (arch->o->bin_obj);
		break;
	case R_BIN_SYM_MAIN:
		addr = Elf_(r_bin_elf_get_main_offset) (arch->o->bin_obj);
		break;
	case R_BIN_SYM_INIT:
		addr = Elf_(r_bin_elf_get_init_offset) (arch->o->bin_obj);
		break;
	case R_BIN_SYM_FINI:
		addr = Elf_(r_bin_elf_get_fini_offset) (arch->o->bin_obj);
		break;
	}
	if (addr && (ret = R_NEW0 (RBinAddr))) {
		ret->paddr = addr;
		ret->vaddr = obj->baddr + addr;
	}
	return ret;
}

static RList* entries(RBinFile *arch) {
	RList *ret;
	RBinAddr *ptr = NULL;
	struct Elf_(r_bin_elf_obj_t)* obj = arch->o->bin_obj;

	if (!obj)
		return NULL;

	if (!(ret = r_list_new ()))
		return NULL;

	ret->free = free;
	if (!(ptr = R_NEW0 (RBinAddr)))
		return ret;
	ptr->paddr = Elf_(r_bin_elf_get_entry_offset) (arch->o->bin_obj);
	ptr->vaddr = obj->baddr + ptr->paddr;
	r_list_append (ret, ptr);
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	struct r_bin_elf_section_t *section = NULL;
	int i, n, num, found_phdr = 0;
	struct Elf_(r_bin_elf_obj_t)* obj = arch && arch->o ? arch->o->bin_obj : NULL;
	Elf_(Phdr)* phdr = NULL;

	if (!obj || !(ret = r_list_newf (free)))
		return NULL;
	ret->free = free;
	if ((section = Elf_(r_bin_elf_get_sections) (obj))) {
		for (i = 0; !section[i].last; i++) {
			if (!section[i].size) continue;
			if (!(ptr = R_NEW0 (RBinSection)))
				break;
			strncpy (ptr->name, (char*)section[i].name, R_BIN_SIZEOF_STRINGS);
			ptr->size = section[i].size;
			ptr->vsize = section[i].size;
			ptr->paddr = section[i].offset;
			ptr->vaddr = section[i].address;

			// HACK if (ptr->vaddr == 0) { ptr->vaddr = section[i].offset; }
			ptr->srwx = 0;
			if (R_BIN_ELF_SCN_IS_EXECUTABLE (section[i].flags))
				ptr->srwx |= R_BIN_SCN_EXECUTABLE;
			if (R_BIN_ELF_SCN_IS_WRITABLE (section[i].flags))
				ptr->srwx |= R_BIN_SCN_WRITABLE;
			if (R_BIN_ELF_SCN_IS_READABLE (section[i].flags))
				ptr->srwx |= R_BIN_SCN_READABLE;
			r_list_append (ret, ptr);
		}
		free (section); // TODO: use r_list_free here
	}

	// program headers is another section
	num = obj->ehdr.e_phnum;
	phdr = obj->phdr;
	for (i=n=0; i<num; i++) {
		if (phdr && phdr[i].p_type == 1) {
			found_phdr = 1;
			ut64 paddr = phdr[i].p_offset;
			ut64 vaddr = phdr[i].p_vaddr;
			int memsz = (int)phdr[i].p_memsz;
			int perms = phdr[i].p_flags;
			ut64 align = phdr[i].p_align;
			if (!align) align = 0x1000;
			memsz = (int)(size_t)R_PTR_ALIGN_NEXT ((size_t)memsz, (int)align);
			//vaddr -= obj->baddr; // yeah
			if (!(ptr = R_NEW0 (RBinSection)))
				return ret;
			sprintf (ptr->name, "phdr%d", n);
			ptr->size = memsz;
			ptr->vsize = memsz;
			ptr->paddr = paddr;
			ptr->vaddr = vaddr;
			ptr->srwx = perms;
			r_list_append (ret, ptr);
			n++;
		}
	}

	return ret;

	if (r_list_empty (ret)) {
		if (!arch->size) {
			struct Elf_(r_bin_elf_obj_t) *bin = arch->o->bin_obj;
			arch->size = bin? bin->size: 0x9999;
		}
		if (found_phdr == 0) {
			if (!(ptr = R_NEW0 (RBinSection)))
				return ret;
			sprintf (ptr->name, "uphdr");
			ptr->size = arch->size;
			ptr->vsize = arch->size;
			ptr->paddr = 0;
			ptr->vaddr = 0x10000;
			ptr->srwx = 7;
			r_list_append (ret, ptr);
		}
	}
	// add entry for ehdr
#if 0
	ptr = R_NEW0 (RBinSection);
	if (ptr) {
		ut64 ehdr_size = sizeof (obj->ehdr);

		sprintf (ptr->name, "ehdr");
		ptr->paddr = 0;
		ptr->vaddr = obj->baddr;
		ptr->size = ehdr_size;
		ptr->vsize = ehdr_size;
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_WRITABLE;
		r_list_append (ret, ptr);
	}
#endif

	return ret;
}

static RBinInfo* info(RBinFile *arch);
static RList* symbols(RBinFile *arch) {
	struct Elf_(r_bin_elf_obj_t) *bin;
	struct r_bin_elf_symbol_t *symbol = NULL;
	RBinSymbol *ptr = NULL;
	RList *ret = NULL;
	int i;

	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;

	bin = arch->o->bin_obj;

	if (!(ret = r_list_newf (free)))
		return NULL;

	if (!bin->_sym_table)
		return ret;

	symbol = bin->_sym_table;

	for (i = 0; !symbol[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinSymbol)))
			break;

		if (symbol[i].is_import)
			snprintf (ptr->name, R_BIN_SIZEOF_STRINGS, "imp.%s", symbol[i].name);
		else
			strncpy (ptr->name, symbol[i].name, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->forwarder, "NONE", R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->bind, symbol[i].bind, R_BIN_SIZEOF_STRINGS);
		strncpy (ptr->type, symbol[i].type, R_BIN_SIZEOF_STRINGS);

		ptr->paddr = symbol[i].offset;
		ptr->vaddr = symbol[i].address;
		if (ptr->vaddr < baddr (arch))
			ptr->vaddr += baddr (arch);
		ptr->size = symbol[i].size;
		ptr->ordinal = symbol[i].ordinal;

		r_list_append (ret, ptr);
	}

	return ret;
}

static RList* imports(RBinFile *arch) {
	struct Elf_(r_bin_elf_obj_t) *bin = arch->o->bin_obj;
	struct r_bin_elf_symbol_t *import = NULL;
	RBinImport *ptr = NULL;
	RList *ret = NULL;
	int i;

	if (!(ret = r_list_newf (free)))
		return NULL;

	if (!bin->_sym_table)
		return ret;

	import = bin->_sym_table; 

	for (i = 0; !import[i].last; i++) {
		if (!import[i].is_import)
			continue;
		if (!(ptr = R_NEW0 (RBinImport)))
			break;
		strncpy (ptr->name, import[i].name, sizeof(ptr->name)-1);
		strncpy (ptr->bind, import[i].bind, sizeof(ptr->bind)-1);
		strncpy (ptr->type, import[i].type, sizeof(ptr->type)-1);
		ptr->ordinal = import[i].ordinal;
		r_list_append (ret, ptr);
	}

	return ret;
}

static RList* libs(RBinFile *arch) {
	struct r_bin_elf_lib_t *libs = NULL;
	RList *ret = NULL;
	char *ptr = NULL;
	int i;

	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;
	if (!(ret = r_list_newf (free)))
		return NULL;
	if (!(libs = Elf_(r_bin_elf_get_libs) (arch->o->bin_obj)))
		return ret;
	for (i = 0; !libs[i].last; i++) {
		ptr = strdup (libs[i].name);
		r_list_append (ret, ptr);
	}
	free (libs);
	return ret;
}

static RList* relocs(RBinFile *arch) {
	struct Elf_(r_bin_elf_obj_t) *bin = arch->o->bin_obj;
	RList *ret = NULL;
	RBinReloc *ptr = NULL;
	RBinElfReloc *relocs = NULL;
	int i;

	if (!(ret = r_list_newf (free)))
		return NULL;

	if (!bin->_rel_table)
		return ret;

	relocs = bin->_rel_table;

	for (i = 0; !relocs[i].last; i++) {
		ptr = R_NEW0 (RBinReloc);

		ptr->vaddr = relocs[i].address;
		ptr->paddr = relocs[i].offset;

		r_list_append (ret, ptr);
	}

	return ret;
}

static int has_canary(RBinFile *arch) {
	RList* imports_list = imports (arch);
	RListIter *iter;
	RBinImport *import;
	r_list_foreach (imports_list, iter, import) {
		if (!strcmp(import->name, "__stack_chk_fail") ) {
			r_list_free (imports_list);
			return 1;
		}
	}
	r_list_free (imports_list);
	return 0;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	char *str;

	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->lang = "c";
	if (arch->file)
		strncpy (ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	else *ret->file = 0;
	if ((str = Elf_(r_bin_elf_get_rpath)(arch->o->bin_obj))) {
		strncpy (ret->rpath, str, R_BIN_SIZEOF_STRINGS);
		free (str);
	} else strncpy (ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);
	// if (!(str = Elf_(r_bin_elf_get_file_type) (arch->o->bin_obj))) {
	// 	free (ret);
	// 	return NULL;
	// }
	// strncpy (ret->type, str, R_BIN_SIZEOF_STRINGS);
	// ret->has_pi = (strstr (str, "DYN"))? 1: 0;
	ret->has_canary = has_canary (arch);
	// free (str);
	// if (!(str = Elf_(r_bin_elf_get_elf_class) (arch->o->bin_obj))) {
	// 	free (ret);
	// 	return NULL;
	// }
	// strncpy (ret->bclass, str, R_BIN_SIZEOF_STRINGS);
	// free (str);
	// if (!(str = Elf_(r_bin_elf_get_osabi_name) (arch->o->bin_obj))) {
	// 	free (ret);
	// 	return NULL;
	// }
	// strncpy (ret->os, str, R_BIN_SIZEOF_STRINGS);
	// free (str);
	// if (!(str = Elf_(r_bin_elf_get_osabi_name) (arch->o->bin_obj))) {
	// 	free (ret);
	// 	return NULL;
	// }
	// strncpy (ret->subsystem, str, R_BIN_SIZEOF_STRINGS);
	// free (str);
	// if (!(str = Elf_(r_bin_elf_get_machine_name) (arch->o->bin_obj))) {
	// 	free (ret);
	// 	return NULL;
	// }
	// strncpy (ret->machine, str, R_BIN_SIZEOF_STRINGS);
	// free (str);
	if (!(str = Elf_(r_bin_elf_get_arch) (arch->o->bin_obj))) {
		return NULL;
	}
	strncpy (ret->arch, str, R_BIN_SIZEOF_STRINGS);
	strncpy (ret->rclass, "elf", R_BIN_SIZEOF_STRINGS);
	ret->bits = Elf_(r_bin_elf_get_bits) (arch->o->bin_obj);
	ret->big_endian = Elf_(r_bin_elf_is_big_endian) (arch->o->bin_obj);
	ret->has_va = Elf_(r_bin_elf_has_va) (arch->o->bin_obj);
	ret->has_nx = Elf_(r_bin_elf_has_nx) (arch->o->bin_obj);
	ret->dbg_info = 0;
	if (!Elf_(r_bin_elf_get_stripped) (arch->o->bin_obj))
		ret->dbg_info |= R_BIN_DBG_LINENUMS | R_BIN_DBG_SYMS | R_BIN_DBG_RELOCS;
	else  ret->dbg_info |= R_BIN_DBG_STRIPPED;
	if (Elf_(r_bin_elf_get_static) (arch->o->bin_obj))
		ret->dbg_info |= R_BIN_DBG_STATIC;
	return ret;
}

static RList* fields(RBinFile *arch) {
	RList *ret = NULL;
	RBinField *ptr = NULL;
	struct r_bin_elf_field_t *field = NULL;
	int i;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(field = Elf_(r_bin_elf_get_fields) (arch->o->bin_obj)))
		return ret;
	for (i = 0; !field[i].last; i++) {
		if (!(ptr = R_NEW0 (RBinField)))
			break;
		strncpy (ptr->name, field[i].name, R_BIN_SIZEOF_STRINGS);
		ptr->vaddr = field[i].offset;
		ptr->paddr = field[i].offset;
		r_list_append (ret, ptr);
	}
	free (field);
	return ret;
}

static int size(RBinFile *arch) {
	ut64 off = 0;
	ut64 len = 0;
	if (!arch->o->sections) {
		RListIter *iter;
		RBinSection *section;
		arch->o->sections = sections (arch);
		r_list_foreach (arch->o->sections, iter, section) {
			if (section->paddr > off) {
				off = section->paddr;
				len = section->size;
			}
		}
	}
	return off+len;
}

#if !R_BIN_ELF64

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

static int check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length > 4 &&
		!memcmp (buf, "\x7F\x45\x4c\x46", 4) && buf[4] != 2)
		return R_TRUE;
	return R_FALSE;
}

extern struct r_bin_dbginfo_t r_bin_dbginfo_elf;
extern struct r_bin_write_t r_bin_write_elf;

static RBuffer* create(RBin* bin, const ut8 *code, int codelen, const ut8 *data, int datalen) {
	ut32 filesize, code_va, code_pa, phoff;
	ut32 p_start, p_phoff, p_phdr;
	ut32 p_ehdrsz, p_phdrsz;
	ut16 ehdrsz, phdrsz;
	ut32 p_vaddr, p_paddr, p_fs, p_fs2;
	ut32 baddr;
	int is_arm = 0;
	RBuffer *buf = r_buf_new ();
	if (bin && bin->cur && bin->cur->o && bin->cur->o->info)
		is_arm = !strcmp (bin->cur->o->info->arch, "arm");
	// XXX: hardcoded
	if (is_arm) {
		baddr = 0x40000;
	} else {
		baddr = 0x8048000;
	}

#define B(x,y) r_buf_append_bytes(buf,(const ut8*)x,y)
#define D(x) r_buf_append_ut32(buf,x)
#define H(x) r_buf_append_ut16(buf,x)
#define Z(x) r_buf_append_nbytes(buf,x)
#define W(x,y,z) r_buf_write_at(buf,x,(const ut8*)y,z)
#define WZ(x,y) p_tmp=buf->length;Z(x);W(p_tmp,y,strlen(y))

	B ("\x7F" "ELF" "\x01\x01\x01\x00", 8);
	Z (8);
	H (2); // ET_EXEC
	if (is_arm)
		H (40); // e_machne = EM_ARM
	else
		H (3); // e_machne = EM_I386

	D (1);
	p_start = buf->length;
	D (-1); // _start
	p_phoff = buf->length;
	D (-1); // phoff -- program headers offset
	D (0);  // shoff -- section headers offset
	D (0);  // flags
	p_ehdrsz = buf->length;
	H (-1); // ehdrsz
	p_phdrsz = buf->length;
	H (-1); // phdrsz
	H (1);
	H (0);
	H (0);
	H (0);
	// phdr:
	p_phdr = buf->length;
	D (1);
	D (0);
	p_vaddr = buf->length;
	D (-1); // vaddr = $$
	p_paddr = buf->length;
	D (-1); // paddr = $$
	p_fs = buf->length;
	D (-1); // filesize
	p_fs2 = buf->length;
	D (-1); // filesize
	D (5); // flags
	D (0x1000); // align

	ehdrsz = p_phdr;
	phdrsz = buf->length - p_phdr;
	code_pa = buf->length;
	code_va = code_pa + baddr;
	phoff = 0x34;//p_phdr ;
	filesize = code_pa + codelen + datalen;

	W (p_start, &code_va, 4);
	W (p_phoff, &phoff, 4);
	W (p_ehdrsz, &ehdrsz, 2);
	W (p_phdrsz, &phdrsz, 2);

	code_va = baddr; // hack
	W (p_vaddr, &code_va, 4);
	code_pa = baddr; // hack
	W (p_paddr, &code_pa, 4);

	W (p_fs, &filesize, 4);
	W (p_fs2, &filesize, 4);

	B (code, codelen);

	if (data && datalen>0) {
		//ut32 data_section = buf->length;
		eprintf ("Warning: DATA section not support for ELF yet\n");
		B (data, datalen);
	}
	return buf;
}


static ut64 get_elf_vaddr (RBinFile *arch, ut64 ba, ut64 pa, ut64 va) {
	//NOTE(aaSSfxxx): since RVA is vaddr - "official" image base, we just need to add imagebase to vaddr
// WHY? NO NEED TO HAVE PLUGIN SPECIFIC VADDR
	struct Elf_(r_bin_elf_obj_t)* obj = arch->o->bin_obj;
	return obj->baddr - obj->boffset + va - ba;

}

RBinPlugin r_bin_plugin_elf = {
	.name = "elf",
	.desc = "ELF format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = &boffset,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.minstrlen = 4,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.dbginfo = &r_bin_dbginfo_elf,
	.create = &create,
	.write = &r_bin_write_elf,
	.get_vaddr = &get_elf_vaddr,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf
};
#endif
#endif
