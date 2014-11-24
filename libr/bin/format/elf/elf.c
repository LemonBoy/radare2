#include <stdio.h>
#include <r_types.h>
#include <r_util.h>
#include "elf.h"

#define ELF_DEBUG 1

static ut64 r_bin_elf_get_offset (struct Elf_(r_bin_elf_obj_t) *bin, ut64 va) {
	int i;

	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (va >= bin->phdr[i].p_vaddr && va < bin->phdr[i].p_vaddr + bin->phdr[i].p_memsz)
			return (va - bin->phdr[i].p_vaddr) + bin->phdr[i].p_offset;
	}

	// We shouldn't really trust the section headers, just hope we never reach this point
	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (va >= bin->shdr[i].sh_addr && va < bin->shdr[i].sh_addr + bin->shdr[i].sh_size)
			return (va - bin->shdr[i].sh_addr) + bin->shdr[i].sh_offset;
	}

	return va;
}

static char *r_bin_elf_get_strtab (struct Elf_(r_bin_elf_obj_t) *bin) {
	char *buf;

	if (!bin || !bin->strtab_size)
		return NULL;

	if ((buf = malloc (bin->strtab_size)) == NULL)
		return NULL;

	if (r_buf_read_at (bin->b, bin->strtab_offset, (ut8 *)buf, bin->strtab_size) != bin->strtab_size) {
		eprintf ("Could not read the strtab section\n");
		R_FREE (buf);
		return NULL;
	}

	return buf;
}

static Elf_(Dyn) *Elf_(r_bin_elf_dyn_find)(struct Elf_(r_bin_elf_obj_t) *bin, const ut32 tag) {
	int i;

	if (!bin->phdr || !bin->dyn_buf)
		return NULL;

	for (i = 0; i < bin->dyn_entries; i++) {
		if (bin->dyn_buf[i].d_tag == tag)
			return &bin->dyn_buf[i];
	}
	
	return NULL;
}

int Elf_(r_bin_elf_has_phdr)(struct Elf_(r_bin_elf_obj_t) *bin, const int type) {
	int i;

	if (!bin || !bin->ehdr.e_phnum)
		return R_FALSE;

	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		if (bin->phdr[i].p_type == type)
			return R_TRUE;
	}

	return R_FALSE;
}

int Elf_(r_bin_elf_has_shdr)(struct Elf_(r_bin_elf_obj_t) *bin, const int type) {
	int i;

	if (!bin || !bin->ehdr.e_shnum)
		return R_FALSE;

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (bin->shdr[i].sh_type == type)
			return R_TRUE;
	}

	return R_FALSE;
}

static RBinElfSymbol *r_bin_elf_sym_lookup (struct Elf_(r_bin_elf_obj_t) *bin, int sym) {
	int i;

	if (!bin->_sym_table)
		return NULL;

	for (i = 0; !bin->_sym_table[i].last; i++) {
		if (bin->_sym_table[i].ordinal == sym)
			return &bin->_sym_table[i];
	}

	return NULL;
}

static Elf_(Shdr) *Elf_(r_bin_elf_get_section_by_name)(struct Elf_(r_bin_elf_obj_t) *bin, const char *section_name) {
	int i;

	if (!bin || !bin->ehdr.e_shnum || !bin->shstr_size)
		return NULL;

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		if (bin->shdr[i].sh_name < bin->shstr_size)
			if (!strcmp (bin->shstr_buf + bin->shdr[i].sh_name, section_name))
				return &bin->shdr[i];
	}

	return NULL;
}

static ut64 Elf_(r_bin_elf_get_section_offset)(struct Elf_(r_bin_elf_obj_t) *bin, const char *section_name) {
	Elf_(Shdr)* shdr = Elf_(r_bin_elf_get_section_by_name)(bin, section_name);
	if (!shdr) 
		return -1;
	return (ut64)shdr->sh_offset;
}

static int Elf_(r_bin_elf_init_ehdr) (struct Elf_(r_bin_elf_obj_t) *bin) {
	if (!bin || !bin->b)
		return R_FALSE;

	if (r_buf_fread_at (bin->b, 0, (ut8 *)&bin->ehdr,
#if R_BIN_ELF64
		bin->endian?"16c2SI3LI6S":"16c2si3li6s",
#else
		bin->endian?"16c2S5I6S":"16c2s5i6s",
#endif
		1) != sizeof (Elf_(Ehdr))) {
		eprintf ("Incorrect header\n");
		return R_FALSE;
	}

	if (memcmp (bin->ehdr.e_ident, ELFMAG, SELFMAG)) {
		eprintf ("Incorrect e_ident\n");
		return R_FALSE;
	}

	if (bin->ehdr.e_version != EV_CURRENT) {
		eprintf ("Incorrect e_version\n");
		return R_FALSE;
	}

	if (bin->ehdr.e_type != ET_REL && 
		bin->ehdr.e_type != ET_DYN && 
		bin->ehdr.e_type != ET_CORE &&
		bin->ehdr.e_type != ET_EXEC) {
		eprintf ("Incorrect e_type\n");
		return R_FALSE;
	}

	if (bin->ehdr.e_phnum == 0 && bin->ehdr.e_shnum == 0) {
		eprintf ("No sections nor program headers found!\n");
		return R_FALSE;
	}

	bin->endian = (bin->ehdr.e_ident[EI_DATA] == ELFDATA2MSB)? LIL_ENDIAN: !LIL_ENDIAN;

	return R_TRUE;
}

static int Elf_(r_bin_elf_init_phdr)(struct Elf_(r_bin_elf_obj_t) *bin) {
	int i;

	if (bin->phdr || !bin->ehdr.e_phnum)
		return R_TRUE;

	if (bin->ehdr.e_phnum > 100) {
		eprintf ("Too many program headers!\n");
		return R_FALSE;
	}

	if ((bin->phdr = calloc (bin->ehdr.e_phnum, sizeof (Elf_(Phdr)))) == NULL) {
		perror ("malloc (phdr)");
		return R_FALSE;
	}

	if (r_buf_fread_at (bin->b, bin->ehdr.e_phoff, (ut8 *)bin->phdr,
		#if R_BIN_ELF64
		bin->endian? "2I6L": "2i6l",
		#else
		bin->endian? "8I": "8i",
		#endif
		bin->ehdr.e_phnum) != bin->ehdr.e_phnum * sizeof (Elf_(Phdr))) {
		eprintf ("Warning: read (phdr)\n");
		R_FREE (bin->phdr);
		return R_FALSE;
	}

	bin->baddr = UT64_MAX;
	bin->boffset = UT64_MAX;

	// Find the PT_DYNAMIC segments for later use and determine the base address by examining all the
	// PT_LOAD segments
	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		switch (bin->phdr[i].p_type) {
			case PT_DYNAMIC:
				bin->dyn_buf = calloc (1, bin->phdr[i].p_filesz);
				if (!bin->dyn_buf) {
					eprintf ("Cannot allocate %d phdr[%d].p_filesz\n", 
							(int)bin->phdr[i].p_filesz, (int)i);
					R_FREE (bin->phdr);
					return R_FALSE;
				}
				r_buf_read_at (bin->b, bin->phdr[i].p_offset, (ut8 *)bin->dyn_buf, bin->phdr[i].p_filesz);
				bin->dyn_entries = bin->phdr[i].p_filesz / sizeof (Elf_(Dyn));
			break;

			case PT_LOAD:
				if (bin->phdr[i].p_vaddr < bin->baddr)
					bin->baddr = bin->phdr[i].p_vaddr;
				if (bin->phdr[i].p_offset < bin->boffset)
					bin->boffset = bin->phdr[i].p_offset;
			break;

			case PT_NOTE:
			break;
		}
	}

	return (bin->baddr < UT64_MAX && bin->boffset < UT64_MAX);
}

static int Elf_(r_bin_elf_init_shdr)(struct Elf_(r_bin_elf_obj_t) *bin) {
	Elf_(Shdr) *shstr;
	int shstr_index;

	if (!bin || !bin->b) 
		return R_TRUE;

	if (bin->shdr || !bin->ehdr.e_shnum)
		return R_TRUE;

	if (bin->ehdr.e_shnum > 100) {
		eprintf ("Too many section headers!\n");
		return R_FALSE;
	}

	// This file has nameless section headers
	if (bin->ehdr.e_shstrndx == SHN_UNDEF)
		return R_FALSE;

	if (bin->ehdr.e_shstrndx > bin->ehdr.e_shnum)
		return R_FALSE;

	if ((bin->shdr = calloc (bin->ehdr.e_shnum, sizeof (Elf_(Shdr)))) == NULL) {
		perror ("malloc (shdr)");
		return R_FALSE;
	}

	if (r_buf_fread_at (bin->b, bin->ehdr.e_shoff, (ut8*)bin->shdr,
#if R_BIN_ELF64
		bin->endian?"2I4L2I2L":"2i4l2i2l",
#else
		bin->endian?"10I":"10i",
#endif
		bin->ehdr.e_shnum) != bin->ehdr.e_shnum * sizeof (Elf_(Shdr))) {
		eprintf ("Warning: read (shdr) at 0x%"PFMT64x"\n", (ut64) bin->ehdr.e_shoff);
		R_FREE (bin->shdr);
		return R_FALSE;
	}

	// Straight from the official documentation:
	//  If the section name string table section index is greater than or equal to SHN_LORESERVE (0xff00), 
	//  this member has the value SHN_XINDEX (0xffff) and the actual index of the section name string 
	//  table section is contained in the sh_link field of the section header at index 0. 
	//  (Otherwise, the sh_link member of the initial entry contains 0.) 
	shstr_index = (bin->ehdr.e_shstrndx >= SHN_LORESERVE)?
		bin->shdr[0].sh_link:
		bin->ehdr.e_shstrndx;

	if (shstr_index > bin->ehdr.e_shstrndx || bin->shdr[shstr_index].sh_type != SHT_STRTAB) {
		eprintf ("Invalid e_shstrndx section!\n");
		R_FREE (bin->shdr);
		return R_FALSE;
	}

	shstr = &bin->shdr[shstr_index];
	bin->shstr_buf = malloc (shstr->sh_size);
	bin->shstr_size = shstr->sh_size;

	if (r_buf_read_at (bin->b, shstr->sh_offset, (ut8 *)bin->shstr_buf, shstr->sh_size) < 1) {
		eprintf ("Phony shstr section\n");
		R_FREE (bin->shstr_buf);
		R_FREE (bin->shdr);
		return R_FALSE;
	}

	return R_TRUE;
}

typedef struct {
	Elf32_Word nbuckets;
	Elf32_Word nchain;
} Elf_Hash;

typedef struct {
	Elf32_Word nbuckets;
	Elf32_Word symbol_base;
	Elf32_Word bitmask_nwords;
	Elf32_Word gnu_shift;
} Elf_GNU_Hash;

// Extract the total number of exports/imports by looking at the DT_HASH section
// or the DT_GNU_HASH one if the former isn't present.
// http://deroko.phearless.org/dt_gnu_hash.txt

#define MIPS_SYMTABNO 0x70000011

#define MAX_HASH_CHAIN 400

static int Elf_(r_bin_elf_get_symbols_count) (struct Elf_(r_bin_elf_obj_t) *bin) {
	Elf_(Dyn) *hash;

	// Mips is kind enough to spare us this nasty task
	hash = Elf_(r_bin_elf_dyn_find) (bin, MIPS_SYMTABNO);
	if (hash)
		return hash->d_un.d_val;
	
	hash = Elf_(r_bin_elf_dyn_find) (bin, DT_HASH);
	if (hash) {
		Elf_Hash dt_hash;

		if (r_buf_fread_at (bin->b, r_bin_elf_get_offset (bin, hash->d_un.d_ptr), (ut8*)&dt_hash, 
				bin->endian?"2I":"2i", 1) != sizeof (Elf_Hash)) {
			eprintf ("Could not read DT_HASH\n");
			return -1;
		}

		return dt_hash.nchain;
	}

	hash = Elf_(r_bin_elf_dyn_find) (bin, DT_GNU_HASH);
	if (hash) {
#if 1
		int i, last_sym;
		Elf_GNU_Hash dt_gnu_hash;
		Elf32_Word *bucket;
		Elf32_Word *chains;

		if (r_buf_fread_at (bin->b, r_bin_elf_get_offset (bin, hash->d_un.d_ptr), 
				(ut8 *)&dt_gnu_hash, bin->endian?"4I":"4i", 1) != sizeof (Elf_GNU_Hash)) {
			eprintf ("Could not read DT_GNU_HASH\n");
			return -1;
		}

		bucket = calloc (dt_gnu_hash.nbuckets, sizeof (Elf32_Word));
		if (!bucket)
			return -1;

		const ut64 bucket_off = r_bin_elf_get_offset (bin, hash->d_un.d_ptr) + sizeof (Elf_GNU_Hash) + 
			dt_gnu_hash.bitmask_nwords * sizeof(Elf_(Addr));
		const ut64 chain_off = bucket_off + dt_gnu_hash.nbuckets * 4;

		if (r_buf_fread_at (bin->b, bucket_off, (ut8 *)bucket, bin->endian?"I":"i", 
				dt_gnu_hash.nbuckets) != sizeof (Elf32_Word) * dt_gnu_hash.nbuckets) {
			free (bucket);
			eprintf ("Could not read the hash buckets\n");
			return -1;
		}

		last_sym = 0;
		for (i = 0; i < dt_gnu_hash.nbuckets; i++) {
			if (bucket[i] > last_sym)
				last_sym = bucket[i];
		}

		free (bucket);

		// The section is probably malformed, ignore it 
		if (last_sym < dt_gnu_hash.symbol_base)
			return -1;

		chains = calloc (MAX_HASH_CHAIN, sizeof (Elf32_Word));
		if (!chains)
			return -1;

		if (r_buf_fread_at (bin->b, chain_off, (ut8 *)chains, bin->endian?"I":"i", MAX_HASH_CHAIN) < 
				sizeof (Elf32_Word) * MAX_HASH_CHAIN) {
			eprintf ("Could not read the hash chain\n");
			return -1;
		}

		// Walk the latest chain
		for (i = 0; i < MAX_HASH_CHAIN; i++) {
			if (chains[last_sym - dt_gnu_hash.symbol_base]&1)
				break;

			last_sym++;
		}
		last_sym++;

#ifdef ELF_DEBUG
		eprintf ("We've come a long way, found %i symbols!\n", last_sym);
#endif

		free (chains);

		return last_sym;
#else
		eprintf("Unsupported DT_GNU_HASH section found!\n");
#endif
	}

	return -1;
}

// Try, in the following order, to get a symbol table:
// - using the SYMTAB/STRTAB entry in PT_DYNAMIC
// - using the .dynsym/.dynstr section
// - using the .symtab/.strtab section
static int Elf_(r_bin_elf_choose_symbol_table) (struct Elf_(r_bin_elf_obj_t) *bin) {
	Elf_(Dyn) *d_symtab, *d_strtab, *d_strsz;
	Elf_(Shdr) *s_sym, *s_str;
	int sym_entries;

	if (!bin)
		return R_FALSE;

	d_symtab = Elf_(r_bin_elf_dyn_find) (bin, DT_SYMTAB);
	d_strtab = Elf_(r_bin_elf_dyn_find) (bin, DT_STRTAB);
	d_strsz  = Elf_(r_bin_elf_dyn_find) (bin, DT_STRSZ);

	sym_entries = Elf_(r_bin_elf_get_symbols_count) (bin);

	if (d_symtab && d_strtab && d_strsz && sym_entries >= 0) {
		bin->sym_offset = r_bin_elf_get_offset (bin, d_symtab->d_un.d_ptr);
		bin->sym_entries = sym_entries;

		bin->strtab_offset = r_bin_elf_get_offset (bin, d_strtab->d_un.d_ptr);
		bin->strtab_size = d_strsz->d_un.d_val;

#ifdef ELF_DEBUG
		eprintf ("Using SYMTAB obtained from PT_DYNAMIC (%i symbols)\n", bin->sym_entries);
#endif

		return R_TRUE;
	}

	s_sym = Elf_(r_bin_elf_get_section_by_name) (bin, ".dynsym");
	s_str = Elf_(r_bin_elf_get_section_by_name) (bin, ".dynstr");

	if (s_sym && s_str) {
		bin->sym_offset = s_sym->sh_offset;
		bin->sym_entries = s_sym->sh_size / sizeof (Elf_(Sym));

		bin->strtab_offset = s_str->sh_offset;
		bin->strtab_size = s_str->sh_size;

#ifdef ELF_DEBUG
		eprintf ("Using .dynsym (%i symbols)\n", bin->sym_entries);
#endif

		return R_TRUE;
	}

	s_sym = Elf_(r_bin_elf_get_section_by_name) (bin, ".symtab");
	s_str = Elf_(r_bin_elf_get_section_by_name) (bin, ".strtab");

	if (s_sym && s_str) {
		bin->sym_offset = s_sym->sh_offset;
		bin->sym_entries = s_sym->sh_size / sizeof (Elf_(Sym));

		bin->strtab_offset = s_str->sh_offset;
		bin->strtab_size = s_str->sh_size;

#ifdef ELF_DEBUG
		eprintf ("Using .symtab (%i symbols)\n", bin->sym_entries);
#endif

		return R_TRUE;
	}



	return R_FALSE;
}

struct r_bin_elf_section_t* Elf_(r_bin_elf_get_sections)(struct Elf_(r_bin_elf_obj_t) *bin) {
	struct r_bin_elf_section_t *ret = NULL;
	int i;

	if (!bin || !bin->ehdr.e_shnum)
		return NULL;

	if ((ret = calloc ((bin->ehdr.e_shnum + 1), sizeof (struct r_bin_elf_section_t))) == NULL)
		return NULL;

	for (i = 0; i < bin->ehdr.e_shnum; i++) {
		ret[i].offset = bin->shdr[i].sh_offset;
		ret[i].address = bin->shdr[i].sh_addr;
		ret[i].size = bin->shdr[i].sh_size;
		ret[i].align = bin->shdr[i].sh_addralign;
		ret[i].flags = bin->shdr[i].sh_flags;
		ret[i].last = R_FALSE;

		// At this point we've already checked that the shstr section is valid
		if (bin->shdr[i].sh_name > bin->shstr_size)
			snprintf (ret[i].name, sizeof (ret[i].name), "invalid_%i", i);
		else
			strncpy (ret[i].name, bin->shstr_buf + bin->shdr[i].sh_name, sizeof (ret[i].name));
	}

	ret[i].last = R_TRUE;

	return ret;
}

static int Elf_(r_bin_elf_read_relocs)
	(struct Elf_(r_bin_elf_obj_t) *bin, RBinElfReloc *ret, int n, ut64 offset, int is_rela, int info) {
#if R_BIN_ELF64
	ut64 *buf;
#else
	ut32 *buf;
#endif
	int i;
	ut64 size;

	if (!bin || n < 1)
		return 0;

	if (info > 1 && info > bin->ehdr.e_shnum)
		return 0;

	size = n * (is_rela? sizeof (Elf_(Rela)): sizeof (Elf_(Rel)));

	if (!(buf = malloc (size)))
		return 0;

	if (r_buf_fread_at (bin->b, offset, (ut8 *)buf, 
#if R_BIN_ELF64
		bin->endian? (is_rela? "3L": "2L"): (is_rela? "3l": "2l"),
#else
		bin->endian? (is_rela? "3I": "2I"): (is_rela? "3i": "2i"),
#endif
		n) != size) {
		eprintf ("Could not read the relocations!\n");
		R_FREE (buf);
		return 0;
	}

	int sym, type;
	RBinElfSymbol *ref_sym;

	for (i = 0; i < n; i++) {
		ret[i].is_rela = is_rela;

		ut64 r_offset = buf[0 + i * (is_rela? 3: 2)];
		ut64 r_info = buf[1 + i * (is_rela? 3: 2)];

		switch (bin->ehdr.e_type) {
			case ET_DYN:
				ret[i].address = r_offset;
				break;
			case ET_EXEC:
				ret[i].address = r_offset;
				break;
			case ET_REL:
				ret[i].address = bin->shdr[info].sh_addr + r_offset;
				break;
		}

		ret[i].offset = r_bin_elf_get_offset (bin, ret[i].address);

#if R_BIN_ELF64
		sym = ELF64_R_SYM (r_info);
		type = ELF64_R_TYPE (r_info);
#else
		sym = ELF32_R_SYM (r_info);
		type = ELF32_R_TYPE (r_info);
#endif

		// Try to assign the respective plt address to every imported symbol
		ref_sym = r_bin_elf_sym_lookup (bin, sym);
		if (sym && ref_sym && ref_sym->is_import) {
			// eprintf ("Assoc %s (%i)\n", ref_sym->name, sym);
			ut64 plt_off = r_bin_elf_get_offset (bin, ret[i].address);
#if R_BIN_ELF64
			ut64 a = 0;
			r_buf_fread_at (bin->b, plt_off, &a, bin->endian? "L":"l", 1);
#else
			ut32 a = 0;
			r_buf_fread_at (bin->b, plt_off, &a, bin->endian? "I": "i", 1);
#endif
			// TODO : This needs to be adjusted per-arch
			ref_sym->address = a - 6;
		}

		ret[i].sym = sym;
		ret[i].type = type;

		if (is_rela)
			ret[i].addend = buf[2 + i * (is_rela? 3: 2)];
	}

	R_FREE (buf);

	return i;
}

int Elf_(r_bin_elf_get_relocs_num)(struct Elf_(r_bin_elf_obj_t) *bin) {
	Elf_(Dyn) *d_tags[3];
	int i, n;

	if (!bin)
		return 0;

	n = 0;

	if (bin->ehdr.e_shnum) {
		for (i = 0; i < bin->ehdr.e_shnum; i++) {
			if (bin->shdr[i].sh_type != SHT_RELA && bin->shdr[i].sh_type != SHT_REL)
				continue;

			n += bin->shdr[i].sh_size / 
				((bin->shdr[i].sh_type == SHT_RELA)? 
				sizeof (Elf_(Rela)): sizeof (Elf_(Rel)));
		}

		return n;
	}

	// DT_JMPREL DT_PLTRELSZ DT_PLTREL
	d_tags[0] = Elf_(r_bin_elf_dyn_find) (bin, DT_JMPREL);
	d_tags[1] = Elf_(r_bin_elf_dyn_find) (bin, DT_PLTRELSZ);
	d_tags[2] = Elf_(r_bin_elf_dyn_find) (bin, DT_PLTREL);

	if (d_tags[0] && d_tags[1] && d_tags[2]) {
		n += d_tags[1]->d_un.d_val / 
			((d_tags[2]->d_un.d_val == DT_RELA)?
			sizeof (Elf_(Rela)): sizeof (Elf_(Rel)));
	}

	d_tags[0] = Elf_(r_bin_elf_dyn_find) (bin, DT_RELA);
	d_tags[1] = Elf_(r_bin_elf_dyn_find) (bin, DT_RELASZ);
	d_tags[2] = Elf_(r_bin_elf_dyn_find) (bin, DT_RELAENT);

	if (d_tags[0] && d_tags[1] && d_tags[2])
		n += d_tags[1]->d_un.d_val / d_tags[2]->d_un.d_val;
	
	d_tags[0] = Elf_(r_bin_elf_dyn_find) (bin, DT_REL);
	d_tags[1] = Elf_(r_bin_elf_dyn_find) (bin, DT_RELSZ);
	d_tags[2] = Elf_(r_bin_elf_dyn_find) (bin, DT_RELENT);

	if (d_tags[0] && d_tags[1] && d_tags[2])
		n += d_tags[1]->d_un.d_val / d_tags[2]->d_un.d_val;

	return n;
}

RBinElfReloc *Elf_(r_bin_elf_get_relocs)(struct Elf_(r_bin_elf_obj_t) *bin) {
	Elf_(Dyn) *d_tags[3];
	RBinElfReloc *rel;
	ut64 offset, size;
	int i, n, p, type;
	size_t elm_size;

	if (!bin)
		return NULL;

	bin->_rel_table = NULL;

	n = Elf_(r_bin_elf_get_relocs_num) (bin);

	if (!(rel = calloc (n + 1, sizeof (RBinElfReloc))))
		return NULL;

	rel[n].last = R_TRUE;

	p = 0;

	if (bin->ehdr.e_shnum) {
		for (i = 0; i < bin->ehdr.e_shnum; i++) {
			if (bin->shdr[i].sh_type != SHT_RELA && bin->shdr[i].sh_type != SHT_REL)
				continue;
			
			elm_size = (bin->shdr[i].sh_type == SHT_RELA)?
				sizeof (Elf_(Rela)) : sizeof (Elf_(Rel));

			p += Elf_(r_bin_elf_read_relocs) (bin, &rel[p], 
					bin->shdr[i].sh_size / elm_size, 
					bin->shdr[i].sh_offset, 
					bin->shdr[i].sh_type == SHT_RELA,
					bin->shdr[i].sh_info);
		}

		return rel;
	}

	d_tags[0] = Elf_(r_bin_elf_dyn_find) (bin, DT_JMPREL);
	d_tags[1] = Elf_(r_bin_elf_dyn_find) (bin, DT_PLTRELSZ);
	d_tags[2] = Elf_(r_bin_elf_dyn_find) (bin, DT_PLTREL);

	if (d_tags[0] && d_tags[1] && d_tags[2]) {
		elm_size = (d_tags[2]->d_un.d_val == DT_RELA)?
			sizeof (Elf_(Rela)) : sizeof (Elf_(Rel));

		p += Elf_(r_bin_elf_read_relocs) (bin, &rel[p],
				d_tags[1]->d_un.d_val / elm_size,
				r_bin_elf_get_offset (bin, d_tags[0]->d_un.d_val),
				d_tags[2]->d_un.d_val == DT_RELA,
				-1);
	}

	d_tags[0] = Elf_(r_bin_elf_dyn_find) (bin, DT_REL);
	d_tags[1] = Elf_(r_bin_elf_dyn_find) (bin, DT_RELSZ);

	if (d_tags[0] && d_tags[1]) {
		p += Elf_(r_bin_elf_read_relocs) (bin, &rel[p],
				d_tags[1]->d_un.d_val / sizeof (Elf_(Rel)),
				r_bin_elf_get_offset (bin, d_tags[0]->d_un.d_val),
				R_FALSE,
				-1);
	}

	d_tags[0] = Elf_(r_bin_elf_dyn_find) (bin, DT_RELA);
	d_tags[1] = Elf_(r_bin_elf_dyn_find) (bin, DT_RELASZ);

	if (d_tags[0] && d_tags[1]) {
		p += Elf_(r_bin_elf_read_relocs) (bin, &rel[p],
				d_tags[1]->d_un.d_val / sizeof (Elf_(Rela)),
				r_bin_elf_get_offset (bin, d_tags[0]->d_un.d_val),
				R_FALSE,
				-1);
	}

#ifdef ELF_DEBUG
	eprintf ("%i out of %i processed\n", p, n);
#endif

	return rel;
}

struct r_bin_elf_symbol_t* Elf_(r_bin_elf_get_symbols)(struct Elf_(r_bin_elf_obj_t) *bin, int type) {
	struct r_bin_elf_symbol_t *ret = NULL;
	Elf_(Sym) *sym;
	int i, filt_syms;
	char *strtab;

	if (!bin || !bin->b || !bin->sym_entries)
		return NULL;

	if ((sym = calloc (bin->sym_entries, sizeof (Elf_(Sym)))) == NULL)
		return NULL;

	if (r_buf_fread_at (bin->b, bin->sym_offset, (ut8 *)sym,
#if R_BIN_ELF64
			bin->endian? "I2cS2L": "i2cs2l",
#else
			bin->endian? "3I2cS": "3i2cs",
#endif
			bin->sym_entries) != sizeof (Elf_(Sym)) * bin->sym_entries) {
		eprintf ("Could not read the symbol table\n");
		free(sym);
		return NULL;
	}

	if ((strtab = r_bin_elf_get_strtab (bin)) == NULL)
		return NULL;

	filt_syms = 0;

	for (i = 0; i < bin->sym_entries; i++) {
		// Skip the uninteresting cruft
		if (ELF_ST_TYPE(sym[i].st_info) != STT_FUNC &&
			ELF_ST_TYPE(sym[i].st_info) != STT_OBJECT && 
			ELF_ST_TYPE(sym[i].st_info) != STT_SECTION &&
			// ELF_ST_TYPE(sym[i].st_info) != STT_NOTYPE &&
			1)
			continue;

		if (type & R_BIN_ELF_IMPORTS && type & R_BIN_ELF_SYMBOLS) {
		} else {
			if (type & R_BIN_ELF_IMPORTS && sym[i].st_shndx != SHN_UNDEF)
				continue;
			if (type & R_BIN_ELF_SYMBOLS && sym[i].st_shndx == SHN_UNDEF)
				continue;
		}

		// We're not interested in sections that don't get loaded in memory
		if (ELF_ST_TYPE(sym[i].st_info) == STT_SECTION && !sym[i].st_value)
			continue;
		
		ret = realloc (ret, (filt_syms + 1) * sizeof (struct r_bin_elf_symbol_t));

		if (ELF_ST_TYPE(sym[i].st_info) != STT_SECTION) {
			if (sym[i].st_name && sym[i].st_name < bin->strtab_size)
				strncpy (ret[filt_syms].name, strtab + sym[i].st_name, sizeof (ret[filt_syms].name));
			else
				snprintf (ret[filt_syms].name, sizeof (ret[filt_syms].name), "unnamed_%i", i);
		} else {
			if (sym[i].st_shndx == SHN_XINDEX)
				snprintf (ret[filt_syms].name, sizeof (ret[filt_syms].name), "xindex_%i", i);
			else if (sym[i].st_shndx < bin->ehdr.e_shnum && bin->shdr[sym[i].st_shndx].sh_name < bin->shstr_size)
				strncpy (ret[filt_syms].name, bin->shstr_buf + bin->shdr[sym[i].st_shndx].sh_name, sizeof (ret[filt_syms].name));
			else
				snprintf (ret[filt_syms].name, sizeof (ret[filt_syms].name), "invalid_%i", i);
		}

		ret[filt_syms].ordinal = i;
		ret[filt_syms].is_import = (sym[i].st_shndx == SHN_UNDEF);
		ret[filt_syms].size = sym[i].st_size;
		ret[filt_syms].offset = 0;
		ret[filt_syms].address = 0;
		ret[filt_syms].last = R_FALSE;

#if 1
		if (sym[i].st_shndx != SHN_UNDEF) {
			if (bin->ehdr.e_type == ET_REL) {
				switch (sym[i].st_shndx) {
					case SHN_ABS:
						ret[filt_syms].address = sym[i].st_value;
						ret[filt_syms].offset = r_bin_elf_get_offset (bin, sym[i].st_value);
					break;

					case SHN_COMMON:
					case SHN_UNDEF:
						R_FREE (sym);
						R_FREE (strtab);
						R_FREE (ret);
						return NULL;
					break;

					default:
						if (sym[i].st_shndx < bin->ehdr.e_shnum) {
#ifdef ELF_DEBUG
							// eprintf("uhuh\n%i\n%x %x\n%x\n",
							// 		sym[i].st_shndx,
							// 		bin->shdr[sym[i].st_shndx].sh_offset,
							// 		bin->shdr[sym[i].st_shndx].sh_addr,
							// 		sym[i].st_value);
#endif
							ret[filt_syms].offset = bin->shdr[sym[i].st_shndx].sh_offset + sym[i].st_value;
							ret[filt_syms].address = bin->shdr[sym[i].st_shndx].sh_addr + sym[i].st_value;
						} else {
							eprintf ("Symbol refers to non-existent section!\n");
							R_FREE (sym);
							R_FREE (strtab);
							R_FREE (ret);
							return NULL;
						}
					break;
				}
			} else {
				ret[filt_syms].address = sym[i].st_value;
				ret[filt_syms].offset = r_bin_elf_get_offset (bin, sym[i].st_value);
			}
		} else {
			ret[filt_syms].address = sym[i].st_value;
			ret[filt_syms].offset = r_bin_elf_get_offset (bin, sym[i].st_value);
		}
#endif

		#define s_bind(x) snprintf (ret[filt_syms].bind, ELF_STRING_LENGTH, x);
		switch (ELF_ST_BIND (sym[i].st_info)) {
			case STB_LOCAL:  s_bind ("LOCAL"); break;
			case STB_GLOBAL: s_bind ("GLOBAL"); break;
			case STB_NUM:    s_bind ("NUM"); break;
			case STB_LOOS:   s_bind ("LOOS"); break;
			case STB_HIOS:   s_bind ("HIOS"); break;
			case STB_LOPROC: s_bind ("LOPROC"); break;
			case STB_HIPROC: s_bind ("HIPROC"); break;
			default:         s_bind ("UNKNOWN");
		}
		#define s_type(x) snprintf (ret[filt_syms].type, ELF_STRING_LENGTH, x);
		switch (ELF_ST_TYPE (sym[i].st_info)) {
			case STT_NOTYPE:  s_type ("NOTYPE"); break;
			case STT_OBJECT:  s_type ("OBJECT"); break;
			case STT_FUNC:    s_type ("FUNC"); break;
			case STT_SECTION: s_type ("SECTION"); break;
			case STT_FILE:    s_type ("FILE"); break;
			case STT_COMMON:  s_type ("COMMON"); break;
			case STT_TLS:     s_type ("TLS"); break;
			case STT_NUM:     s_type ("NUM"); break;
			case STT_LOOS:    s_type ("LOOS"); break;
			case STT_HIOS:    s_type ("HIOS"); break;
			case STT_LOPROC:  s_type ("LOPROC"); break;
			case STT_HIPROC:  s_type ("HIPROC"); break;
			default:          s_type ("UNKNOWN");
		}

		filt_syms++;
	}

	R_FREE (sym);
	R_FREE (strtab);

	ret = realloc (ret, (filt_syms + 1) * sizeof (struct r_bin_elf_symbol_t));
	ret[filt_syms].last = R_TRUE;

	return ret;
}

struct r_bin_elf_lib_t* Elf_(r_bin_elf_get_libs)(struct Elf_(r_bin_elf_obj_t) *bin) {
	struct r_bin_elf_lib_t *ret = NULL;
	char *strtab;
	int i, libs_count;

	if (!bin || !bin->dyn_entries || !bin->strtab_size)
		return NULL;

	if ((strtab = r_bin_elf_get_strtab (bin)) == NULL)
		return NULL;

	libs_count = 0;

	for (i = 0; i < bin->dyn_entries; i++) {
		if (bin->dyn_buf[i].d_tag == DT_NEEDED) {
			if (bin->dyn_buf[i].d_un.d_val > bin->strtab_size)
				continue;
			if (!strtab[bin->dyn_buf[i].d_un.d_val])
				continue;

			ret = realloc (ret, (libs_count + 1) * sizeof (struct r_bin_elf_lib_t));
			if (!ret) {
				perror ("realloc (libs)");
				return NULL;
			}

			strncpy (ret[libs_count].name, strtab + bin->dyn_buf[i].d_un.d_val, sizeof (ret[libs_count].name));
			ret[libs_count].last = R_FALSE;
			
			libs_count++;
		}
	}

	ret = realloc (ret, (libs_count + 1) * sizeof (struct r_bin_elf_lib_t));
	if (!ret) {
		perror ("realloc (libs)");
		return NULL;
	}
	ret[libs_count].last = R_TRUE;

	return ret;
}

ut64 Elf_(r_bin_elf_get_init_offset)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	ut8 buf[512];
	if (!bin)
		return 0LL;
	if (r_buf_read_at (bin->b, entry+16, buf, sizeof (buf)) == -1) {
		eprintf ("Warning: read (init_offset)\n");
		return 0;
	}
	if (buf[0] == 0x68) { // push // x86 only
		memmove (buf, buf+1, 4);
		return (ut64)((int)(buf[0]+(buf[1]<<8)+(buf[2]<<16)+(buf[3]<<24)))-bin->baddr;
	}
	return 0;
}

ut64 Elf_(r_bin_elf_get_fini_offset)(struct Elf_(r_bin_elf_obj_t) *bin) {
	// Elf_(Dyn) *d_fini;
	// RBinAddr *addr;

	// if (!(addr = malloc (sizeof (RBinAddr))))
	// 	return NULL;

	// d_fini = Elf_(r_bin_elf_dyn_find) (bin, DT_FINI);
	// if (d_fini) {
		// addr->vaddr = d_fini->d_un.d_ptr;
		// addr->paddr = addr->vaddr - bin->baddr;
	// }

	// return addr;
	return 0;
}

ut64 Elf_(r_bin_elf_get_entry_offset)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut64 entry;
	if (!bin)
		return 0LL;
	entry = (ut64) bin->ehdr.e_entry;
	if (entry == 0LL) {
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".init.text");
		if (entry != UT64_MAX) return entry;
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".text");
		if (entry != UT64_MAX) return entry;
		entry = Elf_(r_bin_elf_get_section_offset)(bin, ".init");
		if (entry != UT64_MAX) return entry;
	}
	if (bin->ehdr.e_entry < bin->baddr)
		return bin->ehdr.e_entry;
	return bin->ehdr.e_entry - bin->baddr;
}

ut64 Elf_(r_bin_elf_get_main_offset)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut64 entry = Elf_(r_bin_elf_get_entry_offset) (bin);
	ut8 buf[512];
	if (!bin)
		return 0LL;

	if (r_buf_read_at (bin->b, entry, buf, sizeof (buf)) == -1) {
		eprintf ("Warning: read (main)\n");
		return 0;
	}
	// TODO: Use arch to identify arch before memcmp's

	// MIPS
	/* get .got, calculate offset of main symbol */
	if (!memcmp (buf, "\x21\x00\xe0\x03\x01\x00\x11\x04\x00\x00\x00\x00", 12)) {
		ut64 got_addr = 0LL; // TODO: get .got offset
		short delta = (buf[28]+(buf[29]<<8));
		// NOTE: This is the way to resolve 'gp' register
		r_buf_read_at (bin->b, got_addr+(32734+delta), buf, 4);
		return (ut64)((int)(buf[0]+(buf[1]<<8)+(buf[2]<<16)+(buf[3]<<24)))-bin->baddr;
	}
	// ARM
	if (!memcmp (buf, "\x24\xc0\x9f\xe5\x00\xb0\xa0\xe3", 8)) {
		return (ut64)((int)(buf[48+0]+(buf[48+1]<<8)+
		(buf[48+2]<<16)+(buf[48+3]<<24)))-bin->baddr;
	}
	// X86-PIE
	if (buf[0x1d] == 0x48 && buf[0x1e] == 0x8b) {
		if (!memcmp (buf, "\x31\xed\x49\x89", 4)) {// linux
			ut64 maddr, baddr;
			ut32 n32, *num = (ut32 *)(buf+0x20);
			maddr = entry + 0x24 + *num;
			if (r_buf_read_at (bin->b, maddr, (ut8*)&n32, sizeof (n32)) == -1) {
				eprintf ("Warning: read (maddr) 2\n");
				return 0;
			}
			maddr = (ut64)n32;
			baddr = (bin->ehdr.e_entry >> 16) << 16;
			if (bin->phdr) {
				baddr = Elf_(r_bin_elf_get_baddr) (bin);
			}
			maddr += baddr;
			return maddr;
		}
	}
	// X86-NONPIE
#if R_BIN_ELF64
	if (!memcmp (buf, "\x49\x89\xd9", 3) && buf[156] == 0xe8) {// openbsd
		return (ut64)((int)(buf[157+0]+(buf[157+1]<<8)+
		(buf[157+2]<<16)+(buf[157+3]<<24)))+ entry + 156 + 5;
	}
	if (!memcmp (buf+29, "\x48\xc7\xc7", 3)) // linux
		return (ut64)((int)(buf[29+3]+(buf[29+4]<<8)+
		(buf[29+5]<<16)+(buf[29+6]<<24)))-bin->baddr;
#else
	if (buf[23] == '\x68')
		return (ut64)((int)(buf[23+1]+(buf[23+2]<<8)+
		(buf[23+3]<<16)+(buf[23+4]<<24)))-bin->baddr;
#endif
	return 0;
}

struct r_bin_elf_field_t* Elf_(r_bin_elf_get_fields)(struct Elf_(r_bin_elf_obj_t) *bin) {
	struct r_bin_elf_field_t *ret = NULL;
	int i;

	if (!bin)
		return NULL;

	if ((ret = calloc (bin->ehdr.e_phnum + 3, sizeof (struct r_bin_elf_field_t))) == NULL)
		return NULL;

	strncpy (ret[0].name, "ehdr", ELF_STRING_LENGTH);
	ret[0].offset = 0;
	strncpy (ret[1].name, "shoff", ELF_STRING_LENGTH);
	ret[1].offset = bin->ehdr.e_shoff;
	strncpy (ret[2].name, "phoff", ELF_STRING_LENGTH);
	ret[2].offset = bin->ehdr.e_phoff;

	for (i = 0; i < bin->ehdr.e_phnum; i++) {
		snprintf (ret[3 + i].name, ELF_STRING_LENGTH, "phdr_%i", i);
		ret[3 + i].offset = bin->phdr[i].p_offset;
	}

	ret[3 + i].last = R_TRUE;

	return ret;
}

int Elf_(r_bin_elf_get_bits)(struct Elf_(r_bin_elf_obj_t) *bin) {
	/* Hack for ARCompact */
	if (bin->ehdr.e_machine == EM_ARC_A5)
		return 16;

	switch (bin->ehdr.e_ident[EI_CLASS]) {
		case ELFCLASS32:   return 32;
		case ELFCLASS64:   return 64;
		case ELFCLASSNONE:
		default:           return 32; // defaults
	}
}

int Elf_(r_bin_elf_has_nx)(struct Elf_(r_bin_elf_obj_t) *bin) {
	return Elf_(r_bin_elf_has_phdr) (bin, PT_GNU_STACK);
}

int Elf_(r_bin_elf_has_relro)(struct Elf_(r_bin_elf_obj_t) *bin) {
	return Elf_(r_bin_elf_has_phdr) (bin, PT_GNU_RELRO);
}

ut64 Elf_(r_bin_elf_get_baddr)(struct Elf_(r_bin_elf_obj_t) *bin) {
	return bin->baddr;
}

ut64 Elf_(r_bin_elf_get_boffset)(struct Elf_(r_bin_elf_obj_t) *bin) {
	return bin->boffset;
}

int Elf_(r_bin_elf_get_stripped)(struct Elf_(r_bin_elf_obj_t) *bin) {
	return Elf_(r_bin_elf_has_shdr) (bin, SHT_SYMTAB);
}

int Elf_(r_bin_elf_get_static)(struct Elf_(r_bin_elf_obj_t) *bin) {
	return Elf_(r_bin_elf_has_phdr) (bin, PT_INTERP);
}

int Elf_(r_bin_elf_has_va)(struct Elf_(r_bin_elf_obj_t) *bin) {
	ut32 e_type = (ut32)bin->ehdr.e_type; // cast to avoid warn in iphone-gcc, must be ut16
	return (e_type == ET_REL)? 0: 1;
}

static int Elf_(r_bin_elf_init)(struct Elf_(r_bin_elf_obj_t) *bin) {
	if (!Elf_(r_bin_elf_init_ehdr) (bin))
		return R_FALSE;

	if (!Elf_(r_bin_elf_init_phdr) (bin)) {
		eprintf ("Error: Cannot initialize program headers\n");
		return R_FALSE;
	}

	if (!Elf_(r_bin_elf_init_shdr) (bin)) {
		eprintf ("Error: Cannot initialize section headers\n");
		return R_FALSE;
	}

	(void)Elf_(r_bin_elf_choose_symbol_table) (bin);

	bin->_sym_table = Elf_(r_bin_elf_get_symbols) (bin, R_BIN_ELF_IMPORTS | R_BIN_ELF_SYMBOLS);
	bin->_rel_table = Elf_(r_bin_elf_get_relocs) (bin);

	sdb_bool_set (bin->kv, "elf.relro", Elf_(r_bin_elf_has_relro)(bin), 0);
	sdb_num_set (bin->kv, "elf_header_size.offset", sizeof (Elf_(Ehdr)), 0);
	sdb_num_set (bin->kv, "elf_phdr_size.offset", sizeof (Elf_(Phdr)), 0);
	sdb_num_set (bin->kv, "elf_shdr_size.offset", sizeof (Elf_(Shdr)), 0);
#if R_BIN_ELF64
	sdb_num_set (bin->kv, "elf_phdr.offset", bin->ehdr.e_phoff, 0);
	sdb_set (bin->kv, "elf_phdr.format", "qqqqqqqq type offset vaddr paddr filesz memsz flags align", 0);
	sdb_num_set (bin->kv, "elf_shdr.offset", bin->ehdr.e_shoff, 0);
	sdb_set (bin->kv, "elf_shdr.format", "xxqqqqxxqq name type flags addr offset size link info addralign entsize", 0);
#else
	sdb_num_set (bin->kv, "elf_phdr.offset", bin->ehdr.e_phoff, 0);
	sdb_set (bin->kv, "elf_phdr.format", "wxxxwwww type offset vaddr paddr filesz memsz flags align", 0);
	sdb_num_set (bin->kv, "elf_shdr.offset", bin->ehdr.e_shoff, 0);
	sdb_set (bin->kv, "elf_shdr.format", "xxxxxxxxxx name type flags addr offset size link info addralign entsize", 0);
#endif

	return R_TRUE;
}

const char *Elf_(r_bin_elf_get_arch)(struct Elf_(r_bin_elf_obj_t) *bin) {
	switch (bin->ehdr.e_machine) {
		case EM_ARC:
		case EM_ARC_A5:
			return "arc";
		case EM_AVR:
			return "avr";
		case EM_68K:
			return "m68k";
		case EM_MIPS:
		case EM_MIPS_RS3_LE:
		case EM_MIPS_X:
			return "mips";
		case EM_ARM:
		case EM_AARCH64:
			return "arm";
		case EM_SPARC:
		case EM_SPARC32PLUS:
		case EM_SPARCV9:
			return "sparc";
		case EM_PPC:
		case EM_PPC64:
			return "ppc";
		case EM_PROPELLER:
			return "propeller";
		case EM_SH: 
			return "sh";
		case EM_X86_64:
		case EM_386:
			return "x86";
	}

	return NULL;
}

int Elf_(r_bin_elf_is_big_endian)(struct Elf_(r_bin_elf_obj_t) *bin) {
	return bin->endian;
}

char *Elf_(r_bin_elf_get_rpath)(struct Elf_(r_bin_elf_obj_t) *bin) {
	Elf_(Dyn) *d_runpath;
	char *strtab, *ret;

	if (!bin)
		return NULL;

	if ((strtab = r_bin_elf_get_strtab (bin)) == NULL)
		return NULL;

	if (!(d_runpath = Elf_(r_bin_elf_dyn_find) (bin, DT_RUNPATH)))
		d_runpath = Elf_(r_bin_elf_dyn_find) (bin, DT_RPATH);

	if (!d_runpath) {
		R_FREE (strtab);
		return NULL;
	}

	if (d_runpath->d_un.d_val > bin->strtab_size) {
		R_FREE (strtab);
		return NULL;
	}

	if (!(ret = calloc (1, ELF_STRING_LENGTH))) {
		R_FREE (strtab);
		return NULL;
	}

	strncpy (ret, strtab + d_runpath->d_un.d_val, ELF_STRING_LENGTH);

	return ret;
}

void* Elf_(r_bin_elf_free)(struct Elf_(r_bin_elf_obj_t)* bin) {
	R_FREE (bin->shdr);
	R_FREE (bin->phdr);
	R_FREE (bin->shstr_buf);
	R_FREE (bin->dyn_buf);
	R_FREE (bin->_sym_table);
	R_FREE (bin->_rel_table);
	r_buf_free (bin->b);

	return NULL;
}

struct Elf_(r_bin_elf_obj_t)* Elf_(r_bin_elf_new)(const char* file) {
	return NULL;
}

struct Elf_(r_bin_elf_obj_t)* Elf_(r_bin_elf_new_buf)(struct r_buf_t *buf) {
	struct Elf_(r_bin_elf_obj_t) *bin = R_NEW0 (struct Elf_(r_bin_elf_obj_t));
	bin->kv = sdb_new0 ();
	bin->b = r_buf_new ();
	bin->size = buf->length;
	if (!r_buf_set_bytes (bin->b, buf->buf, buf->length))
		return Elf_(r_bin_elf_free) (bin);
	if (!Elf_(r_bin_elf_init) (bin))
		return Elf_(r_bin_elf_free) (bin);
	return bin;
}
