/* radare - LGPL - Copyright 2009-2014 - pancake */

static void r_core_file_info (RCore *core, int mode) {
	const char *fn = NULL;
	int dbg = r_config_get_i (core->config, "cfg.debug");
	RBinInfo *info = r_bin_get_info (core->bin);
	RBinFile *binfile = r_core_bin_cur (core);
	RCoreFile *cf = core->file;
	RBinPlugin *plugin = r_bin_file_cur_plugin (binfile);
	if (mode == R_CORE_BIN_JSON)
		r_cons_printf ("{");
	if (mode == R_CORE_BIN_RADARE)
		return;
	if (info) {
		fn = info->file;
		switch (mode) {
		case R_CORE_BIN_JSON:
		r_cons_printf ("\"type\":\"%s\","
			"\"os\":\"%s\","
			"\"arch\":\"%s\","
			"\"bits\":%d,"
			"\"endian\":\"%s\","
			, info->type
			, info->os
			, info->machine
			, info->bits
			, info->big_endian? "big": "little");
			break;
		default:
		r_cons_printf ("type\t%s\n"
			"os\t%s\n"
			"arch\t%s\n"
			"bits\t%d\n"
			"endian\t%s\n"
			, info->type
			, info->os
			, info->machine
			, info->bits
			, info->big_endian? "big": "little");
			break;
		}
	} else fn = cf ? cf->filename : NULL;
	if (cf && mode == R_CORE_BIN_JSON) {
		r_cons_printf ("\"file\":\"%s\"", fn);
		if (dbg) dbg = R_IO_WRITE | R_IO_EXEC;
		r_cons_printf (",\"fd\":%d", cf->desc->fd);
		r_cons_printf (",\"size\":%d", cf->size);
		r_cons_printf (",\"mode\":\"%s\"", r_str_rwx_i (
			cf->rwx | dbg));
		r_cons_printf (",\"block\":%d", core->blocksize);
		r_cons_printf (",\"uri\":\"%s\"", cf->uri);
		if (binfile) {
			if (binfile->curxtr)
				r_cons_printf (",\"packet\":\"%s\"",
					binfile->curxtr->name);
			if (plugin)
				r_cons_printf (",\"format\":\"%s\"",
					plugin->name);
		}
		r_cons_printf ("}");
	} else if (cf) {
		//r_cons_printf ("# Core file info\n");
		r_cons_printf ("file\t%s\n", fn);
		if (dbg) dbg = R_IO_WRITE | R_IO_EXEC;
		r_cons_printf ("fd\t%d\n", cf->desc->fd);
		r_cons_printf ("size\t0x%x\n", cf->size);
		r_cons_printf ("mode\t%s\n", r_str_rwx_i (cf->rwx | dbg));
		r_cons_printf ("block\t0x%x\n", core->blocksize);
		r_cons_printf ("uri\t%s\n", cf->uri);
		if (binfile && binfile->curxtr)
			r_cons_printf ("packet\t%s\n",
				binfile->curxtr->name);
		if (plugin)
			r_cons_printf ("format\t%s\n",
				plugin->name);
	}
}

static void cmd_info_bin(RCore *core, ut64 offset, int va, int mode) {
	if (core->file) {
		if (mode == R_CORE_BIN_JSON)
			r_cons_printf ("{\"bin\":");
		r_core_bin_info (core, R_CORE_BIN_ACC_INFO,
			mode, va, NULL, offset);
		if (mode == R_CORE_BIN_JSON)
			r_cons_printf (",\"core\":");
		r_core_file_info (core, mode);
		if (mode == R_CORE_BIN_JSON)
			r_cons_printf ("}\n");
	} else eprintf ("No selected file\n");
}

static int cmd_info(void *data, const char *input) {
	RCore *core = (RCore *)data;
	int newline = r_config_get_i (core->config, "scr.interactive");
	ut64 offset = r_bin_get_offset (core->bin);
	RBinObject *o = r_bin_cur_object (core->bin);
	RCoreFile *cf = core->file;

	int va = core->io->va || core->io->debug;
	int mode = 0; //R_CORE_BIN_SIMPLE;
	int is_array = 0;
	Sdb *db;

	if (strchr (input, '*'))
		mode = R_CORE_BIN_RADARE;
	if (strchr (input, 'j'))
		mode = R_CORE_BIN_JSON;

	if (mode == R_CORE_BIN_JSON) {
		if (strlen (input+1)>1)
			is_array = 1;
	}
	if (is_array)
		r_cons_printf ("{");
	if (!*input)
		cmd_info_bin (core, offset, va, mode);
	while (*input) {
		switch (*input) {
		case 'b':
			{
			ut64 baddr = r_config_get_i (core->config, "bin.baddr");
			if (input[1]==' ')
				baddr = r_num_math (core->num, input+1);
			// XXX: this will reload the bin using the buffer.
			// An assumption is made that assumes there is an underlying
			// plugin that will be used to load the bin (e.g. malloc://)
			// TODO: Might be nice to reload a bin at a specified offset?
			r_core_bin_reload (core, NULL, baddr);
			r_core_block_read (core, 0);
			}
			break;
		case 'k':
			db = o ? o->kv : NULL;
			//:eprintf ("db = %p\n", db);
			switch (input[1]) {
			case 'v':
				if (db) sdb_query (db, input+3);
				break;
			case '.':
			case ' ':
				if (db) sdb_query (db, input+2);
				break;
			case '\0':
				if (db) sdb_list (db);
				break;
			case '?':
			default:
				eprintf ("Usage: ik [sdb-query]\n");
			}
			break;
		case 'o': r_core_bin_load (core, input[1]==' '?
				input+2: cf->filename,
				r_config_get_i (core->config, "bin.baddr"));
			break;
	#define RBININFO(n,x) \
	if (is_array) { \
		if (is_array==1) is_array++; else r_cons_printf (","); \
		r_cons_printf ("\"%s\":",n); \
	}\
	r_core_bin_info (core,x,mode,va,NULL,offset);
		case 'A': newline=0; r_bin_list_archs (core->bin, 1); break;
		case 'S': RBININFO ("sections",R_CORE_BIN_ACC_SECTIONS); break;
		case 'h': RBININFO ("fields", R_CORE_BIN_ACC_FIELDS); break;
		case 'l': RBININFO ("libs", R_CORE_BIN_ACC_LIBS); break;
		case 's': RBININFO ("symbols", R_CORE_BIN_ACC_SYMBOLS); break;
		case 'R':
		case 'r': RBININFO ("relocs", R_CORE_BIN_ACC_RELOCS); break;
		case 'd': RBININFO ("dwarf", R_CORE_BIN_ACC_DWARF); break;
		case 'i': RBININFO ("imports",R_CORE_BIN_ACC_IMPORTS); break;
		case 'I': RBININFO ("info", R_CORE_BIN_ACC_INFO); break;
		case 'e': RBININFO ("entries",R_CORE_BIN_ACC_ENTRIES); break;
		case 'z': RBININFO ("strings",R_CORE_BIN_ACC_STRINGS); break;
		case 'c':
		case 'C': RBININFO ("classes",R_CORE_BIN_ACC_CLASSES); break;
		case 'a':
			{
				switch (mode) {
				case R_CORE_BIN_RADARE: cmd_info (core, "i*IiesSz"); break;
				case R_CORE_BIN_JSON: cmd_info (core, "ijIiesSz"); break;
				default:
				case R_CORE_BIN_SIMPLE: cmd_info (core, "iIiesSz"); break;
				}
			}
			break;
		case '?':
			r_cons_printf (
			"|Usage: i[aeciIsosSz][jq*]      ; get info from opened file\n"
			"|Output mode:\n"
			"| '*'   output in radare commands\n"
			"| 'j'   output in json\n"
			"| 'q'   simple quiet output\n"
			"|Actions:\n"
			"| i, ij       show info of current file (in JSON)\n"
			"| iA          list archs\n"
			"| ia          show all info (imports, exports, sections..)\n"
			"| ib          reload the current buffer for setting of the bin (use once only)\n"
			"| ic          list classes\n"
			"| id          debug information (source lines)\n"
			"| ie          entrypoint\n"
			"| ih          headers\n"
			"| ii          imports\n"
			"| iI          binary info\n"
			"| il          libraries\n"
			"| ik [query]  key-value database from RBinObject\n"
			"| io [file]   load info from file (or last opened) use bin.baddr\n"
			"| is          symbols\n"
			"| iS          sections\n"
			"| ir/iR       relocs\n"
			"| iz          strings\n"
			);
			goto done;
		case '*':
			mode = R_CORE_BIN_RADARE;
			goto done;
		case 'j':
			mode = R_CORE_BIN_JSON;
			cmd_info_bin (core, offset, va, mode);
			goto done;
		default:
			cmd_info_bin (core, offset, va, mode);
			break;
		}
		input++;
		if (!strcmp (input, "j"))
			break;
	}
done:
	if (is_array)
		r_cons_printf ("}\n");
	if (newline) r_cons_newline();
	return 0;
}
