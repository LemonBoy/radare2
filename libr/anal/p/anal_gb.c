/* radare - LGPL - Copyright 2012 - pancake<nopcode.org>
			     2014 - condret

	this file was based on anal_i8080.c */

#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_reg.h>
#include "../../asm/arch/gb/gbdis.c"
#include "../arch/gb/meta_gb_cmt.c"
#include "../arch/gb/gb_makros.h"

struct r_anal_plugin_t r_anal_plugin_gb = {
	.name = "gb",
	.desc = "Gameboy CPU code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_NONE,
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_gb
};
#endif
