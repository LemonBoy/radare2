/* radare - LGPL - Copyright 2012 - pancake<nopcode.org>
			     2014 - condret

	this file was based on anal_i8080.c */

#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_anal.h>
#include <r_reg.h>
#define GB_DIS_LEN_ONLY
#include "../../asm/arch/gb/gbdis.c"
#include "../arch/gb/meta_gb_cmt.c"
#include "../arch/gb/gb_makros.h"


