/* radare - LGPL - Copyright 2010-2011 - pancake<nopcode.org> */

#include <r_anal.h>

R_API RAnalValue *r_anal_value_new() {
	RAnalValue *ret = R_NEW0 (RAnalValue);
	if (ret) 
		ret->type = R_ANAL_VALUE_TYPE_INVALID;
	return ret;
}

R_API RAnalValue *r_anal_value_new_from_string(const char *str) {
	/* TODO */
	return NULL;
}

R_API RAnalValue *r_anal_value_copy(RAnalValue *ov) {
	RAnalValue *v = R_NEW (RAnalValue);
	memcpy (v, ov, sizeof (RAnalValue));
	// reference to reg and regdelta should be kept
	return v;
}

// TODO: move into .h as #define free
R_API void r_anal_value_free(RAnalValue *value) {
	if (value) {
		free (value->reg);
		free (value->index);
		free (value);
	}
}

// mul*value+regbase+regidx+delta
R_API ut64 r_anal_value_to_ut64(RAnal *anal, RAnalValue *val) {
	ut64 num;
	/*if (val==NULL)*/
		/*return 0LL;*/
	/*num = val->base + (val->delta*(val->mul?val->mul:1));*/
	/*if (val->reg)*/
		/*num += r_reg_get_value (anal->reg, val->reg);*/
	/*if (val->regdelta)*/
		/*num += r_reg_get_value (anal->reg, val->regdelta);*/
	/*switch (val->memref) {*/
	/*case 1:*/
	/*case 2:*/
	/*case 4:*/
	/*case 8:*/
		/*anal->bio ...*/
		/*eprintf ("TODO: memref for to_ut64 not supported\n");*/
		/*break;*/
	/*}*/
	return num;
}

R_API int r_anal_value_set_ut64(RAnal *anal, RAnalValue *val, ut64 num) {
	/*if (val->memref) {*/
		/*if (anal->iob.io) {*/
			/*ut8 data[8];*/
			/*ut64 addr = r_anal_value_to_ut64 (anal, val);*/
			/*r_mem_set_num (data, val->memref, num, anal->big_endian);*/
			/*anal->iob.write_at (anal->iob.io, addr, data, val->memref);*/
		/*} else eprintf ("No IO binded to r_anal\n");*/
	/*} else {*/
		/*if (val->reg)*/
			/*r_reg_set_value (anal->reg, val->reg, num);*/
	/*}*/
	/*return R_FALSE;							//is this necessary*/
}

R_API char *r_anal_value_to_string (RAnalValue *value) {
	char *out;

#define ss(x) (x)?(x)->name:"(null)"

	switch (value->type) {
		case R_ANAL_VALUE_TYPE_IMM:
			out = r_str_newf ("0x%"PFMT64x, value->imm); 
			break;
		case R_ANAL_VALUE_TYPE_MEM:
			out = r_str_new ("[");
			if (value->reg)
				out = r_str_concatf (out, "%s", ss(value->reg));
			if (value->index)
				out = r_str_concatf (out, "+%s", ss(value->index));
			if (value->disp)
				out = r_str_concatf (out, "+0x%"PFMT64x, value->disp);
			out = r_str_concat (out, "]");
			break;
		default:
			out = NULL;
	}

#undef ss

	return out;
}
