/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <x86.h>

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif
#if CS_API_MINOR < 1
#error Old Capstone not supported
#endif

#define esilprintf(op, fmt, arg...) r_strbuf_setf (&op->esil, fmt, ##arg)
#define INSOP(n) insn->detail->x86.operands[n]

static RAnalValue *convert_cs_to_r(RAnal *anal, csh handle, cs_x86_op *in) {
	RAnalValue *out = r_anal_value_new ();
	switch (in->type) {
		case X86_OP_IMM:
			out->type = R_ANAL_VALUE_TYPE_IMM;
			out->imm = in->imm;
			break;
		case X86_OP_REG:
			out->type = R_ANAL_VALUE_TYPE_REG;
			out->reg = //NULL; 
				(in->reg == X86_REG_INVALID) ? NULL : 
				r_reg_get (anal->reg, cs_reg_name(handle, in->reg), R_REG_TYPE_GPR);
			break;
		case X86_OP_MEM:
			out->type = R_ANAL_VALUE_TYPE_MEM;
			out->reg = //NULL;
				(in->mem.base == X86_REG_INVALID) ? NULL : 
				r_reg_get (anal->reg, cs_reg_name(handle, in->mem.base), R_REG_TYPE_GPR);
			out->index = //NULL;
				(in->mem.index == X86_REG_INVALID) ? NULL : 
				r_reg_get (anal->reg, cs_reg_name(handle, in->mem.index), R_REG_TYPE_GPR);
			out->disp = in->mem.disp;
			out->size = 4; // FIXME:LEMON
			break;
		case X86_OP_FP:
			out->type = R_ANAL_VALUE_TYPE_FP;
			out->fp = in->fp;
			break;
		default:
			break;
	}

	return out;
}

static int convert_cs_cond_from_insn (cs_insn *in) {
	switch (in->id) {
		case X86_INS_JL:
		case X86_INS_JLE:
		case X86_INS_JA:
		case X86_INS_JAE:
		case X86_INS_JB:
		case X86_INS_JBE:
		case X86_INS_JCXZ:
		case X86_INS_JECXZ:
		case X86_INS_JO:
		case X86_INS_JNO:
		case X86_INS_JS:
		case X86_INS_JNS:
		case X86_INS_JP:
		case X86_INS_JNP:
		case X86_INS_JE:
		case X86_INS_JNE:
		case X86_INS_JG:
		case X86_INS_JGE:
			return -1;
	}
	return R_ANAL_COND_AL;
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
	cs_insn *insn;
	int mode;
	int i;

	switch (a->bits) {
		case 16: mode = CS_MODE_16; break;
		case 32: mode = CS_MODE_32; break;
		case 64: mode = CS_MODE_64; break;
	}
	
	if (cs_open (CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
		return -1;

	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);

	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->size = 0;
	op->delay = 0;

	if (cs_disasm_ex (handle, (const ut8*)buf, len, addr, 1, &insn) < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		return -1;
	}

	r_strbuf_init (&op->esil);
	int rs = a->bits/8;
	const char *pc = (a->bits==16)?"ip":
		(a->bits==32)?"eip":"rip";
	const char *sp = (a->bits==16)?"sp":
		(a->bits==32)?"esp":"rsp";

	if (insn->detail->x86.op_count) {
		op->dst = convert_cs_to_r (a, handle, &INSOP(0));
		for (i = 1; i < insn->detail->x86.op_count; i++)
			op->src[i-1] = convert_cs_to_r (a, handle, &INSOP(i));
	}

	op->size = insn->size;
	switch (insn->id) {
		case X86_INS_FNOP:
		case X86_INS_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			if (a->decode)
				esilprintf (op, "");
			break;
		case X86_INS_CLI:
		case X86_INS_STI:
		case X86_INS_CLC:
		case X86_INS_STC:
			break;
		case X86_INS_MOV:
		case X86_INS_MOVZX:
		case X86_INS_MOVABS:
		case X86_INS_MOVHPD:
		case X86_INS_MOVHPS:
		case X86_INS_MOVLPD:
		case X86_INS_MOVLPS:
		case X86_INS_MOVBE:
		case X86_INS_MOVSB:
		case X86_INS_MOVSD:
		case X86_INS_MOVSQ:
		case X86_INS_MOVSS:
		case X86_INS_MOVSW:
		case X86_INS_MOVD:
		case X86_INS_MOVQ:
		case X86_INS_MOVDQ2Q:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case X86_INS_CMP:
		case X86_INS_VCMP:
		case X86_INS_CMPPD:
		case X86_INS_CMPPS:
		case X86_INS_CMPSW:
		case X86_INS_CMPSD:
		case X86_INS_CMPSQ:
		case X86_INS_CMPSB:
		case X86_INS_CMPSS:
		case X86_INS_TEST:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case X86_INS_LEA:
			op->type = R_ANAL_OP_TYPE_LEA;
			break;
		case X86_INS_ENTER:
		case X86_INS_PUSH:
		case X86_INS_PUSHAW:
		case X86_INS_PUSHAL:
		case X86_INS_PUSHF:
			op->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case X86_INS_LEAVE:
		case X86_INS_POP:
		case X86_INS_POPAW:
		case X86_INS_POPAL:
		case X86_INS_POPF:
		case X86_INS_POPCNT:
			op->type = R_ANAL_OP_TYPE_POP;
			break;
		case X86_INS_HLT:
		case X86_INS_RET:
		case X86_INS_RETF:
		case X86_INS_IRET:
		case X86_INS_IRETD:
		case X86_INS_IRETQ:
		case X86_INS_SYSRET:
			op->type = R_ANAL_OP_TYPE_RET;
			if (a->decode)
				esilprintf (op, "%s,[%d],%s,=,%d,%s,+=",
						sp, rs, pc, rs, sp);
			break;
		case X86_INS_INT1:
		case X86_INS_INT3:
		case X86_INS_INTO:
		case X86_INS_INT:
		case X86_INS_VMCALL:
		case X86_INS_VMMCALL:
			op->type = R_ANAL_OP_TYPE_TRAP;
			/* 32-bit linux syscalls */
			if ((int)INSOP(0).imm == 0x80)
				op->type = R_ANAL_OP_TYPE_SWI;
			if (a->decode)
				esilprintf (op, "%d,$", (int)INSOP(0).imm);
			break;
		case X86_INS_SYSCALL:
			op->type = R_ANAL_OP_TYPE_SWI;
			if (a->decode)
				esilprintf (op, "%d,$", (int)INSOP(0).imm);
			break;
		case X86_INS_JL:
		case X86_INS_JLE:
		case X86_INS_JA:
		case X86_INS_JAE:
		case X86_INS_JB:
		case X86_INS_JBE:
		case X86_INS_JCXZ:
		case X86_INS_JECXZ:
		case X86_INS_JO:
		case X86_INS_JNO:
		case X86_INS_JS:
		case X86_INS_JNS:
		case X86_INS_JP:
		case X86_INS_JNP:
		case X86_INS_JE:
		case X86_INS_JNE:
		case X86_INS_JG:
		case X86_INS_JGE:
			op->cond = convert_cs_cond_from_insn(insn);
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = INSOP(0).imm;
			op->fail = addr+op->size;
			break;
		case X86_INS_CALL:
		case X86_INS_LCALL:
			if (INSOP(0).type == X86_OP_IMM) {
				op->type = R_ANAL_OP_TYPE_CALL;
				op->jump = INSOP(0).imm;
			} else {
				op->type = R_ANAL_OP_TYPE_UCALL;
				op->jump = UT64_MAX;
			}
			op->fail = addr+op->size;
			break;
		case X86_INS_JMP:
		case X86_INS_LJMP:
			if (INSOP(0).type == X86_OP_IMM) {
				op->type = R_ANAL_OP_TYPE_JMP;
				op->jump = INSOP(0).imm;
			} else {
				op->type = R_ANAL_OP_TYPE_UJMP;
				op->jump = UT64_MAX;
			}
			if (a->decode) {
				ut64 dst = INSOP(0).imm;
				esilprintf (op, "0x%"PFMT64x",%s,=", dst, pc);
			}
			break;
		case X86_INS_IN:
		case X86_INS_INSW:
		case X86_INS_INSD:
		case X86_INS_INSB:
		case X86_INS_OUT:
		case X86_INS_OUTSB:
		case X86_INS_OUTSD:
		case X86_INS_OUTSW:
			op->type = R_ANAL_OP_TYPE_IO;
			break;
		case X86_INS_VXORPD:
		case X86_INS_VXORPS:
		case X86_INS_VPXORD:
		case X86_INS_VPXORQ:
		case X86_INS_VPXOR:
		case X86_INS_KXORW:
		case X86_INS_PXOR:
		case X86_INS_XOR:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case X86_INS_OR:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case X86_INS_SUB:
		case X86_INS_DEC:
		case X86_INS_PSUBB:
		case X86_INS_PSUBW:
		case X86_INS_PSUBD:
		case X86_INS_PSUBQ:
		case X86_INS_PSUBSB:
		case X86_INS_PSUBSW:
		case X86_INS_PSUBUSB:
		case X86_INS_PSUBUSW:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case X86_INS_AND:
		case X86_INS_ANDN:
		case X86_INS_ANDPD:
		case X86_INS_ANDPS:
		case X86_INS_ANDNPD:
		case X86_INS_ANDNPS:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case X86_INS_DIV:
			op->type = R_ANAL_OP_TYPE_DIV;
			break;
		case X86_INS_MUL:
			op->type = R_ANAL_OP_TYPE_MUL;
			break;
		case X86_INS_INC:
		case X86_INS_ADD:
		case X86_INS_FADD:
		case X86_INS_ADDPD:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
	}

	cs_free (insn, 1);
	cs_close (&handle);

	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	return R_TRUE;
}


RAnalPlugin r_anal_plugin_x86_cs = {
	.name = "x86.cs",
	.desc = "Capstone X86 analysis",
	.license = "BSD",
	.arch = R_SYS_ARCH_X86,
	.bits = 16|32|64,
	.op = &analop,
	/*.set_reg_profile = &set_reg_profile,*/
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_cs
};
#endif
