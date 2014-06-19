/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>
#include <mips.h>

#define INSOP(n) insn->detail->mips.operands[n]

static RAnalValue *convert_cs_to_r(RAnal *anal, csh handle, cs_mips_op *in) {
	RAnalValue *out = r_anal_value_new ();
	switch (in->type) {
		case MIPS_OP_IMM:
			out->type = R_ANAL_VALUE_TYPE_IMM;
			out->imm = in->imm;
			break;
		case MIPS_OP_REG:
			out->type = R_ANAL_VALUE_TYPE_REG;
			out->reg = //NULL; 
				(in->reg == MIPS_REG_INVALID) ? NULL : 
				r_reg_get (anal->reg, cs_reg_name(handle, in->reg), R_REG_TYPE_GPR);
			break;
		case MIPS_OP_MEM:
			out->type = R_ANAL_VALUE_TYPE_MEM;
			out->reg =  
				(in->mem.base == MIPS_REG_INVALID) ? NULL : 
				r_reg_get (anal->reg, cs_reg_name(handle, in->mem.base), R_REG_TYPE_GPR);
			out->index = NULL;
			out->disp = in->mem.disp;
			out->size = 4;
			break;
		default:
			break;
	}

	return out;
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	int n, ret, i, opsize = -1;
	csh handle;
	cs_insn* insn;
	int mode = a->big_endian? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;

	mode |= (a->bits==64)? CS_MODE_64: CS_MODE_32;
// XXX no arch->cpu ?!?! CS_MODE_MICRO, N64
	ret = cs_open (CS_ARCH_MIPS, mode, &handle);
	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_ILL;
	op->size = 4;
	if (ret != CS_ERR_OK) goto fin;
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	n = cs_disasm_ex (handle, (ut8*)buf, len, addr, 1, &insn);
	if (n<1 || insn->size<1)
		goto beach;

	if (insn->detail->mips.op_count) {
		op->dst = convert_cs_to_r (a, handle, &INSOP(0));
		for (i = 1; i < insn->detail->mips.op_count; i++)
			op->src[i-1] = convert_cs_to_r (a, handle, &INSOP(i));
	}

	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_NULL;
	op->delay = 0;
	op->size = insn->size;

	opsize = op->size = insn->size;
	switch (insn->id) {
	    case MIPS_INS_INVALID:
		    op->type = R_ANAL_OP_TYPE_ILL;
		    break;
	    case MIPS_INS_LB:
	    case MIPS_INS_LBU:
	    case MIPS_INS_LBUX:
	    case MIPS_INS_LW:
	    case MIPS_INS_LWC1:
	    case MIPS_INS_LWC2:
	    case MIPS_INS_LWL:
	    case MIPS_INS_LWR:
	    case MIPS_INS_LWXC1:
	    case MIPS_INS_LD:
	    case MIPS_INS_LDC1:
	    case MIPS_INS_LDC2:
	    case MIPS_INS_LDL:
	    case MIPS_INS_LDR:
	    case MIPS_INS_LDXC1:
		    op->type = R_ANAL_OP_TYPE_LOAD;
		    break;
	    case MIPS_INS_SW:
	    case MIPS_INS_SWC1:
	    case MIPS_INS_SWC2:
	    case MIPS_INS_SWL:
	    case MIPS_INS_SWR:
	    case MIPS_INS_SWXC1:
		    op->type = R_ANAL_OP_TYPE_STORE;
		    break;
	    case MIPS_INS_NOP:
		    op->type = R_ANAL_OP_TYPE_NOP;
		    break;
	    case MIPS_INS_SYSCALL:
	    case MIPS_INS_BREAK:
		    op->type = R_ANAL_OP_TYPE_TRAP;
		    break;
	    case MIPS_INS_JALR:
		    op->type = R_ANAL_OP_TYPE_UCALL;
		    op->delay = 1;
		    op->jump = UT64_MAX;
		    op->fail = addr+opsize;
		    break;
	    case MIPS_INS_JAL:
	    case MIPS_INS_JALRC:
		    op->type = R_ANAL_OP_TYPE_CALL;
		    op->delay = 1;
		    break;
	    case MIPS_INS_MOVE:
		    op->type = R_ANAL_OP_TYPE_MOV;
		    break;
	    case MIPS_INS_ADD:
	    case MIPS_INS_ADDI:
	    case MIPS_INS_ADDIU:
	    case MIPS_INS_DADD:
	    case MIPS_INS_DADDI:
	    case MIPS_INS_DADDIU:
		    op->type = R_ANAL_OP_TYPE_ADD;
		    break;
	    case MIPS_INS_SUB:
	    case MIPS_INS_SUBV:
	    case MIPS_INS_DSUBU:
	    case MIPS_INS_FSUB:
		    op->type = R_ANAL_OP_TYPE_SUB;
		    break;
	    case MIPS_INS_MULV:
	    case MIPS_INS_MULT:
	    case MIPS_INS_MULSA:
	    case MIPS_INS_FMUL:
	    case MIPS_INS_MUL:
	    case MIPS_INS_DMULT:
	    case MIPS_INS_DMULTU:
		    op->type = R_ANAL_OP_TYPE_MUL;
		    break;
	    case MIPS_INS_XOR:
	    case MIPS_INS_XORI:
		    op->type = R_ANAL_OP_TYPE_XOR;
		    break;
	    case MIPS_INS_AND:
	    case MIPS_INS_ANDI:
		    op->type = R_ANAL_OP_TYPE_AND;
		    break;
	    case MIPS_INS_NOT:
		    op->type = R_ANAL_OP_TYPE_NOT;
		    break;
	    case MIPS_INS_OR:
	    case MIPS_INS_ORI:
		    op->type = R_ANAL_OP_TYPE_OR;
		    break;
	    case MIPS_INS_DIV:
	    case MIPS_INS_DIVU:
	    case MIPS_INS_DDIV:
	    case MIPS_INS_DDIVU:
	    case MIPS_INS_FDIV:
	    case MIPS_INS_DIV_S:
	    case MIPS_INS_DIV_U:
		    op->type = R_ANAL_OP_TYPE_DIV;
		    break;
	    case MIPS_INS_CMPGDU:
	    case MIPS_INS_CMPGU:
	    case MIPS_INS_CMPU:
	    case MIPS_INS_CMPI:
		    op->type = R_ANAL_OP_TYPE_CMP;
		    break;

	    case MIPS_INS_B:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + (INSOP(0).imm << 0);
		op->fail = addr+opsize;
		op->delay = 1;
		break;
	    case MIPS_INS_J:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = (addr&0xf0000000) | (INSOP(0).imm << 0);
		op->fail = addr+opsize;
		op->delay = R_TRUE;
		break;

	    case MIPS_INS_BEQ:
	    case MIPS_INS_BGEZ:
	    case MIPS_INS_BGEZAL:
	    case MIPS_INS_BGTZ:
	    case MIPS_INS_BLEZ:
	    case MIPS_INS_BLTZ:
	    case MIPS_INS_BLTZAL:
	    case MIPS_INS_BMNZI:
	    case MIPS_INS_BMNZ:
	    case MIPS_INS_BMZI:
	    case MIPS_INS_BMZ:
	    case MIPS_INS_BNE:
	    case MIPS_INS_BNEGI:
	    case MIPS_INS_BNEG:
	    case MIPS_INS_BNZ:
	    case MIPS_INS_BTEQZ:
	    case MIPS_INS_BTNEZ:
	    case MIPS_INS_BNEZ:
		    op->type = R_ANAL_OP_TYPE_CJMP;
		    op->jump = addr + (INSOP(1).imm << 0);
		    op->fail = addr+opsize;
		    op->delay = 1;
		    break;
	    case MIPS_INS_JR:
	    case MIPS_INS_JRC:
		    op->type = R_ANAL_OP_TYPE_JMP;
		    op->delay = 1;
		    op->jump = UT64_MAX;
		    op->fail = addr+opsize;
		    // register 31 is $ra, so jmp is a return
		    if (INSOP(0).reg == MIPS_REG_31)
			op->type = R_ANAL_OP_TYPE_RET;
		    break;
	}
	beach:
	cs_free (insn, n);
	cs_close (&handle);
	fin:
	return opsize;
}

RAnalPlugin r_anal_plugin_mips_cs = {
	.name = "mips.cs",
	.desc = "Capstone MIPS analyzer",
	.license = "BSD",
	.arch = R_SYS_ARCH_MIPS,
	.bits = 16|32|64,
	.op = &analop,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_mips_cs
};
#endif
