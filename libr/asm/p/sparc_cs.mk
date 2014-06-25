OBJ_SPARCCS=asm_sparc_cs.o

include p/capstone.mk

STATIC_OBJ+=${OBJ_SPARCCS}
SHARED_OBJ+=${SHARED_SPARCCS}
TARGET_SPARCCS=asm_sparc_cs.${EXT_SO}

ALL_TARGETS+=${TARGET_SPARCCS}

${TARGET_SPARCCS}: ${OBJ_SPARCCS}
	${CC} $(call libname,asm_sparc) ${LDFLAGS} ${CFLAGS} $(CS_LDFLAGS)\
		-o ${TARGET_SPARCCS} ${OBJ_SPARCCS} ${SHARED2_SPARCCS}
