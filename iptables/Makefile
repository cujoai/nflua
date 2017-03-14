#Copyright (c) 2016 CUJO LLC. All rights reserved.

include		../Makefile.inc

# library parameters
LIB=		${OBJDIR}/libxt_lua.so
MAJOR=		1
MINOR=		0
PATCH=		0

LIBOBJ=		${LIB}.${MAJOR}.${MINOR}.${PATCH}
all:		${LIB}

CFLAGS=		-L../../../../debian/mips-unknown-linux-gnu/fakeroot/lib \
		-lxtables -I${CONTRIB}/xtables \
		-I../../../../kernel/octeon-linux/net/netfilter \
		${MUSL_CPPFLAGS}

SRCS=		libxt_lua.c
OBJS=		${SRCS:%.c=${OBJDIR}/%.o}
DEPS=		${SRCS:%.c=${OBJDIR}/%.d}

${OBJDIR}/%.o: %.c | ${OBJDIR}
	$(eval REALPATH := $(realpath $<))
	${MUSL_CC} -o $@ -MD ${CFLAGS} -c ${REALPATH}

${LIB}: ${LIBOBJ}
	ln -sf $(notdir $<) $@

${LIBOBJ}: ${OBJS}
	${MUSL_CC} -fPIC -DPIC -o $@ ${OBJS} ${SHARED}
	${STRIP} $@

clean:
	rm -rf ${OBJDIR}

.PHONY: clean

-include ${DEPS}
