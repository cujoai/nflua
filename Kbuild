# Our module, nflua
obj-m += nflua.o

# Main code for nflua
nflua-objs += src/nf_util.o src/xt_lua.o

# Lunatik object files
nflua-objs += lib/lunatik/lua/lapi.o lib/lunatik/lua/lcode.o lib/lunatik/lua/lctype.o \
	lib/lunatik/lua/ldebug.o lib/lunatik/lua/ldo.o lib/lunatik/lua/ldump.o \
	lib/lunatik/lua/lfunc.o lib/lunatik/lua/lgc.o lib/lunatik/lua/llex.o \
	lib/lunatik/lua/lmem.o lib/lunatik/lua/lobject.o lib/lunatik/lua/lopcodes.o \
	lib/lunatik/lua/lparser.o lib/lunatik/lua/lstate.o lib/lunatik/lua/lstring.o \
	lib/lunatik/lua/ltable.o lib/lunatik/lua/ltm.o lib/lunatik/lua/lundump.o \
	lib/lunatik/lua/lvm.o lib/lunatik/lua/lzio.o lib/lunatik/lua/lauxlib.o \
	lib/lunatik/lua/lbaselib.o lib/lunatik/lua/lbitlib.o lib/lunatik/lua/lcorolib.o \
	lib/lunatik/lua/ldblib.o lib/lunatik/lua/lstrlib.o lib/lunatik/lua/ltablib.o \
	lib/lunatik/lua/lutf8lib.o lib/lunatik/lua/loslib.o lib/lunatik/lua/lmathlib.o \
	lib/lunatik/lua/linit.o

nflua-objs += lib/lunatik/util/modti3.o
nflua-objs += lib/lunatik/arch/$(ARCH)/setjmp.o

# Luadata object files
nflua-objs += lib/luadata/binary.o lib/luadata/data.o lib/luadata/handle.o \
	lib/luadata/layout.o lib/luadata/luautil.o lib/luadata/luadata.o

# Luajson object files
nflua-objs += lib/luajson/luajson.o

# Luabase64 object files
nflua-objs += lib/luabase64/lbase64.o

# Compiler and assembly flags
ccflags-y := -D_KERNEL -I$(src)/lib/lunatik/lua -I$(src)/ -I$(src)/lib/luadata/ \
	-D'CHAR_BIT=(8)' -D'MIN=min' -D'MAX=max' -D'UCHAR_MAX=(255)' -D'UINT64_MAX=((u64)~0ULL)' \
	-Dstrtoll=simple_strtoll \
	$(shell (echo ${KBUILD_SRC} | grep -q arrisxb6) && echo -DCUJO_COMCAST_AXB6)

ifeq ($(ARCH), arm)
	AFLAGS_setjmp.o := -D_CUJO
endif

ifeq ($(ARCH), $(filter $(ARCH),i386 x86))
	AFLAGS_setjmp.o := -D_REGPARM
endif

ifeq ($(ARCH), mips)
	AFLAGS_setjmp.o = -D_CUJO -D__mips_n64 -D_MIPS_ISA_MIPS64 \
		-D_MIPS_ISA=_MIPS_ISA_MIPS64 
endif
