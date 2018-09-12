# Global definitions

define lunatik_files
	lib/lunatik/lua/lapi.o lib/lunatik/lua/lcode.o lib/lunatik/lua/lctype.o 
	lib/lunatik/lua/ldebug.o lib/lunatik/lua/ldo.o lib/lunatik/lua/ldump.o 
	lib/lunatik/lua/lfunc.o lib/lunatik/lua/lgc.o lib/lunatik/lua/llex.o 
	lib/lunatik/lua/lmem.o lib/lunatik/lua/lobject.o lib/lunatik/lua/lopcodes.o 
	lib/lunatik/lua/lparser.o lib/lunatik/lua/lstate.o lib/lunatik/lua/lstring.o 
	lib/lunatik/lua/ltable.o lib/lunatik/lua/ltm.o lib/lunatik/lua/lundump.o 
	lib/lunatik/lua/lvm.o lib/lunatik/lua/lzio.o lib/lunatik/lua/lauxlib.o 
	lib/lunatik/lua/lbaselib.o lib/lunatik/lua/lbitlib.o lib/lunatik/lua/lcorolib.o 
	lib/lunatik/lua/ldblib.o lib/lunatik/lua/lstrlib.o lib/lunatik/lua/ltablib.o 
	lib/lunatik/lua/lutf8lib.o lib/lunatik/lua/loslib.o lib/lunatik/lua/lmathlib.o 
	lib/lunatik/lua/linit.o 
	lib/lunatik/util/modti3.o lib/lunatik/arch/$(ARCH)/setjmp.o
endef

define nflua_files
	src/nf_util.o src/xt_lua.o
endef

define luadata_files
	lib/luadata/binary.o lib/luadata/data.o lib/luadata/handle.o 
	lib/luadata/layout.o lib/luadata/luautil.o lib/luadata/luadata.o
endef

define luajson_files
	lib/luajson/luajson.o
endef

define luabase64_files
	lib/luabase64/lbase64.o
endef

define lunatik_driver_files
	lib/lunatik-tests/kernel/linux/driver/lua.o
endef

# Compiler and assembly flags

ccflags-y += -D_KERNEL -I$(src)/lib/lunatik/lua -I$(src)/ -I$(src)/lib/luadata/ \
	-D'CHAR_BIT=(8)' -D'MIN=min' -D'MAX=max' -D'UCHAR_MAX=(255)' -D'UINT64_MAX=((u64)~0ULL)' \
	-Dstrtoll=simple_strtoll \
	$(shell (echo ${KBUILD_SRC} | grep -q arrisxb6) && echo -DCUJO_COMCAST_AXB6)

CFLAGS_lua.o := -I$(src)/lib/lunatik

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

# Module definitions

ifdef CONFIG_NFLUA
	obj-m += nflua.o
	nflua-objs += $(strip $(lunatik_files)) $(strip $(luadata_files)) $(strip $(luajson_files)) \
		$(strip $(luabase64_files)) $(strip $(nflua_files))
endif

ifdef CONFIG_LUNATIK_DEBUG
	obj-m += lunatik_debug.o
	lunatik_debug-objs += $(strip $(lunatik_files)) $(strip $(lunatik_driver_files))
endif

ifdef CONFIG_LUADATA_DEBUG
	obj-m += luadata_debug.o
	luadata_debug-objs += $(strip $(lunatik_files)) $(strip $(lunatik_driver_files)) $(strip $(luadata_files))
	CFLAGS_lua.o += -DDEBUG_LUADATA
endif

ifdef CONFIG_LUAJSON_DEBUG
	obj-m += luajson_debug.o
	luajson_debug-objs += $(strip $(lunatik_files)) $(strip $(lunatik_driver_files)) $(strip $(luajson_files))
	CFLAGS_lua.o += -DDEBUG_LUAJSON
endif

ifdef CONFIG_LUABASE64_DEBUG
	obj-m += luabase64_debug.o
	luabase64_debug-objs += $(strip $(lunatik_files)) $(strip $(lunatik_driver_files)) $(strip $(luabase64_files))
	CFLAGS_lua.o += -DDEBUG_LUABASE64
endif
