subdir-ccflags-y += -D_MODULE -D_KERNEL -I $(src)/lib/lunatik -I$(src)/lib/lunatik/lua -I$(src)/ \
	-I$(src)/lib/luadata/ \
	$(shell (echo ${KBUILD_SRC} | grep -q arrisxb6) && echo -DARRISXB6)

obj-y := src/ lib/luadata/ lib/luajson/ lib/luabase64/ lib/lunatik-tests/ lib/lunatik/
