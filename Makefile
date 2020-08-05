# This file is Confidential Information of CUJO LLC.
# Copyright (c) 2020 CUJO LLC. All rights reserved.

BUILD_NF ?= 1
BUILD_XT ?= 1
BUILD_TESTS ?= 1

ifndef BUILD_DIR
$(error BUILD_DIR is undefined, but required!)
endif
ifndef STAGING_ROOT
$(error STAGING_ROOT is undefined, but required!)
endif
ifndef INSTALL_ROOT
$(error INSTALL_ROOT is undefined, but required!)
endif
ifndef CUJO_PREFIX
$(error CUJO_PREFIX is undefined, but required!)
endif
ifeq ($(BUILD_NF),1)
ifndef KERNEL_HEADERS_DIR
$(error KERNEL_HEADERS_DIR is undefined, but required!)
endif
ifndef KERNEL_ARCH
$(error KERNEL_ARCH is undefined, but required! (Try $$(uname -m) for a host build.))
endif
endif

.PHONY: modules iptables modules-install iptables-install tests-install

STAGING_CUJO := $(STAGING_ROOT)$(CUJO_PREFIX)
INSTALL_CUJO := $(INSTALL_ROOT)$(CUJO_PREFIX)

NETLINK_NFLUA ?= 16

KERNEL_BINUTILS_PREFIX ?=
KERNEL_BUILD_DIR ?= $(KERNEL_HEADERS_DIR)
TARGET_XTABLES_LIBDIR ?= /usr/lib/iptables

MODULE_MAKE_OPTS := \
	-C "$(KERNEL_BUILD_DIR)" \
	M="$(BUILD_DIR)" \
	CROSS_COMPILE="$(KERNEL_BINUTILS_PREFIX)" \
	ARCH=$(KERNEL_ARCH) \
	NETLINK_NFLUA=$(NETLINK_NFLUA) \
	CONFIG_NFLUA=m \
	CONFIG_LUNATIK=m \
	CONFIG_LUABASE64=m \
	CONFIG_LUADATA=m \
	CONFIG_LUAJSON=m \
	CONFIG_LUNATIK_DEBUG=m \
	$(NFLUA_MAKE_OPTS)

ALL ?= modules iptables
INSTALL_ALL ?= modules-install iptables-install

ifeq ($(BUILD_NF),1)
ALL = modules
INSTALL_ALL = modules-install
endif
ifeq ($(BUILD_XT),1)
ALL = iptables
INSTALL_ALL = iptables-install
endif
ifeq ($(BUILD_TESTS),1)
INSTALL_ALL += tests-install
endif

all: $(ALL)

modules: | $(BUILD_DIR)
	$(MAKE) $(MODULE_MAKE_OPTS)

iptables: $(BUILD_DIR)/iptables/libxt_lua.so

$(BUILD_DIR)/iptables/libxt_lua.so: | $(BUILD_DIR)
	$(CC) \
		$(CFLAGS) \
		-I "$(BUILD_DIR)"/src \
		-DNETLINK_NFLUA=$(NETLINK_NFLUA) \
		"$(BUILD_DIR)"/iptables/libxt_lua.c \
		-fPIC -shared -o "$@"

stage: $(STAGING_CUJO)/include/nflua

$(STAGING_CUJO)/include/nflua: | $(BUILD_DIR)
	install -d "$(STAGING_CUJO)"/include/nflua
	install -m0644 -t "$(STAGING_CUJO)"/include/nflua \
		"$(BUILD_DIR)"/lib/lunatik/lua/lauxlib.h \
		"$(BUILD_DIR)"/lib/lunatik/lua/lua.h \
		"$(BUILD_DIR)"/lib/lunatik/lua/luaconf.h \
		"$(BUILD_DIR)"/src/luaconntrack.h

install: $(INSTALL_ALL)

# 'modules_install' preserves the source directory structure, which we don't
# want, so use it to install in a temporary directory and install the files
# from there manually.
# Using modules_install as a first step is preferable, because it handles e.g.
# compressing the modules appropriately based on the CONFIG_MODULE_COMPRESS
# settings.
define modules-install-cmds
	$(MAKE) $(MODULE_MAKE_OPTS) modules_install \
		INSTALL_MOD_PATH="$(BUILD_DIR)/modules.tmp"
	kernel_version=$$(basename $$(ls "$(BUILD_DIR)"/modules.tmp/lib/modules/)) && \
		install -d "$(INSTALL_ROOT)/lib/modules/$$kernel_version/" && \
		find "$(BUILD_DIR)/modules.tmp/lib/modules/$$kernel_version" -type f \
			$(1) \
			-exec install -pm0644 -t "$(INSTALL_ROOT)/lib/modules/$$kernel_version/" {} +
endef

modules-install: modules stage
ifeq ($(BUILD_TESTS),1)
	$(modules-install-cmds)
else
	$(call modules-install-cmds,\! -name 'lunatiktest*.ko')
endif

iptables-install: iptables
	install -Dpm0755 \
		"$(BUILD_DIR)"/iptables/libxt_lua.so \
		"$(INSTALL_CUJO)"/lib/iptables/libxt_lua.so
	if [ -n "$(TARGET_XTABLES_LIBDIR)" ]; then \
		install -d "$(INSTALL_ROOT)/$(TARGET_XTABLES_LIBDIR)" || exit 1; \
		ln -sf \
			"$(CUJO_PREFIX)"/lib/iptables/libxt_lua.so \
			"$(INSTALL_ROOT)/$(TARGET_XTABLES_LIBDIR)"/libxt_lua.so || exit 1; \
	fi

tests-install: | $(BUILD_DIR)
	install -d "$(INSTALL_CUJO)"/share/nflua-tests/lunatik
	install -m0644 \
		"$(BUILD_DIR)"/lib/lunatik-tests/*.lua \
		"$(BUILD_DIR)"/lib/lunatik-tests/kernel/linux/*.lua \
		"$(INSTALL_CUJO)"/share/nflua-tests/lunatik/
	install -m0755 \
		"$(BUILD_DIR)"/lib/lunatik-tests/kernel/linux/runall.sh \
		"$(INSTALL_CUJO)"/share/nflua-tests/lunatik/
	install -d "$(INSTALL_CUJO)"/share/nflua-tests/luabase64
	install -m0644 \
		"$(BUILD_DIR)"/lib/luabase64/test.lua \
		"$(INSTALL_CUJO)"/share/nflua-tests/luabase64/
	install -d "$(INSTALL_CUJO)"/share/nflua-tests/luadata
	install -m0644 \
		"$(BUILD_DIR)"/lib/luadata/test.lua \
		"$(INSTALL_CUJO)"/share/nflua-tests/luadata/
	install -d "$(INSTALL_CUJO)"/share/nflua-tests/luajson
	install -m0644 \
		"$(BUILD_DIR)"/lib/luajson/test.lua \
		"$(INSTALL_CUJO)"/share/nflua-tests/luajson/

clean:
	rm -rf \
		"$(BUILD_DIR)" \
		"$(STAGING_CUJO)"/include/nflua/ \
		"$(INSTALL_CUJO)"/lib/iptables/ \
		"$(INSTALL_CUJO)"/share/nflua-tests/ \
		"$(INSTALL_ROOT)/$(TARGET_XTABLES_LIBDIR)"/libxt_lua.so \
		"$(INSTALL_ROOT)"/lib/modules/*/luabase64.ko
		"$(INSTALL_ROOT)"/lib/modules/*/luaconntrack.ko
		"$(INSTALL_ROOT)"/lib/modules/*/luadata.ko
		"$(INSTALL_ROOT)"/lib/modules/*/luajson.ko
		"$(INSTALL_ROOT)"/lib/modules/*/lunatik.ko
		"$(INSTALL_ROOT)"/lib/modules/*/lunatiktest.ko
		"$(INSTALL_ROOT)"/lib/modules/*/nflua.ko
