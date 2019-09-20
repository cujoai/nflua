subdir-ccflags-y += \
	-D_MODULE -D_KERNEL \
	-I$(src)/lib/lunatik \
	-I$(src)/lib/lunatik/lua \
	-I$(src)/ \
	-I$(src)/lib/luadata

obj-y := src/

# Add all libraries from lib/.
#
# Our working directory is not typically here, so use $(src) to point to the
# lib directory here. But $(src) has an absolute path, so use patsubst to
# relativize the results of the wildcard invocation.
obj-y += $(patsubst $(src)/%,%,$(wildcard $(src)/lib/*/))
