NFLua
=====

In order to build NFLua and its depedencies, follow the instruction in
section 2 of [Building External Modules](https://www.kernel.org/doc/Documentation/kbuild/modules.txt).

You must declare the following parameters in your make invocation.

```
CONFIG_LUNATIK=m
CONFIG_LUADATA=m
CONFIG_LUAJSON=m
CONFIG_LUABASE64=m
CONFIG_NFLUA=m
```

An example of the invocation:

```
make -C /usr/src/linux-headers-`uname -r` M=$PWD \
CONFIG_LUNATIK=m \
CONFIG_LUADATA=m \
CONFIG_LUAJSON=m \
CONFIG_LUABASE64=m \
CONFIG_NFLUA=m \
modules
```

An example of loading NFLua and its dependencies:

```
sudo insmod ./deps/lunatik/lunatik.ko
sudo insmod ./deps/luabase64/luabase64.ko
sudo insmod ./deps/luadata/luadata.ko
sudo insmod ./deps/luajson/luajson.ko
sudo insmod ./src/nflua.ko
```
