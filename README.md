_Copyright (C) 2018-2019  CUJO LLC_

_This program is free software; you can redistribute it and/or modify_
_it under the terms of the GNU General Public License as published by_
_the Free Software Foundation; either version 2 of the License, or_
_(at your option) any later version._

_This program is distributed in the hope that it will be useful,_
_but WITHOUT ANY WARRANTY; without even the implied warranty of_
_MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the_
_GNU General Public License for more details._

_You should have received a copy of the GNU General Public License along_
_with this program; if not, write to the Free Software Foundation, Inc.,_
_51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA._
- - -

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

Running tests:

```
sudo LD_LIBRARY_PATH=./lib:./deps/luadata LUA_CPATH="./lua/?.so;;" lua tests/all.lua
```
