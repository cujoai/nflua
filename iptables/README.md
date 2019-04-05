_Copyright (C) 2019  CUJO LLC_

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

NFLua - libxt_lua
=================

### Introduction 

This a userspace plugin for the `iptables` command line tool. The purpose is to
provide a way to add rules that use the `nflua` kernel extension.

### Building

```
$ make
```

### Installing

Copy the library file `libxt_lua.so` to the `XTABLES_LIBDIR` on your system.
Usually it's located at `/usr/libexec/xtables` but it might be
different depending on the system.

Example on Ubuntu 18.04:

```
$ cp libxt_lua.so /usr/lib/x86_64-linux-gnu/xtables/
```

### Using

When using iptables Lua match, you must specify the Lua state and the Lua
function iptables should call. Remember that the state must already be created.
You can use `nfluactl` for that.

For help:

```
$ iptables -m lua --help
...
Netfilter Lua
[!] --state	match state
[!] --function	match function
```

Example:

```
iptables -A INPUT -p tcp -s 192.168.1.100 -m lua --state st1 --function myfunc -j ACCEPT
```

### References

[Xtables-Addons](http://xtables-addons.sourceforge.net/)
[Writing Netfilter Modules](http://inai.de/documents/Netfilter_Modules.pdf)
