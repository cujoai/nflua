_Copyright (C) 2017-2020  CUJO LLC_

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

Index
-----

- [`nf.connid`](#id--nfconnid)
- [`nf.traffic`](#packets-bytes--packets-bytes--nftrafficfamily-protocol-srcaddr-srcport-dstaddr-dstport-dir)
- [`nf.getpacket`](#packet--nfgetpacket)
- [`nf.hotdrop`](#nfhotdropdrop)
- [`nf.netlink`](#size--nfnetlinkport-groups-payload)
- [`nf.reply`](#nfreplytype-message)
- [`nf.time`](#seconds-millis--nftime)
- [`nf.get_mem_info`](#getmeminfo)
- [`packet:close`](#packetclose)
- [`packet:send`](#packetsendpayload)
- [`Code walktrough`](#walkthrough)

Contents
--------

### `id = nf.connid()`

Returns an integer that represents the ID of the current connection as maintained by `conntrack` module of Netfilter.
This `id` might be reused by other future connections, but such reuse indicates that all previous connections identified by the same value are not tracked anymore.

### `packets, bytes [, packets, bytes] = nf.traffic(family, protocol, srcaddr, srcport, dstaddr, dstport, dir)`

Returns the numbers of packets and the number of bytes of a given connection.

`family` is either 4 or 6.
`protocol` is either `'tcp'` or `'udp'`.
`srcaddr` and `dstaddr` are the dotted-notation strings representing the IP addresses.
`srcport` and `dstport` are integers representing the transport layer ports.
The parameter `dir` should be either `"original"`, `"reply"` or `"both"`.
In case of `"both"` returns 4 values corresponding to the counters of the directions `"original"` and `"reply"` respectively.

Contrary to connections passing through the INPUT and OUTPUT chains, the ones passing through FORWARD chain will have distinct pairs of source and destination address.

The following example illustrates a scenario where a connection passing through FORWARD with distinct address information for each direction.

```
+--------------------------------------------------------------------+
|                              router                                |
|                                                                    |
| +-------------------+        bridge          +-------------------+ |
| |       eth1        |------------------------|       eth0        | |
| |  192.168.1.1/24   |                        |     10.0.0.38     | |
| +-------------------+                        +-------------------+ |
+--------------------------------------------------------------------+
            |                                            |            
            |                                            |            
            |                                            |            
            |                                            |            
            |                                            |            
            |                                            |            
  +-------------------+                         +-------------------+
  |      device       |                         |     internet      |
  | 192.168.1.100/24  |                         |     8.8.8.8       |
  +-------------------+                         +-------------------+

```

In such case, the output of the command `conntrack -L` should be:

```
# conntrack -L
ipv4     2 udp      17 0 src=192.168.1.100 dst=8.8.8.8 sport=8080 dport=22 packets=1 bytes=76 src=8.8.8.8 dst=10.0.0.38 sport=22 dport=8080 packets=1 bytes=76 mark=0 use=2
```

Moreover, the code below illustrates the result of `traffic` in such case.

```lua
local p1, b1 = nf.traffic(4, "udp", "192.168.1.100", 8080, "8.8.8.8", 22, 'original')
local p2, b2 = nf.traffic(4, "udp", "10.0.0.38", 8080, "8.8.8.8", 22, 'original')
local p3, b3 = nf.traffic(4, "udp", "8.8.8.8", 22, "10.0.0.38", 8080, 'reply')
local p4, b4 = nf.traffic(4, "udp", "8.8.8.8", 22, "192.168.1.100", 8080, 'reply')

assert(p1 == p3)
assert(b1 == b3)
assert(p2 == nil)
assert(p4 == nil)
```

### `packet = nf.getpacket()`

Returns a copy of the current packet being filtered by Netlink framework.
This function can only be called from a NFLua evaluation callback function.

### `nf.hotdrop(drop)`

Sets whether the packet will be hot-dropped or not, based on the boolean `drop`.

### `size = nf.netlink(port, groups, payload)`

Sends a Netlink datagram using protocol defined by kernel symbol `NETLINK_NFLUA`.
The datagram is sent to port with ID given by number `port` and to multicast groups given by the bits on number `groups`.
The datagram contains the string `payload` as payload.

### `nf.reply(type, message)`

Sends a TCP reply with the string `message` as payload.
`type` must be string that starts with character `t`.

### `seconds, millis = nf.time()`

Returns the number of seconds since UNIX epoch time (01/01/1970), followed by the number of milliseconds since this second.

### `nf.get_mem_info()`

Get lunatik memory statistics

### `packet:close()`

Discards all resources of copied packet `packet`.
After this call no further operations can be performed on packet `packet`.

### `packet:send([payload])`

Send the copied packet `packet` through the network and then closes it, thus it cannot be sent again.
If `payload` is provided, the original packet payload is replaced by the contents of string `payload`.
This function only works when you acquire the packet during a match in FORWARD chain.


## `Code walktrough`

### Packet flow in nflua using iptables match:
Example syntax: iptables -I INPUT -p tcp -m tcp -m lua --function nf_test  
Userspace support for iptables lua match is in iptables/libxt_lua.c

```
Register handler: xt_register_match(&nflua_mt_reg)
 nflua_match() - Packet enters nflua
 nflua_call()
 nflua_docall()
  - Two arguments given to lua-function 'nf_test'. Frame is ethernet header
    with mac-addresses. packet is the full ip-packet.
 nflua_call() - boolean true/false returned from lua function
 nflua_match()
  - return false or true. true will match to target given with -j option
```

### Packet flow in nflua using iptables target:
Example syntax: iptables -I INPUT -p tcp -m tcp -j LUA --function nf_test  
Userspace support for iptables LUA target is in iptables/libxt_LUA.c

```
Register handler: xt_register_target(&nflua_tg_reg)
 nflua_target() - Packet enters nflua
 nflua_call()
 nflua_docall()
  - Two arguments given to lua-function 'nf_test'. Frame is ethernet header
    with mac-addresses. packet is the full ip-packet.
 nflua_call() - string value returned from lua function
 nflua_target()
  - return string 'accept' which is mapped to netfilter verdict in string_to_tg()
```

### Netlink flow userspace -> kernel:
```
 Operations are registered in genl_nflua_ops.
 genl_nflua_rx_msg(), receives messages to 'NFLUA' family name.
  Lua code sent from userspace is executed in lunatik context.
```

### Netlink flow kernel -> userspace:
```
 Lunatik Lua scripts call nf.genetlink(...)
 nflua_genetlink()
  writes to generic netlink socket
```