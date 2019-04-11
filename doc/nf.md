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

Index
-----

- [`nf.connid`](#id--nfconnid)
- [`nf.findconnid`](##id--nffindconnidfamily-protocol-srcaddr-srcport-dstaddr-dstport)
- [`nf.getpacket`](#packet--nfgetpacket)
- [`nf.hotdrop`](#nfhotdropdrop)
- [`nf.netlink`](#size--nfnetlinkport-groups-payload)
- [`nf.reply`](#nfreplytype-message)
- [`nf.time`](#seconds-millis--nftime)
- [`packet:close`](#packetclose)
- [`packet:send`](#packetsendpayload)

Contents
--------

### `id = nf.connid()`

Returns a userdata that represents the ID of the current connection as maintained by `conntrack` module of Netfilter.
This `id` might be reused by other future connections, but such reuse indicates that all previous connections identified by the same value are not tracked anymore.

### `id = nf.findconnid(family, protocol, srcaddr, srcport, dstaddr, dstport)`

Returns a userdata that represents the ID of the connection specified, similar to [`nf.connid`](#id--nfconnid). Raises an error in case of invalid parameters.
Returns nil and an error message if it can't find the connection ID.

`family` is either 4 or 6.
`protocol` is either `'tcp'` or `'udp'`.
`srcaddr` and `dstaddr` are the dotted-notation strings representing the IP addresses.
`srcport` and `dstport` are integers representing the transport layer ports.

Contrary to connections passing through the INPUT and OUTPUT chains, the ones passing through FORWARD chain will have distinct pairs of source and destination address.

The following example illustrates a scenario where a connection passing through FORWARD with distinct address information for each direction.

```
+--------------------------------------------------------------------+
|                              router                                |
|                                                                    |
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

Moreover, the code below illustrates the result of `findconnid` in such case.

```lua
local id1 = nf.findconnid(4, "udp", "192.168.1.100", 8080, "8.8.8.8", 22)
local id2 = nf.findconnid(4, "udp", "10.0.0.38", 8080, "8.8.8.8", 22)
local id3 = nf.findconnid(4, "udp", "8.8.8.8", 22, "10.0.0.38", 8080)
local id4 = nf.findconnid(4, "udp", "8.8.8.8", 22, "192.168.1.100", 8080)

assert(id1 == id3)
assert(id2 == nil)
assert(id4 == nil)
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

### `packet:close()`

Discards all resources of copied packet `packet`.
After this call no further operations can be performed on packet `packet`.

### `packet:send([payload])`

Send the copied packet `packet` through the network and then closes it, thus it cannot be sent again.
If `payload` is provided, the original packet payload is replaced by the contents of string `payload`.
This function only works when you acquire the packet during a match in FORWARD chain.
