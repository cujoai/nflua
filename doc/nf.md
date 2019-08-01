_Copyright (C) 2017-2019  CUJO LLC_

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

# Introduction

This documentation describes the Lua kernel modules that are available in NFLua.

# Netfilter Callbacks

## Match callback function

```
function match(pkt)
	return true
end
```

The match callback receives one [packet object](#packet) `pkt` representing a Linux `sk_buff`.
After the callback returns no further operations can be performed on the packet.
This callback should return either a boolean to indicate whether it's a match, or `"hotdrop"` to indicate hotdropping the packet; other return values are considered an error.
In case of errors, it is considered that the match function returned false.
For information on how to register a match callback see the `nflua/iptables/README.md` documentation.

## Target callback function

```
function target(pkt)
	return 'drop'
end
```

The target callback receives one [packet object](#packet) `pkt` representing a Linux sk_buff.
After the callback returns no further operations can be performed on the packet unless it returned `'stolen'`.
This callback should return one of the following strings: `'drop'`, `'accept'`, `'stolen'`, `'queue'`, `'repeat'` and `'stop'`.
Returning any other value will have the same effect as `XT_CONTINUE`.
For information on how to register a target callback see the `nflua/iptables/README.md` documentation.

# Modules

## Netlink

### `size = netlink.send(port, groups, payload)`

Sends a Netlink datagram using protocol defined by kernel symbol `NETLINK_NFLUA`.
The datagram is sent to port with ID given by number `port` and to multicast groups given by the bits on number `groups`.
The contents of the datagram is given by the parameter `payload`, which can be either a string or a [memory](https://github.com/cujoai/lua-memory/) object.

## Timer

### `timer = timer.create(msecs, callback)`

Return a new timer that will call the function `callback` once after `msecs` milliseconds.

### `timer.destroy(timer)`

If `timer` was never triggered, it is cancelled so its callback will not be called.
Otherwise, this function has no effect.

## Conntrack

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

## Packet

### `packet:close()`

Discards all resources of the packet; this function can only be called on packets that have been stolen.
After this call no further operations can be performed on the packet.
Returns true on success.

### `id = packet:connid()`

Returns a userdata that represents the ID of the packet's connection as maintained by `conntrack` module of Netfilter.
This `id` might be reused by other future connections, but such reuse indicates that all previous connections identified by the same value are not tracked anymore.

### `mem = packet:frame()`

Returns a [memory](https://github.com/cujoai/lua-memory/) object which references the frame part of the packet (L1 header).
When the packet is closed the memory object becomes empty and stop referencing the packet.

### `packet:send([payload])`

Send the packet through the network and then closes it, thus it cannot be sent again.
If `payload` is provided, the original packet payload is replaced by the contents of string `payload`.
This function only works after you steal the packet in the FORWARD chain.

### `packet:tcpreply(type, message)`

Sends a TCP reply with the string `message` as payload.
To this function work two conditions must be met:

- The original packet must be intercepted in the FORWARD chain.
- The address of the recipient of the reply packet must be in the same subnet of the interface that the original packet was intercepted.

### `... = packet:unpack(fmt [, pos])`

Returns the values encoded in position `pos` of packet's payload (see diagram below), according to the format `fmt` (see the [Lua manual](https://www.lua.org/manual/5.3/manual.html#6.4.2)).
Formats `f`, `d` are not supported.
The default value for `pos` is 1.

```
+-----------------------------------------+
|packet header||      packet payload      |
+-----------------------------------------+
+-----------------------------------------+
|             ||      |       |           |
|  Ethernet   ||  IP  |  TCP  |    ...    |
|             ||      |       |           |
+---------------------+-------+-----------+
```

### `packet:copybytes(m [, i [, j [, o]]])`

Copies as much of the contents of packet's payload from position `i` until `j` to memory `m` from position `o` of `m`;
i, j and o can be negative.

These indices are corrected following the same rules of function [`memory.find`](https://github.com/cujoai/lua-memory/blob/master/doc/manual.md#memoryfind-m-s--i--j--o).
