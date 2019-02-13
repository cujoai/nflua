Index
-----

- [`nf.connid`](#id--nfconnid)
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
