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

This documentation describes the user space Lua library that manages the Lunatik states in NFLua.
Unless otherwise stated, all functions return `nil` on failure, plus an error message and a system-dependent error code.
In case of success, the functions return a value different from `nil`; `true` if not stated otherwise.
If the contract of the functions are not respected, the function may trigger an error.

# Contents

## Constants

### `nflua.datamaxsize`

Integer constant that represents the maximum number of bytes transmitted in a single data message.

### `nflua.defaultmaxallocbytes`

Integer constant that represents the default maximum number of bytes that each state can allocate.

### `nflua.maxstates`

Integer constant that represents the maximum number of states that can coexist at a single time.

### `nflua.scriptnamemaxsize`

Integer constant that represents the maximum name size of a script.

### `nflua.statenamemaxsize`

Integer constant that represents the maximum name size of a state.

## Control Socket

### `control = nflua.control([port])`

Returns a new control socket that can be used to send control messages to the NFLua kernel module over Netlink.
The number `port` is used as the port ID of the socket and it must be in range [1, 2^31).
If `port` is absent an automatic port ID is assigned.

### `control:close()`

Closes the control socket `control`.

### `control:getfd()`

Returns the file descriptor number of control socket `control`.

### `control:getpid()`

Returns the port ID number of control socket `control`.

### `control:getstate()`

Returns a string that defines the current state of control socket `control`, as described below:

* `"ready"`: socket can be used to send commands.
* `"sending"`: socket shall be used to send the remaining of the current command.
* `"waiting"`: socket shall be used to start receiving a reply.
* `"receiving"`: socket shall be used to receive the remains of a reply.
* `"failed"`: socket shall be closed due to faulty communication using the underlying protocol.
* `"closed"`: socket is closed.

### `control:create(name [, maxalloc])`

Sends command using socket `control` to NFLua kernel module to create a new Lua state.
After sending the command successfully, the code must call [`control:receive`](#result--controlreceive) to obtain the actual result before sending the another command.

String `name` is the name of the module; it must be unique and it should have less than [`nflua.statenamemaxsize`](#nfluastatenamemaxsize) characters.
Number `maxalloc` is the maximum number of bytes that the state can allocate in the kernel; the default value is defined by [`nflua.defaultmaxallocbytes`](#nfluadefaultmaxallocbytes).

### `control:destroy(state)`

Sends command using socket `control` to NFLua kernel module to remove a Lua state with name `state`.
After sending the command successfully, the code must call [`control:receive`](#result--controlreceive) to obtain the actual result before sending the another command.

### `control:execute(state, chunk [, scriptname])`

Sends command using socket `control` to NFLua kernel module to execute the Lua code in string `chunk` in state with name `state`.
`scriptname` is a string used to represent the name of the script file in error messages; it must have less than [`nflua.statenamemaxsize`](#nfluastatenamemaxsize) characters.
This function should be called multiple times with the same arguments until there are no more fragments to be sent.
Returns `nil` and `"pending"` if there are still fragments to be sent; returns `true` once finished sending the whole chunk.
After sending the command successfully, the code must call [`control:receive`](#result--controlreceive) to obtain the actual result before sending the another command.

### `control:list()`

Sends command using socket `control` to NFLua kernel module to reply with information about all current Lua states.
After sending the command successfully, the code must call [`control:receive`](#result--controlreceive) to obtain the actual result before sending the another command.

### `result = control:receive()`

Receives a command reply using socket `control`.
This function should be called multiple times until there are no more fragments to be received.
Returns `nil` and `"pending"` if there are still fragments to be received.
The reply of commands sent by operations [`control:create`](#controlcreatename--maxalloc), [`control:destroy`](#controldestroystate), and [`control:execute`](#controlexecutestate-chunk--scriptname) return `true` in case of success.
The reply of commands sent by operation [`control:list`](#controllist) return a sequence of tables with the following structures:

```lua
{
	name = "MyNFLua",  -- unique name of the state.
	maxalloc = 65536,  -- maximum of 64K bytes allocated.
	curralloc = 12345, -- number of bytes currently allocated.
}
```

## Data Socket

### `nflua.data([port])`

Returns a new data socket that can be used to send data to Lua states of the NFLua kernel module over Netlink.
The number `port` is interpreted just like in function [`nflua.control`](#control--nfluacontrolport).

### `data:close()`

Closes the data socket `data`.

### `data:getfd()`

Returns the file descriptor number of data socket `data`.

### `data:getpid()`

Returns the port ID number of data socket `data`.

### `data:send(state, buffer)`

Sends data from the [memory](https://github.com/cujoai/lua-memory/blob/master/doc/manual.md) `buffer` using socket `data` to the Lua state with name `state` in NFLua kernel module.

### `recv, state = data:receive(buffer, offset)`

Receives a data message in the [memory](https://github.com/cujoai/lua-memory/blob/master/doc/manual.md) `buffer` starting at the given `offset` (integer).
There should be at least `nflua.datamaxsize` bytes available in `buffer` to receive a chunk of the message.
Returns the number of bytes read and the state that sent the message.
