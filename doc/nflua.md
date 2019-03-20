Index
-----

- [`nflua.control`](#control--nfluacontrolport)
- [`nflua.data`](#nfluadataport)
- [`nflua.datamaxsize`](#nfluadatamaxsize)
- [`nflua.defaultmaxallocbytes`](#defaultmaxallocbytes)
- [`nflua.fragsize`](#nfluafragsize)
- [`nflua.maxstates`](#nfluamaxstates)
- [`nflua.scriptnamemaxsize`](#nfluascriptnamemaxsize)
- [`nflua.statenamemaxsize`](#nfluastatenamemaxsize)
- [`control:close`](#controlclose)
- [`control:getfd`](#controlgetfd)
- [`control:getpid`](#controlgetpid)
- [`control:getstate`](#controlgetstate)
- [`control:create`](#controlcreatename-intructions-memory--flags)
- [`control:destroy`](#controldestroystate)
- [`control:execute`](#controlexecutestate-chunk)
- [`control:list`](#controllist)
- [`control:receive`](#result--controlreceive)
- [`data:close`](#dataclose)
- [`data:getfd`](#datagetfd)
- [`data:getpid`](#datagetpid)
- [`data:send`](#datasendstate-buffer)
- [`data:receive`](#buffer--datareceive)

Contents
--------

Unless otherwise stated, all functions return nil on failure, plus an error message and a system-dependent error code.
In case of success, the functions return a value different from nil; true if not state otherwise.
If the contract of the functions are not respected, the function may trigger an error.

### `control = nflua.control([port])`

Returns a new control socket that can be used to send control messages to the NFLua kernel module over Netlink.
The number `port` is used as the port ID of the socket and it must be in range [1, 2^31).
If `port` is absent an automatic port ID is assigned.

### `nflua.data([port])`

Returns a new data socket that can be used to send data to Lua states of the NFLua kernel module over Netlink.
The number `port` is interpreted just like in function [`nflua.control`](#control--nfluacontrolport).

### `nflua.datamaxsize`

Integer constant that represents the maximum number of bytes transmitted in a single data message.

### `nflua.defaultmaxallocbytes`

Integer constant that represents the default maximum number of bytes that each state can allocate.

### `nflua.fragsize`

Integer constant that represents the maximum number of bytes transmitted in a script fragment.

### `nflua.maxstates`

Integer constant that represents the maximum number of states that can coexist at a single time.

### `nflua.scriptnamemaxsize`

Integer constant that represents the maximum name size of a script.

### `nflua.statenamemaxsize`

Integer constant that represents the maximum name size of a state.

### `control:close()`

Closes the control socket `control`.

### `control:getfd()`

Returns the file descriptor number of control socket `control`.

### `control:getpid()`

Returns the port ID number of control socket `control`.

### `control:getstate()`

Returns a string that defines the current state of control socket `control`, as described below:

`"ready"`: socket can be used to send commands.
`"waiting"`: socket shall be used to start receiving a reply.
`"receiving"`: socket shall be used to receive the remains of a reply.
`"failed"`: socket shall be closed due to faulty communication using the underlying protocol.

### `control:create(name, intructions, memory [, flags])`

Sends command using socket `control` to NFLua kernel module to create a new Lua state.
String `name` is the name of the module and it must be unique.
Number `instructions` is the maximum number of Lua VM instructions that a Lua state can execute at once; after the interpeter executes this number of instructions, it interrupts the call.
Number `memory` is the maximum number of bytes that the state can allocate in the kernel.
String `flags` shall contain the following characters that will define additional configuration options for the state to be created:

- `d`: loads the Lua Standard Debug library to the state (module `debug`).

### `control:destroy(state)`

Sends command using socket `control` to NFLua kernel module to remove a Lua state with name `state`.

### `control:execute(state, chunk)`

Sends command using socket `control` to NFLua kernel module to execute the Lua code in string `chunk` in state with name `state`.

### `control:list()`

Sends command using socket `control` to NFLua kernel module to reply with information about all current Lua states.

### `result = control:receive()`

Receives a command reply using socket `control`.
The reply of commands sent by operations [`control:create`](#controlcreatename-intructions-memory--flags), [`control:destroy`](#controldestroystate), and [`control:execute`](#controlexecutestate-chunk) return `true` in case of success.
The reply of commands sent by operation [`control:list`](#controllist) return a sequence of tables with the following structures:

```lua
{
	name = "MyNFLua", -- unique name of the state.
	maxruns = 1000,   -- maximum of 1K opcodes executed by callback.
	maxalloc = 65536, -- maximum of 64K bytes allocated.
	flags = "d",      -- optional configuration flags of the state.
}
```

### `data:close()`

Closes the data socket `data`.

### `data:getfd()`

Returns the file descriptor number of data socket `data`.

### `data:getpid()`

Returns the port ID number of data socket `data`.

### `data:send(state, buffer)`

Sends data from the LuaData object `buffer` using socket `data` to the Lua state with name `state` in NFLua kernel module.

### `recv, state = data:receive(buffer, offset)`

Receives a data message in the LuaData object `buffer` starting at the given `offset` (integer).
There should be at least `nflua.datamaxsize` bytes available in `buffer` to receive a chunk of the message.
Returns the number of bytes read and the state that sent the message.
