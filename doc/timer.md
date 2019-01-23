Index
-----

- [`timer.create`](#timer--timercreatemsecs-callback)
- [`timer.destroy`](#timerdestroytimer)

Contents
--------

### `timer = timer.create(msecs, callback)`

Return a new timer that will call the function `callback` once after `msecs` milliseconds.

### `timer.destroy(timer)`

If `timer` was never triggered, it is cancelled so its callback will not be called.
Otherwise, this function has no effect.
