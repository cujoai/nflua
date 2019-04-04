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

- [`timer.create`](#timer--timercreatemsecs-callback)
- [`timer.destroy`](#timerdestroytimer)

Contents
--------

### `timer = timer.create(msecs, callback)`

Return a new timer that will call the function `callback` once after `msecs` milliseconds.

### `timer.destroy(timer)`

If `timer` was never triggered, it is cancelled so its callback will not be called.
Otherwise, this function has no effect.
