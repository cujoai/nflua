#!/bin/bash
#
# Copyright (C) 2019 CUJO LLC
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
#

if ! [ -d $HOME/linux ]; then
	echo "clone linux to your $HOME folder"
	exit -1
fi

tags=$(cd $HOME/linux && git tag -l | grep -v rc | sort -V)
tags=$(echo "$tags" | sed -e '1,/v3.3/ d' -e '/v4.16/,$ d')

CC=gcc-4.8

for tag in $tags; do
  echo "compiling $tag"
  pushd $HOME/linux/
  git checkout "$tag"
  git reset HEAD --hard
  git clean -d -x -f -q
  make defconfig
  make modules_prepare CC=$CC || exit -1
  popd
  make -C $HOME/linux M=$PWD CC=$CC CONFIG_NFLUA=m || exit -1
done

echo "success"
