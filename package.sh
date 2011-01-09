#!/bin/sh
VERSION=0.4.8

rm *.gem *.tar.bz2
rm -rf doc

rdoc -w 4 -SHN -f darkfish -m README.txt --title 'Rua - library for using Lua under Ruby.' README.txt ext/rua.c

mkdir work
cp -r * work 2> /dev/null
cd work

tar jcvf rua-${VERSION}.tar.bz2 --exclude=.svn README.txt *.gemspec lib ext doc
gem build rua.gemspec
gem build rua-mswin32.gemspec
cp rua-${VERSION}-x86-mswin32.gem rua-${VERSION}-mswin32.gem

rm -rf lib
mv lib1.9 lib
gem build rua1.9-mswin32.gemspec

cp *.gem *.tar.bz2 ..
cd ..

rm -rf work
