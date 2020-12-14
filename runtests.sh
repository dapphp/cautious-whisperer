#!/bin/bash

src_objects="src/fp_lib.o src/encryption_functions.o cs12Lib/cs12Lib.o"
src_libs="-lc -lssl -lcrypto"

make || { echo 'error! build failed' ; exit 1; }

yasm -Worphan-labels -f elf64 -g dwarf2 tests/test.asm -o tests/test.o -l tests/test.lst \
	|| { echo 'error! failed to assemble test.asm' ; exit 1; }

gcc -nostdlib -fPIC -no-pie -gdwarf-2 -O0 -DDEBUG -o tests/test tests/test.o $src_objects $src_libs \
	|| { echo 'error! failed to link test' ; exit 1; }

./tests/test
