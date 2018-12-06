CC=gcc
CFLAGS= -O0 -fpermissive
all:
	#gcc -o ssp main.c sha3.c elf.c -static
	#gcc -o ssp main.c sha3.c elf.c -g
	gcc -o ssp main.c sha3.c elf.c
