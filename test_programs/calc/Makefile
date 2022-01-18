
all:
	clang -fno-jump-tables -S -emit-llvm calc.c
	clang calc.c -fno-jump-tables -o calc
