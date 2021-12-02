#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int get_res(char op, int l, int r) {
	switch (op) {
		case '+':
			return l+r;
		case '-':
			return l-r;
		case '*':
			return l*r;
		case '/':
			return l/r;
	}

	printf("Unsupported operation\n");
	exit(-1);
}

int main(int argc, char** argv) {
	if (argc != 4) {
		printf("Expected 4 args...\n");
		return -1;
	}

	printf("res: %i", get_res(*argv[1], atoi(argv[2]), atoi(argv[3])));
}
