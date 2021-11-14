#include <stdint.h>
#include <stdio.h>

int main() {
	int* value = ((uint64_t)malloc(sizeof(int))) ^ 0x1000;
	*(int*)(((uint64_t)value) ^ 0x1000) = 100;
	printf("%i", *(int*)(((uint64_t)value) ^ 0x1000));
	return *(int*)(((uint64_t)value) ^ 0x1000);
}
