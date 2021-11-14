#include <stdio.h>
#include <stdlib.h>

int collatz_message(char* message, int n)
{
        if(n % 2) {
                n = 3 * n + 1;
        }
        else {
                n = n / 2;
        }

        if(message)
                printf("%s: %d", message, n);

        return n;
}

int main(int argc, char** argv) {
        collatz_message("test", atoi(argv[1]));
}

