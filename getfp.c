#include <stdio.h>

int main () {
    unsigned long int rbp;
    __asm__("movq %%rbp, %0" : "=r"(rbp));
    printf("0x%016lx\n", rbp);
    return 0;
}
