#include <stdio.h>
#include <stdlib.h>

#define PROTECT_PTR(pos, ptr)					\
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)

int main(int argc, char** argv) {
  printf("0x%x\n", PROTECT_PTR(strtoull(argv[1], NULL, 16), strtoull(argv[2], NULL, 16)));
}
    
