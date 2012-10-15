#include <stdio.h>
void p(unsigned short i) {
  printf("%x\n",i);
}
main ()
{
  int i;
  p((unsigned long) &i);
}
