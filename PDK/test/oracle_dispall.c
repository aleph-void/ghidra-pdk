// harness: print dispdk (MIT) disassembly of every opcode word for a PDK width
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "emucpu.h"
#include "disass.h"
int main(int argc,char**argv){
  int w=atoi(argv[1]); static struct emuCPU cpu; char buf[64];
  memset(&cpu,0,sizeof cpu); cpu.maxCode=4; 
  TemuCPUdisassemble f = w==13?disass13:w==14?disass14:w==15?disass15:disass16;
  unsigned n=1u<<w;
  for(unsigned op=0;op<n;op++){ cpu.eCode[0]=op; cpu.eCode[1]=0; f(&cpu,0,buf); printf("%04x %s\n",op,buf);}
  return 0;}
