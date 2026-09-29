#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
int main(int argc,char**argv){
 if(argc<2)return 127;
 if(setenv("LD_PRELOAD","/data/local/tmp/libSTANDCHERRY.probe.so",1)!=0)return 126;
 execvp(argv[1],argv+1);
 return 125;
}
