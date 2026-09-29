#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <cstring>
int main(int ac,char**av){int pid=atoi(av[1]);uint64_t cr=strtoull(av[2],0,16);std::string ps="/proc/"+std::to_string(pid);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 1;uint64_t q[17]{};if(pread(fd,q,sizeof(q),cr)!=sizeof(q))return 2;for(int i=0;i<17;i++)printf("q%d=0x%llx\n",i,(unsigned long long)q[i]);printf("MODULEPTRS\n");for(uint64_t i=0;i<q[15]&&i<220;i++){uint64_t v=0;pread(fd,&v,8,q[16]+i*8);char s[128]={};ssize_t g=v?pread(fd,s,sizeof(s)-1,v):0;size_t n=0;while(n<g&&s[n]>=0x20&&s[n]<0x7f)n++;printf("%3llu 0x%llx %s\n",(unsigned long long)i,(unsigned long long)v,n?s:"");}close(fd);}