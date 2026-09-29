#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
int main(int ac,char**av){
 int fd=open("/proc/6048/mem",O_RDONLY);if(fd<0)return 1;
 uint64_t a=strtoull(av[1],0,16);uint64_t q[12];if(pread(fd,q,sizeof(q),a)!=sizeof(q))return 2;
 for(int i=0;i<12;i++){printf("q%d=0x%llx ",i,(unsigned long long)q[i]);if(q[i]){char s[160];ssize_t n=pread(fd,s,159,q[i]);if(n>0){size_t j=0;while(j<(size_t)n&&s[j]>=32&&s[j]<127)j++;if(j>=4)printf("str=%.*s",(int)j,s);}}printf("\n");}
 close(fd);return 0;}