#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string>
int main(int ac,char**av){if(ac<4)return 2;int pid=atoi(av[1]);uint64_t a=strtoull(av[2],0,16);int n=atoi(av[3]);std::string p="/proc/"+std::to_string(pid)+"/mem";int fd=open(p.c_str(),O_RDONLY);if(fd<0)return 1;for(int i=0;i<n;i++){uint64_t v=0;if(pread(fd,&v,8,a+i*8)!=8)break;printf("%04x 0x%llx\n",i*8,(unsigned long long)v);}close(fd);}