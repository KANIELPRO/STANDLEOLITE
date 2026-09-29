#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
static int hx(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
int main(int ac,char**av){
if(ac<4){fprintf(stderr,"usage pid addr hex");return 2;}
int pid=atoi(av[1]);uint64_t a=strtoull(av[2],0,16);std::string h=av[3];
if(h.size()%2){fprintf(stderr,"odd hex");return 3;}std::string mp="/proc/"+std::to_string(pid)+"/mem";int fd=open(mp.c_str(),O_RDWR);if(fd<0){perror("open");return 4;}
size_t n=h.size()/2;std::string b(n,0);
for(size_t i=0;i<n;i++){int x=hx(h[2*i]),y=hx(h[2*i+1]);if(x<0||y<0)return 5;b[i]=(char)((x<<4)|y);}
ssize_t w=pwrite(fd,b.data(),b.size(),a);if(w!=(ssize_t)b.size()){perror("pwrite");return 6;}
close(fd);printf("WROTE %zu at 0x%llx\n",n,(unsigned long long)a);return 0;}
