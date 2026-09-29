#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include <string>
int main(int argc,char**argv){if(argc<4){fprintf(stderr,"usage pid start end [out]\n");return 2;}int pid=atoi(argv[1]);uint64_t s=strtoull(argv[2],0,16),e=strtoull(argv[3],0,16);const char*out=argc>4?argv[4]:"/data/local/tmp/range.bin";std::string mp="/proc/"+std::to_string(pid)+"/mem";int fd=open(mp.c_str(),O_RDONLY);if(fd<0){perror("mem");return 1;}int of=open(out,O_CREAT|O_TRUNC|O_WRONLY,0600);if(of<0){perror("out");return 1;}std::vector<uint8_t>b(4*1024*1024);uint64_t p=s,total=0;while(p<e){size_t w=std::min<uint64_t>(b.size(),e-p);ssize_t g=pread(fd,b.data(),w,p);if(g<=0){perror("pread");break;}write(of,b.data(),g);p+=g;total+=g;}close(of);close(fd);printf("DUMP %s bytes=%llu\n",out,(unsigned long long)total);return 0;}