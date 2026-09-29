#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>
struct R{uint64_t s,e;char line[900];};
int main(int argc,char**argv){if(argc<3)return 2;int pid=atoi(argv[1]);uint64_t target=strtoull(argv[2],0,16);std::string mp="/proc/"+std::to_string(pid)+"/mem";int fd=open(mp.c_str(),O_RDONLY);if(fd<0){perror("mem");return 1;}FILE*f=fopen(("/proc/"+std::to_string(pid)+"/maps").c_str(),"r");if(!f){perror("maps");return 1;}char line[900],perm[8];unsigned long long s,e;std::vector<R>rs;while(fgets(line,sizeof(line),f)){char p[700]={};if(sscanf(line,"%llx-%llx %7s %*s %*s %*s %699[\n]",&s,&e,perm,p)>=3&&perm[0]=='r'){R r{(uint64_t)s,(uint64_t)e,{0}};strncpy(r.line,line,sizeof(r.line)-1);rs.push_back(r);}}fclose(f);
std::vector<uint8_t>b(4*1024*1024+8);uint64_t hits=0;
for(auto&r:rs){if(r.e-r.s<8||r.e-r.s>500ull*1024*1024)continue;uint64_t pos=r.s;size_t ov=0;while(pos<r.e){size_t w=std::min<uint64_t>(4*1024*1024,r.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t i=0;i+8<=n;i+=8){uint64_t v=*reinterpret_cast<uint64_t*>(b.data()+i);if(v==target){uint64_t va=pos+i-ov;printf("HIT 0x%llx map 0x%llx-0x%llx %s",(unsigned long long)va,(unsigned long long)r.s,(unsigned long long)r.e,r.line);uint64_t start=va>=64?va-64:va;uint8_t tmp[320];ssize_t gg=pread(fd,tmp,sizeof(tmp),start);if(gg>0){for(int j=0;j<gg/8;j++){uint64_t x=*reinterpret_cast<uint64_t*>(tmp+j*8);printf("  %02d 0x%llx",(j-8)*8,(unsigned long long)x);if(j%4==3)printf("\n");}printf("\n");}hits++;if(hits>=200)return 0;}}ov=std::min<size_t>(8,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}
printf("DONE hits=%llu\n",(unsigned long long)hits);return 0;}