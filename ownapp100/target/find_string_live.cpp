#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
struct M{uint64_t s,e;};
static void scan(int fd,const M&m,const char*needle){
 size_t L=strlen(needle);std::vector<uint8_t>b(4*1024*1024+256);uint64_t pos=m.s;size_t ov=0;
 while(pos<m.e){size_t w=std::min<uint64_t>(4*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;
  for(size_t i=0;i+L<=n;i++)if(!memcmp(b.data()+i,needle,L)){printf("STR %s @0x%llx\n",needle,(unsigned long long)(pos+i-ov));fflush(stdout);}
  ov=std::min<size_t>(L-1,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;
 }
}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[900],per[5]={},p[600]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r'&&e-s>0&&e-s<220ull*1024*1024)ms.push_back({s,e});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;for(auto&m:ms)scan(fd,m,"mscorlib.dll");close(fd);}