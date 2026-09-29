#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
struct M{uint64_t s,e;char line[700];};
int main(int ac,char**av){
 if(ac<4)return 2;int pid=atoi(av[1]);uint64_t a=strtoull(av[2],0,16),b=strtoull(av[3],0,16);
 std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[700];
 while(fgets(line,sizeof(line),f)){unsigned long long s,e;char p[5]={};if(sscanf(line,"%llx-%llx %4s",&s,&e,p)==3&&p[0]=='r'){M m{(uint64_t)s,(uint64_t)e,{0}};strncpy(m.line,line,699);ms.push_back(m);}}
 fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;std::vector<uint8_t>x(4*1024*1024+16);
 for(auto&m:ms){if(m.e-m.s<16||m.e-m.s>500ull*1024*1024)continue;uint64_t pos=m.s;size_t ov=0;
  while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,x.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;
   for(size_t o=0;o+16<=n;o+=8){uint64_t q=((uint64_t*)x.data())[o/8];uint64_t r=((uint64_t*)x.data())[o/8+1];if(q==a&&r==b)printf("PAIR 0x%llx %llx/%llx map=0x%llx-0x%llx %s",(unsigned long long)(pos+o-ov),(unsigned long long)q,(unsigned long long)r,(unsigned long long)m.s,(unsigned long long)m.e,m.line);}
   ov=std::min<size_t>(8,n);memmove(x.data(),x.data()+n-ov,ov);pos+=g;
  }
 }
 close(fd);return 0;
}