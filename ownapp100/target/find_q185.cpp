#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
struct M{uint64_t s,e;bool w,x;std::string p;};
static bool inp(const std::vector<M>&m,uint64_t v){for(auto&a:m)if(v>=a.s&&v<a.e)return true;return false;}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[900],per[5]={},p[600]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r'&&e-s>=8&&e-s<250ull*1024*1024)ms.push_back({s,e,per[1]=='w',per[2]=='x',n>=5?p:""});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;std::vector<uint8_t>b(4*1024*1024+8);int hits=0;
for(auto&m:ms){uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+16*8<=n;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);if(q[15]!=185||!q[16]||!inp(ms,q[16]))continue;printf("Q185 @0x%llx map=0x%llx-0x%llx w=%d x=%d\n",(unsigned long long)(pos+o-ov),(unsigned long long)m.s,(unsigned long long)m.e,m.w,m.x);for(int i=0;i<17;i++)printf("0x%llx%c",(unsigned long long)q[i],i==16?'\n':' ');fflush(stdout);if(++hits>=100)return 0;}ov=8;memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}printf("DONE %d\n",hits);}