#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
struct M{uint64_t s,e;};
static bool in(const std::vector<M>&ms,uint64_t v){for(auto&a:ms)if(v>=a.s&&v<a.e)return true;return false;}
static bool rs(int fd,uint64_t a,std::string&out){char q[160]={};ssize_t n=pread(fd,q,sizeof(q)-1,a);if(n<=0)return false;size_t i=0;while(i<(size_t)n&&q[i]>=0x20&&q[i]<0x7f)i++;if(i<4)return false;out.assign(q,i);return true;}
int main(int ac,char**av){
 int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 2;std::vector<M>maps;char line[900],per[5]={},p[600]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r'&&e-s>=24&&e-s<260ull*1024*1024)maps.push_back({s,e});}fclose(f);
 int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 3;
 const uint64_t S=0x6f5ecc6000ULL,E=0x6f5f344000ULL;size_t N=E-S;std::vector<uint8_t>mb(N);pread(fd,mb.data(),N,S);
 std::unordered_set<uint64_t>mods;for(size_t o=0;o+24<=N;o+=8){uint64_t*q=(uint64_t*)(mb.data()+o);if(!q[0]||!in(maps,q[0])||!q[1]||q[1]>20000000||!q[2]||!in(maps,q[2]))continue;std::string name;if(!rs(fd,q[0],name)||name.size()>160||name.find(".dll")!=name.size()-4)continue;mods.insert(S+o);}
printf("MODULE_HEADS=%zu\n",mods.size());
std::vector<uint8_t>b(4*1024*1024+16);
for(auto&m:maps){uint64_t pos=m.s;size_t ov=0,last=0,run=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+8<=n;o+=8){uint64_t v=*reinterpret_cast<uint64_t*>(b.data()+o);if(mods.count(v)){if(run==0)last=pos+o-ov;run++;if(run>=3) {printf("TABLE map @0x%llx run=%zu first=0x%llx\n",(unsigned long long)last,run,(unsigned long long)(v));fflush(stdout);}}else run=0;}ov=8;memmove(b.data(),b.data()+n-8,8);pos+=g;}}
close(fd);return 0;}