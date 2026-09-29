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
 int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 2;std::vector<M>maps;char line[900],per[5]={},p[600]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r'&&e-s>0&&e-s<260ull*1024*1024)maps.push_back({s,e});}fclose(f);
 int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 3;
 const uint64_t S=0x6f5ecc6000ULL,E=0x6f5f344000ULL;size_t N=E-S;std::vector<uint8_t>b(N);if(pread(fd,b.data(),N,S)!=(ssize_t)N)return 4;
 std::unordered_set<uint64_t>mods;int mc=0;
 for(size_t o=0;o+24<=N;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);if(!q[0]||!in(maps,q[0])||!q[1]||q[1]>20000000||!q[2]||!in(maps,q[2]))continue;std::string name;if(!rs(fd,q[0],name)||name.size()>160||name.find(".dll")!=name.size()-4)continue;mods.insert(S+o);mc++;}
 printf("MODULE_HEADS=%d\n",mc);
 for(size_t o=0;o+8<=N;o+=8){uint64_t v=*reinterpret_cast<uint64_t*>(b.data()+o);if(!mods.count(v))continue;size_t run=0;while(o+run*8+8<=N&&mods.count(*reinterpret_cast<uint64_t*>(b.data()+o+run*8)))run++;if(run>=3){printf("TABLE @0x%llx run=%zu first=0x%llx\n",(unsigned long long)(S+o),run,(unsigned long long)v);fflush(stdout);}}
 close(fd);return 0;
}