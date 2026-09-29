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
struct M{uint64_t s,e;bool x,w;std::string p;};
static bool in(const std::vector<M>&m,uint64_t v,bool ex,bool wr){
 for(auto&a:m) if(v>=a.s&&v<a.e) return (!ex||a.x)&&(!wr||a.w);
 return false;
}
static const M* owner(const std::vector<M>&m,uint64_t v){
 for(auto&a:m) if(v>=a.s&&v<a.e) return &a; return nullptr;
}
static uint64_t rd64(const std::vector<uint8_t>&b,size_t o){return *reinterpret_cast<const uint64_t*>(b.data()+o);}
static bool small(uint64_t x,uint64_t lim){return x<=lim&&((x>>32)==0);}
int main(int argc,char**argv){
 if(argc<2)return 2;int pid=atoi(argv[1]);std::string ps="/proc/"+std::to_string(pid);
 FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M> ms;char line[1024];
 while(fgets(line,sizeof(line),f)){unsigned long long s,e,off;char perm[5]={};char path[700]={};
  int n=sscanf(line,"%llx-%llx %4s %llx %*s %*s %699[\n]",&s,&e,perm,&off,path);
  if(n>=3&&perm[0]=='r'&&e>s) {std::string p=(n>=5?path:"");ms.push_back({s,e,perm[2]=='x',perm[1]=='w',p});}
 }fclose(f);
 int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;
 std::vector<uint8_t>b(4*1024*1024+16);
 for(auto&m:ms){
  if(m.e-m.s<136||m.e-m.s>300ull*1024*1024)continue;
  uint64_t pos=m.s;size_t ov=0;
  while(pos<m.e){
   size_t want=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,want,pos);if(g<=0)break;size_t n=ov+g;
   for(size_t o=0;o+136<=n;o+=8){
    const uint64_t*q=reinterpret_cast<const uint64_t*>(b.data()+o);
    bool c=small(q[0],2000000)&&small(q[2],5000000)&&small(q[5],5000000)&&small(q[7],1000000)&&small(q[9],1000000)&&small(q[12],1000000)&&small(q[14],1000000)&&small(q[16],5000);
    if(!c)continue;
    if(!q[1]||!in(ms,q[1],true,false))continue;
    if(!q[3]||!in(ms,q[3],true,false))continue;
    if(!q[4]||!in(ms,q[4],true,false))continue;
    if(!q[6]||!in(ms,q[6],true,false))continue;
    if(!q[8]||!in(ms,q[8],true,false))continue;
    if(!q[10]||!in(ms,q[10],true,false))continue;
    if(!q[11]||!in(ms,q[11],false,false))continue;
    if(!q[13]||!in(ms,q[13],false,false))continue;
    if(!q[15]||!in(ms,q[15],false,false))continue;
    if(!q[17]||!in(ms,q[17],false,false))continue;
    uint64_t va=pos+o-ov;printf("CODE 0x%llx map=0x%llx-0x%llx x=%d w=%d\n  ",(unsigned long long)va,(unsigned long long)m.s,(unsigned long long)m.e,m.x,m.w);
    for(int i=0;i<17;i++)printf("%s0x%llx",(i?" ":""),(unsigned long long)q[i]);printf("\n");fflush(stdout);
   }
   ov=std::min<size_t>(16,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;
  }
 }
 close(fd);return 0;
}