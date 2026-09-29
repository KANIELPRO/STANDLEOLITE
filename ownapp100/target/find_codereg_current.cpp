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
static const M*own(const std::vector<M>&m,uint64_t v){for(auto&a:m)if(v>=a.s&&v<a.e)return &a;return nullptr;}
static uint64_t U(const uint8_t*p){return *reinterpret_cast<const uint64_t*>(p);}
int main(int ac,char**av){
 if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);
 FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[900],per[5]={},p[600]={};unsigned long long s,e;
 while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r')ms.push_back({s,e});}fclose(f);
 int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;
 const uint64_t S=0x6f5ecc6000ULL,E=0x6f5f344000ULL;size_t N=E-S;std::vector<uint8_t>b(N);
 if(pread(fd,b.data(),N,S)!=(ssize_t)N)return 5;
 int hits=0;
 for(size_t o=0;o+136<=N;o+=8){
  uint64_t*q=(uint64_t*)(b.data()+o);
  if(q[15]<50||q[15]>5000||!q[16]||!own(ms,q[16]))continue;
  const M* mm=own(ms,q[16]); if(q[16]+q[15]*8>mm->e)continue;
  int good=0;for(uint64_t i=0;i<std::min<uint64_t>(q[15],20);i++){uint64_t v; if(pread(fd,&v,8,q[16]+i*8)!=8)break; if(own(ms,v))good++;}
  if(good<8)continue;
  auto validpair=[&](int c,int pidx,uint64_t lim){return q[c]<=lim && (q[pidx]==0||own(ms,q[pidx]));};
  if(!validpair(0,1,1000000)||!validpair(2,3,10000000)||q[4]&&!own(ms,q[4])||!validpair(5,6,10000000)||!validpair(7,8,10000000)||!own(ms,q[9])||!own(ms,q[10])||!validpair(11,12,10000000)||!validpair(13,14,1000000))continue;
  printf("CODEREG @0x%llx modules=%llu ptr=0x%llx sample=%d\n",(unsigned long long)(S+o),(unsigned long long)q[15],(unsigned long long)q[16],good);
  for(int i=0;i<17;i++)printf(" q%d=0x%llx",(i,(unsigned long long)q[i]));
  printf("\n");fflush(stdout);if(++hits>=50)break;
 }
 printf("DONE %d\n",hits);return 0;
}