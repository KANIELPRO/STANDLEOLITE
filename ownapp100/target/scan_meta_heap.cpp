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
static bool in(const std::vector<M>&ms,uint64_t v){for(auto&a:ms)if(v>=a.s&&v<a.e)return true;return false;}
static bool sm(uint64_t x,uint64_t lo,uint64_t hi){return x>=lo&&x<=hi&&(x>>32)==0;}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[1024],per[5]={},p[700]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %699[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r'&&per[1]!='w'&&std::string(p).empty()&&s>=0x6e00000000ULL&&e<=0x6f60000000ULL)ms.push_back({s,e});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;std::vector<uint8_t>b(4*1024*1024+128);const uint64_t LO=0x6e00000000ULL,HI=0x6f60000000ULL;int total=0;
for(auto&m:ms){uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+128<=n;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);const uint64_t lim[]={1000000,2000000,10000000,500000,5000000,10000000,10000000,100000000};bool ok=1;int nz=0;for(int i=0;i<8;i++){if(q[i*2]>lim[i]||(q[i*2]>>32))ok=0;if(q[i*2]){nz++;if(!sm(q[i*2+1],LO,HI)|| (q[i*2+1]&7))ok=0;}}if(!ok||nz<6||q[6]<10000||q[8]<10000||q[10]<10000||q[12]<10000||q[14]<1000)continue;printf("META @0x%llx\n  ",(unsigned long long)(pos+o-ov));for(int i=0;i<8;i++)printf("%s%llu/0x%llx",(i?" ":""),(unsigned long long)q[i*2],(unsigned long long)q[i*2+1]);printf("\n");fflush(stdout);if(++total>=80)return 0;}ov=std::min<size_t>(128,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}close(fd);return 0;}