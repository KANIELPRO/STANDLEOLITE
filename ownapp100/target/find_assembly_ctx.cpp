#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
struct M{uint64_t s,e;bool x;bool w;std::string p;};
static const M*own(const std::vector<M>&m,uint64_t v){for(auto&a:m)if(v>=a.s&&v<a.e)return &a;return nullptr;}
static bool findb(const uint8_t*b,size_t n,const char*s,size_t&a){size_t z=strlen(s);for(size_t i=0;i+z<=n;i++)if(!memcmp(b+i,s,z)){a=i;return true;}return false;}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[1024],per[5]={},p[700]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %699[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r')ms.push_back({s,e,per[2]=='x',per[1]=='w',n>=5?p:""});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;std::vector<uint8_t>b(4*1024*1024+64);int hits=0;
for(auto&m:ms){if(m.e-m.s>300ull*1024*1024||m.e-m.s<32)continue;uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g,at=0,baseoff=0;while(findb(b.data(),n,"Assembly-CSharp.dll",at)){uint64_t va=pos+at-ov;printf("HIT 0x%llx map 0x%llx-0x%llx x=%d w=%d %s\n",(unsigned long long)va,(unsigned long long)m.s,(unsigned long long)m.e,m.x,m.w,m.p.c_str());uint64_t start=va>=128?va-128:va;uint8_t qbuf[512];ssize_t gg=pread(fd,qbuf,sizeof(qbuf),start);for(int j=0;j<gg/8;j++)printf("  %3d 0x%llx\n",(j-16)*8,(unsigned long long)(*reinterpret_cast<uint64_t*>(qbuf+j*8)));fflush(stdout);if(++hits>=30)return 0;at+=19;}
ov=std::min<size_t>(64,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}close(fd);return 0;}