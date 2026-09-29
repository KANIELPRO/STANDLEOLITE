#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
struct R{uint64_t s,e;std::string p;};
static bool hit(const uint8_t*b,size_t n,const uint8_t*p,size_t m,size_t&a){for(size_t i=0;i+m<=n;i++)if(!memcmp(b+i,p,m)){a=i;return true;}return false;}
int main(int argc,char**argv){int pid=atoi(argv[1]);std::ifstream mf("/proc/"+std::to_string(pid)+"/maps");std::string line,rg,perm,off,dev,ino,path;std::vector<R>rs;
while(std::getline(mf,line)){std::istringstream is(line);is>>rg>>perm>>off>>dev>>ino;std::getline(is,path);while(!path.empty()&&path[0]==' ')path.erase(path.begin());if(perm.empty()||perm[0]!='r')continue;auto d=rg.find('-');uint64_t s=strtoull(rg.substr(0,d).c_str(),0,16),e=strtoull(rg.substr(d+1).c_str(),0,16);if(path.empty()&&e-s>=4096)rs.push_back({s,e,path});}
int fd=open(("/proc/"+std::to_string(pid)+"/mem").c_str(),O_RDONLY);if(fd<0){perror("mem");return 1;}const char*ns[]={"Assembly-CSharp.dll","Axlebolt.Standoff","Gameplay.Bomb.dll"};std::vector<uint8_t>b(4*1024*1024+256);
for(auto&r:rs){uint64_t pos=r.s;size_t ov=0;while(pos<r.e){size_t want=(size_t)std::min<uint64_t>(4*1024*1024,r.e-pos);ssize_t got=pread(fd,b.data()+ov,want,pos);if(got<=0)break;size_t sz=ov+got;bool any=false;for(const char*n:ns){size_t a;if(hit(b.data(),sz,(const uint8_t*)n,strlen(n),a)){printf("FOUND %s addr=0x%llx map=0x%llx-0x%llx\n",n,(unsigned long long)(pos+a-ov),(unsigned long long)r.s,(unsigned long long)r.e);fflush(stdout);any=true;}}
if(any){char out[128];snprintf(out,sizeof(out),"/data/local/tmp/candidate-%llx-%llx.bin",(unsigned long long)r.s,(unsigned long long)r.e);int of=open(out,O_CREAT|O_TRUNC|O_WRONLY,0600);if(of>=0){const size_t chunk=4*1024*1024;std::vector<uint8_t>x(chunk);for(uint64_t a=r.s;a<r.e;){size_t w=(size_t)std::min<uint64_t>(chunk,r.e-a);ssize_t g=pread(fd,x.data(),w,a);if(g<=0)break;write(of,x.data(),g);a+=g;}close(of);printf("DUMPED %s bytes=%llu\n",out,(unsigned long long)(r.e-r.s));fflush(stdout);}break;}
ov=std::min<size_t>(256,sz);memmove(b.data(),b.data()+sz-ov,ov);pos+=got;}}
close(fd);return 0;}
