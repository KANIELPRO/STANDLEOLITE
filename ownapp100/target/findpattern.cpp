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
int main(int argc,char**argv){
 int pid=atoi(argv[1]); std::ifstream mf("/proc/"+std::to_string(pid)+"/maps");
 std::string line,rg,perm,off,dev,ino,path; std::vector<R>rs;
 while(std::getline(mf,line)){std::istringstream is(line);is>>rg>>perm>>off>>dev>>ino;std::getline(is,path);while(!path.empty()&&path[0]==' ')path.erase(path.begin());if(perm.empty()||perm[0]!='r')continue;auto d=rg.find('-');uint64_t s=strtoull(rg.substr(0,d).c_str(),0,16),e=strtoull(rg.substr(d+1).c_str(),0,16);if(e-s>=4096&&(path.empty()||path.find("libunity.so")!=std::string::npos))rs.push_back({s,e,path});}
 int fd=open(("/proc/"+std::to_string(pid)+"/mem").c_str(),O_RDONLY);if(fd<0){perror("mem");return 1;}
 const uint8_t pat[]={0x00,0x60,0x8E,0x06,0x0B,0x02,0x00,0x00,0x10,0x01,0x50,0x22,0x0A,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3E,0x01,0x00,0x00,0x00,0x00,0x00,0xC0,0x3E,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xB0,0x4B,0x1F,0xF0,0x00,0x00,0x00,0x04};
 const uint8_t magic[]={0xAF,0x1B,0xB1,0xFA};
 std::vector<uint8_t>b(4*1024*1024+256);
 for(auto&r:rs){uint64_t pos=r.s;size_t ov=0;while(pos<r.e){size_t want=(size_t)std::min<uint64_t>(4*1024*1024,r.e-pos);ssize_t got=pread(fd,b.data()+ov,want,pos);if(got<=0)break;size_t sz=ov+got,a;if(hit(b.data(),sz,pat,sizeof(pat),a))printf("PATTERN addr=0x%llx map=0x%llx-0x%llx path=%s\n",(unsigned long long)(pos+a-ov),(unsigned long long)r.s,(unsigned long long)r.e,r.p.c_str());if(hit(b.data(),sz,magic,sizeof(magic),a)){printf("MAGIC addr=0x%llx map=0x%llx-0x%llx path=%s\n",(unsigned long long)(pos+a-ov),(unsigned long long)r.s,(unsigned long long)r.e,r.p.c_str());fflush(stdout);}ov=std::min<size_t>(256,sz);memmove(b.data(),b.data()+sz-ov,ov);pos+=got;}}
 close(fd);return 0;}