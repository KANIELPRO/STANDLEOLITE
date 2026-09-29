#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sstream>
#include <fstream>
#include <algorithm>
#include <vector>
struct R{uint64_t s,e,off; std::string perms,path;};
static bool contains(const uint8_t* b,size_t n,const uint8_t* p,size_t m,size_t &at){ if(!m||n<m)return false; for(size_t i=0;i+m<=n;i++){if(!memcmp(b+i,p,m)){at=i;return true;}}return false;}
int main(int argc,char**argv){
 int pid=argc>1?atoi(argv[1]):0; if(!pid){fprintf(stderr,"pid\n");return 2;}
 std::string mp="/proc/"+std::to_string(pid)+"/maps";
 std::ifstream mf(mp); if(!mf){perror("maps");return 1;}
 std::vector<R> rs; std::string line;
 while(std::getline(mf,line)){
   std::istringstream is(line); std::string rg,perm,off,dev,inode; if(!(is>>rg>>perm>>off>>dev>>inode))continue;
   std::string path; std::getline(is,path); while(!path.empty()&&path[0]==' ')path.erase(path.begin());
   if(perm.size()<4 || perm[0]!='r')continue;
   auto dash=rg.find('-'); if(dash==std::string::npos)continue;
   uint64_t s=strtoull(rg.substr(0,dash).c_str(),nullptr,16), e=strtoull(rg.substr(dash+1).c_str(),nullptr,16);
   uint64_t fo=strtoull(off.c_str(),nullptr,16);
   if(e<=s)continue;
   rs.push_back({s,e,fo,path});
 }
 int mem=open((std::string("/proc/")+std::to_string(pid)+"/mem").c_str(),O_RDONLY);
 if(mem<0){perror("mem");return 1;}
 const uint8_t magic[]={0xAF,0x1B,0xB1,0xFA}; const char* needle="Assembly-CSharp.dll";
 std::vector<uint8_t> buf(4*1024*1024+64); uint64_t hits=0;
 for(auto&r:rs){
   uint64_t pos=r.s; size_t overlap=0;
   while(pos<r.e){
     size_t want=(size_t)std::min<uint64_t>(4*1024*1024,r.e-pos);
     ssize_t got=pread(mem,buf.data()+overlap,want,(off_t)pos);
     if(got<=0)break;
     size_t n=overlap+(size_t)got; size_t at;
     if(contains(buf.data(),n,magic,4,at)){printf("MAGIC addr=0x%llx map=0x%llx-0x%llx path=%s\n",(unsigned long long)(pos+at-overlap),(unsigned long long)r.s,(unsigned long long)r.e,r.path.c_str()); hits++;}
     if(contains(buf.data(),n,(const uint8_t*)needle,strlen(needle),at)){printf("NAME addr=0x%llx map=0x%llx-0x%llx path=%s\n",(unsigned long long)(pos+at-overlap),(unsigned long long)r.s,(unsigned long long)r.e,r.path.c_str());}
     overlap = std::min<size_t>(64,n); memmove(buf.data(),buf.data()+n-overlap,overlap);
     pos += got;
   }
 }
 close(mem); printf("DONE maps=%zu magic_hits=%llu\n",rs.size(),(unsigned long long)hits); return 0;
}
