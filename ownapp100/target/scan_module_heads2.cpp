#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
struct M{uint64_t s,e;bool r,x,w;std::string p;};
static const M* own(const std::vector<M>&ms,uint64_t v){for(auto&a:ms)if(v>=a.s&&v<a.e)return &a;return nullptr;}
int main(int ac,char**av){
 if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);
 FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[1024],per[5]={},p[700]={};unsigned long long s,e;
 while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %699[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r')ms.push_back({s,e,1,per[2]=='x',per[1]=='w',n>=5?p:""});}fclose(f);
 int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;
 auto readstr=[&](uint64_t a,std::string&out){char q[180];ssize_t n=pread(fd,q,sizeof(q)-1,a);if(n<=0)return false;size_t i=0;while(i<(size_t)n&&q[i]>=0x20&&q[i]<0x7f)i++;if(i<4)return false;out.assign(q,i);return true;};
 uint64_t S=0x6f5ecc6000ULL,E=0x6f5f344000ULL;size_t N=E-S;std::vector<uint8_t>b(N+8);if(pread(fd,b.data(),N,S)!=(ssize_t)N)return 5;
 int hits=0;for(size_t o=0;o+88<=N;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);std::string name;
  if(!q[0]||!own(ms,q[0])||!readstr(q[0],name)||name.size()>150||name.find(".dll")!=name.size()-4)continue;
  if(q[1]==0||q[1]>20000000||!q[2]||!own(ms,q[2]))continue;
  if(q[3]>5000000|| (q[4]&&!own(ms,q[4])))continue; if(q[5]>5000000|| (q[6]&&!own(ms,q[6])))continue;
  if(q[7]&&!own(ms,q[7]))continue; if(q[8]&&!own(ms,q[8]))continue; if(q[9]&&!own(ms,q[9]))continue; if(q[10]&&!own(ms,q[10]))continue;
  printf("MODULE @0x%llx name=%s\n",(unsigned long long)(S+o),name.c_str()); for(int i=0;i<=10;i++)printf(" q%d=0x%llx",i,(unsigned long long)q[i]);printf("\n");fflush(stdout);if(++hits>=80)break;
 }
 close(fd);return 0;
}