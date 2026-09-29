#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
struct M{uint64_t s,e;bool x,w;std::string p;};
static const M* own(const std::vector<M>&ms,uint64_t v){for(auto&a:ms)if(v>=a.s&&v<a.e)return &a;return nullptr;}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[1024],per[5]={},p[700]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %699[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r')ms.push_back({s,e,per[2]=='x',per[1]=='w',n>=5?p:""});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;auto readstr=[&](uint64_t a,std::string&out){char z[160];ssize_t g=pread(fd,z,sizeof(z)-1,a);if(g<=0)return false;size_t n=0;while(n<(size_t)g&&z[n]>=0x20&&z[n]<0x7f)n++;if(n<4)return false;out.assign(z,n);return true;};std::vector<uint8_t>b(4*1024*1024+136);for(auto&m:ms){if(m.e-m.s<136||m.e-m.s>250ull*1024*1024)continue;uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+136<=n;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);if(!q[0]||!own(ms,q[0]))continue;std::string name;if(!readstr(q[0],name)||name.size()>120||name.find(".dll")!=name.size()-4)continue;if(q[1]>10000000||(q[1]&&!own(ms,q[2])))continue;if(q[3]>2000000||(q[3]&&!own(ms,q[4])))continue;if(q[5]&&!own(ms,q[5]))continue;if(q[6]>2000000||(q[6]&&!own(ms,q[7])))continue;if(q[8]>2000000||(q[8]&&!own(ms,q[9])))continue;if(q[10]>2000000||(q[10]&&!own(ms,q[11])))continue;bool good=true;for(int i: {12,13,14,15,16})if(q[i]&&!own(ms,q[i]))good=false;if(!good)continue;printf("MODULE 0x%llx name=%s\n",(unsigned long long)(pos+o-ov),name.c_str());for(int i=0;i<17;i++)printf("  q%-2d 0x%llx\n",i,(unsigned long long)q[i]);fflush(stdout);}ov=std::min<size_t>(136,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}close(fd);return 0;}