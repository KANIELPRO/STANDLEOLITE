#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <algorithm>
struct M{uint64_t s,e;std::string p;};
int main(int ac,char**av){if(ac<3)return 2;int pid=atoi(av[1]);std::vector<uint64_t>ts;for(int i=2;i<ac;i++)ts.push_back(strtoull(av[i],0,16));std::unordered_map<uint64_t,int>idx;for(int i=0;i<(int)ts.size();i++)idx[ts[i]]=i;std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[900],per[5]={},p[600]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r'&&e-s>=8&&e-s<300ull*1024*1024)ms.push_back({s,e,n>=5?p:""});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;std::vector<uint8_t>b(4*1024*1024+8);for(auto&m:ms){uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+8<=n;o+=8){uint64_t v=*reinterpret_cast<const uint64_t*>(b.data()+o);auto it=idx.find(v);if(it!=idx.end())printf("REF target=0x%llx at=0x%llx map=0x%llx-0x%llx %s\n",(unsigned long long)v,(unsigned long long)(pos+o-ov),(unsigned long long)m.s,(unsigned long long)m.e,m.p.c_str());}ov=8;memmove(b.data(),b.data()+n-8,8);pos+=g;}}close(fd);}