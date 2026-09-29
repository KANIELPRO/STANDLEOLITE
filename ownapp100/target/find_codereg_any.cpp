#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
struct M{uint64_t s,e;bool w,x;};
static const M*own(const std::vector<M>&m,uint64_t v){for(auto&a:m)if(v>=a.s&&v<a.e)return &a;return nullptr;}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[900],per[5]={},p[600]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r'&&e-s>=136)ms.push_back({s,e,per[1]=='w',per[2]=='x'});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;std::vector<uint8_t>b(4*1024*1024+136);
for(auto&m:ms){if(m.e-m.s>350ull*1024*1024)continue;uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+136<=n;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);if(q[15]<100||q[15]>1000||!q[16]||!own(ms,q[16]))continue;const M*pm=own(ms,q[16]);if(q[16]+q[15]*8>pm->e)continue;int good=0;for(int i=0;i<12;i++){uint64_t v;if(pread(fd,&v,8,q[16]+i*8)!=8)break;if(own(ms,v))good++;}if(good<8)continue;auto vp=[&](int c,int p){return q[c]<100000000&&(!q[p]||own(ms,q[p]));};if(!vp(0,1)||!vp(2,3)||!own(ms,q[4])||!vp(5,6)||!vp(7,8)||!own(ms,q[9])||!own(ms,q[10])||!vp(11,12)||!vp(13,14))continue;printf("CODEREG @0x%llx modules=%llu ptr=0x%llx mapw=%d good=%d\n",(unsigned long long)(pos+o-ov),(unsigned long long)q[15],(unsigned long long)q[16],m.w,good);for(int i=0;i<17;i++)printf("0x%llx%c",(unsigned long long)q[i],i==16?'\n':' ');fflush(stdout);}ov=std::min<size_t>(136,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}close(fd);}