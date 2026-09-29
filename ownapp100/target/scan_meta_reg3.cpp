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
static bool sm(uint64_t x,uint64_t lim){return x&&x<=lim&&(x>>32)==0;}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[1024];while(fgets(line,sizeof(line),f)){unsigned long long s,e;char per[5]={},p[700]={};int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %699[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r'&&std::string(p).find("libunity.so")!=std::string::npos)ms.push_back({s,e,per[2]=='x',per[1]=='w',n>=5?p:""});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;std::vector<uint8_t>b(4*1024*1024+16);
for(auto&m:ms){uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+128<=n;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);if(!sm(q[0],2000000)||!sm(q[2],5000000)||!sm(q[6],10000000)||!sm(q[8],10000000)||!sm(q[10],10000000)||!sm(q[12],10000000)||!sm(q[14],10000000))continue;bool ok=1;for(int i=0;i<8;i++){if(q[i*2+1] && !own(ms,q[i*2+1])){ok=0;break;}}if(!ok)continue;if(q[7]<q[5]||q[9]<q[7]){}int rel=0;if(q[6]<=q[8]+1000000&&q[6]+1000000>=q[8])rel+=3;if(q[10]<=q[8]+1000000&&q[10]+1000000>=q[8])rel+=3;if(q[12]<=q[8]+1000000&&q[12]+1000000>=q[8])rel+=2;printf("CAND rel=%d @0x%llx\n  ",rel,(unsigned long long)(pos+o-ov));for(int i=0;i<8;i++)printf("%s%llu/0x%llx",(i?" ":""),(unsigned long long)q[i*2],(unsigned long long)q[i*2+1]);printf("\n");fflush(stdout);}ov=std::min<size_t>(16,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}close(fd);}