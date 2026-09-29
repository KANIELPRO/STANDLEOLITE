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
static const M*own(const std::vector<M>&m,uint64_t v){for(auto&a:m)if(v>=a.s&&v<a.e)return &a;return nullptr;}
static bool sm(uint64_t x,uint64_t lim){return x<=lim&&(x>>32)==0;}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[1024];while(fgets(line,sizeof(line),f)){unsigned long long s,e;char per[5]={},p[700]={};int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %699[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r')ms.push_back({s,e,per[2]=='x',per[1]=='w',n>=5?p:""});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;std::vector<uint8_t>b(4*1024*1024+16);
for(auto&m:ms){if(m.e-m.s<128||m.e-m.s>250ull*1024*1024)continue;uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t want=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,want,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+128<=n;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);const uint64_t lims[]={2000000,5000000,5000000,5000000,5000000,10000000,10000000,100000000};int good=0;bool ok=1;for(int i=0;i<8;i++){if(!sm(q[i*2],lims[i])){ok=0;break;}if(q[i*2]){if(!q[i*2+1]||!own(ms,q[i*2+1])){ok=0;break;}good++;}}if(!ok||good<6)continue;int score=good*10;for(int i=0;i<8;i++){if(q[i*2]&&own(ms,q[i*2+1])&&!own(ms,q[i*2+1])->x)score+=2;if(q[i*2]>10000&&q[i*2]<1000000)score+=2;}uint64_t va=pos+o-ov;printf("META score=%d @0x%llx map=0x%llx-0x%llx\n  ",score,(unsigned long long)va,(unsigned long long)m.s,(unsigned long long)m.e);for(int i=0;i<8;i++)printf("%s%llu/0x%llx",(i?" ":""),(unsigned long long)q[i*2],(unsigned long long)q[i*2+1]);printf("\n");fflush(stdout);}ov=std::min<size_t>(16,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}close(fd);}