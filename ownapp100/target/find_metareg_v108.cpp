#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
struct M{uint64_t s,e;};
static const M*own(const std::vector<M>&m,uint64_t v){for(auto&a:m)if(v>=a.s&&v<a.e)return &a;return nullptr;}
static bool sm(uint64_t x,uint64_t lim){return x<=lim&&(x>>32)==0;}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[900],per[5]={},p[600]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r'&&e-s>=112&&e-s<300ull*1024*1024)ms.push_back({s,e});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;std::vector<uint8_t>b(4*1024*1024+112);int hits=0;
for(auto&m:ms){uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+112<=n;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);uint64_t nt=q[4];if(nt<1000||nt>10000000||q[6]!=nt||q[8]!=nt)continue;if(!sm(q[0],10000000)||!sm(q[2],10000000)||!sm(q[12],10000000)||!sm(q[10],100000000))continue;bool ok=1;for(int i:{1,3,5,7,9,11,13})if(!q[i]||!own(ms,q[i])){ok=0;break;}if(!ok)continue;int score=0;for(int i:{1,3,5,7,9,11,13}){const M*pm=own(ms,q[i]);if(pm)score+=pm->e-pm->s<50ull*1024*1024?2:1;}printf("METAREG score=%d @0x%llx nt=%llu gc=%llu gi=%llu mu=%llu ai=%llu\n",(int)score,(unsigned long long)(pos+o-ov),(unsigned long long)nt,(unsigned long long)q[0],(unsigned long long)q[2],(unsigned long long)q[10],(unsigned long long)q[12]);for(int i=0;i<14;i++)printf("0x%llx%c",(unsigned long long)q[i],i==13?'\n':' ');fflush(stdout);if(++hits>=100)return 0;}ov=112;memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}printf("DONE %d\n",hits);}