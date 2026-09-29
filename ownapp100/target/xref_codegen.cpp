#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
struct M{uint64_t s,e;bool x,w;char line[700];};
static const M* own(const std::vector<M>&ms,uint64_t v){for(auto&a:ms)if(v>=a.s&&v<a.e)return &a;return nullptr;}
static bool inx(const std::vector<M>&ms,uint64_t v){auto*m=own(ms,v);return m&&m->x;}
static bool inr(const std::vector<M>&ms,uint64_t v){return own(ms,v)!=nullptr;}
static void printCandidate(int fd,const std::vector<M>&ms,uint64_t va,const char*tag){
 uint64_t q[17];if(pread(fd,q,sizeof(q),va)!=sizeof(q))return;
 auto okc=[&](uint64_t v,uint64_t lim){return (v<=lim)&&((v>>32)==0);};
 int score=0;
 if(q[1]>0&&q[1]<2000000)score+=3;
 if(q[2]&&inx(ms,q[2]))score+=5;
 if(q[3]<2000000)score+=2;
 if(q[4]&&inr(ms,q[4]))score+=2;
 if(q[5]&&inr(ms,q[5]))score+=2;
 if(q[6]<2000000)score+=2;
 if(q[7]&&inr(ms,q[7]))score+=2;
 if(q[8]<2000000)score+=2;
 if(q[9]&&inr(ms,q[9]))score+=2;
 if(q[10]<2000000)score+=2;
 if(q[11]&&inr(ms,q[11]))score+=2;
 if(q[12]==0||inr(ms,q[12]))score+=1;
 if(q[13]==0||inx(ms,q[13]))score+=1;
 if(q[14]==0||inr(ms,q[14]))score+=1;
 if(q[15]==0||inr(ms,q[15]))score+=1;
 if(q[16]==0||inr(ms,q[16]))score+=1;
 if(score<12)return;
 printf("CAND tag=%s score=%d @0x%llx\n",tag,score,(unsigned long long)va);
 for(int i=0;i<17;i++)printf("  q%d=0x%llx",i,(unsigned long long)q[i]);printf("\n");
 if(q[2])printf("  q2exec=%d q4=%d q5=%d q7=%d q9=%d q11=%d\n",inx(ms,q[2]),inr(ms,q[4]),inr(ms,q[5]),inr(ms,q[7]),inr(ms,q[9]),inr(ms,q[11]));
 fflush(stdout);
}
int main(){
 int pid=6048;std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 1;
 std::vector<M>ms;char line[700],per[5];unsigned long long s,e;while(fgets(line,sizeof(line),f)){if(sscanf(line,"%llx-%llx %4s",&s,&e,per)==3&&per[0]=='r'){M m{(uint64_t)s,(uint64_t)e,per[2]=='x',per[1]=='w',{0}};strncpy(m.line,line,699);ms.push_back(m);}}fclose(f);
 int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 2;
 const char*names[]={"mscorlib.dll","Assembly-CSharp.dll","Axlebolt.Standoff.Game.dll","Axlebolt.Standoff.Gameplay.Bomb.dll"};
 std::vector<uint64_t>strs;
 std::vector<uint8_t>b(4*1024*1024+256);
 for(auto&m:ms){if(m.e-m.s<16||m.e-m.s>500ull*1024*1024)continue;uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(int ni=0;ni<4;ni++){size_t nl=strlen(names[ni]);for(size_t o=0;o+nl<=n;o++){if(!memcmp(b.data()+o,names[ni],nl)){uint64_t va=pos+o-ov;strs.push_back(va);}}}ov=std::min<size_t>(256,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}
 std::sort(strs.begin(),strs.end());strs.erase(std::unique(strs.begin(),strs.end()),strs.end());printf("strings=%zu\n",strs.size());
 for(uint64_t st:strs){uint8_t p8[8];memcpy(p8,&st,8);for(auto&m:ms){uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+8<=n;o+=8){if(!memcmp(b.data()+o,p8,8)){uint64_t va=pos+o-ov;printCandidate(fd,ms,va,"xref");}}ov=std::min<size_t>(8,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}}
 close(fd);return 0;
}