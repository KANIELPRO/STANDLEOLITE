#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
struct R{uint64_t s,e;std::string p;};
static bool hit(const uint8_t*b,size_t n,const uint8_t*p,size_t m,size_t&a){for(size_t i=0;i+m<=n;i++)if(!memcmp(b+i,p,m)){a=i;return true;}return false;}
static void dump(int fd,uint64_t s,uint64_t e,const char*out){int of=open(out,O_CREAT|O_TRUNC|O_WRONLY,0600);if(of<0)return;std::vector<uint8_t>x(4*1024*1024);for(uint64_t p=s;p<e;){size_t w=std::min<uint64_t>(x.size(),e-p);ssize_t g=pread(fd,x.data(),w,p);if(g<=0)break;write(of,x.data(),g);p+=g;}close(of);}
int main(int argc,char**argv){
 int pid=atoi(argv[1]);std::string cmd="showmap -av "+std::to_string(pid);FILE*fp=popen(cmd.c_str(),"r");if(!fp){perror("showmap");return 1;}std::vector<R>rs;char line[1024];fgets(line,sizeof(line),fp);
 while(fgets(line,sizeof(line),fp)){unsigned long long s,e;char perm[5]={};char path[600]={};if(sscanf(line,"%llx %llx %*s %*s %*s %*s %511[\n]",&s,&e,path)<2)continue;char*pp=strstr(line,"r--");char*px=strstr(line,"r-x");char*pw=strstr(line,"rw-");if(!pp&&!px&&!pw)continue;rs.push_back({s,e,std::string(line)});}pclose(fp);
 int fd=open(("/proc/"+std::to_string(pid)+"/mem").c_str(),O_RDONLY);if(fd<0){perror("mem");return 2;}const uint8_t magic[]={0xAF,0x1B,0xB1,0xFA};std::vector<uint8_t>b(4*1024*1024+128);int nfound=0;
 for(auto&r:rs){if(r.e<=r.s||r.e-r.s>400*1024*1024)continue;uint64_t pos=r.s;size_t ov=0;while(pos<r.e){size_t w=std::min<uint64_t>(4*1024*1024,r.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g,a;bool ok=false;
 if(hit(b.data(),n,magic,4,a)||hit(b.data(),n,(const uint8_t*)"Assembly-CSharp.dll",18,a)||hit(b.data(),n,(const uint8_t*)"Axlebolt.Standoff",17,a)||hit(b.data(),n,(const uint8_t*)"global-metadata.dat",19,a)){ok=true;uint64_t va=pos+a-ov;char out[160];snprintf(out,sizeof(out),"/data/local/tmp/showhit-%llx-%llx.bin",r.s,r.e);printf("HIT 0x%llx map=0x%llx-0x%llx %s",va,r.s,r.e,r.p.c_str());dump(fd,r.s,r.e,out);nfound++;break;}
 ov=std::min<size_t>(128,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}
 printf("DONE maps=%zu hits=%d\n",rs.size(),nfound);close(fd);return 0;}