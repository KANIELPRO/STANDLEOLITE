#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
int main(int ac,char**av){
 if(ac<3)return 2;int pid=atoi(av[1]);const char*needle=av[2];size_t nl=strlen(needle);
 std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;
 std::vector<std::pair<uint64_t,uint64_t>> rs;char line[700];unsigned long long s,e;char per[5]={};
 while(fgets(line,sizeof(line),f)){if(sscanf(line,"%llx-%llx %4s",&s,&e,per)==3&&per[0]=='r'&&e>s&&e-s<500ull*1024*1024)rs.push_back({s,e});}fclose(f);
 int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;std::vector<uint8_t>b(4*1024*1024+256);int hits=0;
 for(auto r:rs){uint64_t pos=r.first;size_t ov=0;while(pos<r.second){size_t w=std::min<uint64_t>(4ull*1024*1024,r.second-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;
  for(size_t o=0;o+nl<=n;o++){if(memcmp(b.data()+o,needle,nl)==0){uint64_t va=pos+o-ov;printf("HIT 0x%llx map 0x%llx-0x%llx\n",(unsigned long long)va,(unsigned long long)r.first,(unsigned long long)r.second);fflush(stdout);if(++hits>=100)return 0;}}
  ov=std::min<size_t>(nl-1,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;
 }}
 close(fd);printf("DONE %d\n",hits);return 0;}