#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
struct M{uint64_t s,e;};
static const M*own(const std::vector<M>&ms,uint64_t v){for(auto&a:ms)if(v>=a.s&&v<a.e)return &a;return nullptr;}
static bool rdstr(int fd,uint64_t a,std::string&out){char q[160]={};ssize_t n=pread(fd,q,sizeof(q)-1,a);if(n<=0)return false;size_t z=0;while(z<(size_t)n&&q[z]>=0x20&&q[z]<0x7f)z++;if(z<4)return false;out.assign(q,z);return true;}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");if(!f)return 3;std::vector<M>ms;char line[900],per[5]={},p[600]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r')ms.push_back({s,e});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 4;const uint64_t S=0x6f5ecc6000ULL,E=0x6f5f344000ULL;size_t N=E-S;std::vector<uint8_t>b(N);if(pread(fd,b.data(),N,S)!=(ssize_t)N)return 5;int hits=0;for(size_t o=0;o+88<=N;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);if(!q[0]||!own(ms,q[0]))continue;std::string name;if(!rdstr(fd,q[0],name)||name.size()>150||name.find(".dll")!=name.size()-4)continue;if(q[1]==0||q[1]>20000000||!q[2]||!own(ms,q[2])||q[3]>5000000)continue;if(q[4]&&!own(ms,q[4])||q[5]>5000000||q[6]&&!own(ms,q[6])||q[7]&&!own(ms,q[7])||q[8]&&!own(ms,q[8])||q[9]&&!own(ms,q[9])||q[10]&&!own(ms,q[10]))continue;if(q[9]||q[10]){printf("NONZERO MODULE @0x%llx %s\n",(unsigned long long)(S+o),name.c_str());for(int i=0;i<11;i++)printf("0x%llx%c",(unsigned long long)q[i],i==10?'\n':' ');fflush(stdout);if(++hits>=100)break;}}printf("DONE hits=%d\n",hits);close(fd);return 0;}