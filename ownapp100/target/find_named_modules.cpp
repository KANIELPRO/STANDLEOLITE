#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
struct M{uint64_t s,e;};
static const M*own(const std::vector<M>&m,uint64_t v){for(auto&a:m)if(v>=a.s&&v<a.e)return &a;return nullptr;}
static bool rs(int fd,uint64_t a,std::string&out){char q[160]={};ssize_t n=pread(fd,q,sizeof(q)-1,a);if(n<=0)return false;size_t z=0;while(z<(size_t)n&&q[z]>=0x20&&q[z]<0x7f)z++;if(z<4)return false;out.assign(q,z);return true;}
int main(int ac,char**av){if(ac<2)return 2;int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");std::vector<M>ms;char line[900],per[5]={},p[600]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r')ms.push_back({s,e});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 3;const uint64_t S=0x6f5ecc6000ULL,E=0x6f5f344000ULL;size_t N=E-S;std::vector<uint8_t>b(N);pread(fd,b.data(),N,S);for(size_t o=0;o+88<=N;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);std::string name;if(!q[0]||!own(ms,q[0])||!rs(fd,q[0],name))continue;if(name!="mscorlib.dll"&&name!="Assembly-CSharp.dll"&&name!="Gameplay.Bomb.dll")continue;if(q[1]>20000000||!q[2]||!own(ms,q[2])||q[3]>5000000)continue;printf("MODULE 0x%llx %s q0=0x%llx q1=%llu q2=0x%llx q3=%llu q4=0x%llx q5=%llu q6=0x%llx q7=0x%llx q8=0x%llx q9=0x%llx q10=0x%llx\n",(unsigned long long)(S+o),name.c_str(),(unsigned long long)q[0],(unsigned long long)q[1],(unsigned long long)q[2],(unsigned long long)q[3],(unsigned long long)q[4],(unsigned long long)q[5],(unsigned long long)q[6],(unsigned long long)q[7],(unsigned long long)q[8],(unsigned long long)q[9],(unsigned long long)q[10]);}}
