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
static bool rs(int fd,uint64_t a,std::string&out){char q[128]={};ssize_t n=pread(fd,q,sizeof(q)-1,a);if(n<=0)return false;size_t z=0;while(z<(size_t)n&&q[z]>=0x20&&q[z]<0x7f)z++;if(z<4)return false;out.assign(q,z);return true;}
int main(int ac,char**av){int pid=atoi(av[1]);std::string ps="/proc/"+std::to_string(pid);FILE*f=fopen((ps+"/maps").c_str(),"r");std::vector<M>ms;char line[900],per[5]={},p[600]={};unsigned long long s,e;while(fgets(line,sizeof(line),f)){int n=sscanf(line,"%llx-%llx %4s %*s %*s %*s %599[\n]",&s,&e,per,p);if(n>=3&&per[0]=='r'&&e-s>=88&&e-s<250ull*1024*1024)ms.push_back({s,e});}fclose(f);int fd=open((ps+"/mem").c_str(),O_RDONLY);if(fd<0)return 1;std::vector<uint8_t>b(4*1024*1024+88);for(auto&m:ms){uint64_t pos=m.s;size_t ov=0;while(pos<m.e){size_t w=std::min<uint64_t>(4ull*1024*1024,m.e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g;for(size_t o=0;o+88<=n;o+=8){uint64_t*q=(uint64_t*)(b.data()+o);if(!q[0]||!own(ms,q[0]))continue;std::string name;if(!rs(fd,q[0],name)||name!="mscorlib.dll")continue;if(q[1]==0||q[1]>20000000||!q[2]||!own(ms,q[2])||q[3]>5000000)continue;printf("MSCMODULE @0x%llx q0=0x%llx q1=%llu q2=0x%llx q3=%llu q4=0x%llx q5=%llu q6=0x%llx q7=0x%llx q8=0x%llx q9=0x%llx q10=0x%llx\n",(unsigned long long)(pos+o-ov),(unsigned long long)q[0],(unsigned long long)q[1],(unsigned long long)q[2],(unsigned long long)q[3],(unsigned long long)q[4],(unsigned long long)q[5],(unsigned long long)q[6],(unsigned long long)q[7],(unsigned long long)q[8],(unsigned long long)q[9],(unsigned long long)q[10]);fflush(stdout);}ov=88;memmove(b.data(),b.data()+n-ov,ov);pos+=g;}}close(fd);}