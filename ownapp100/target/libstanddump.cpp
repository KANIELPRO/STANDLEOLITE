#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <string>
#include <algorithm>
#include <vector>
static const uint8_t magic[]={0xAF,0x1B,0xB1,0xFA};
static const uint8_t pat[]={0x00,0x60,0x8E,0x06,0x0B,0x02,0x00,0x00,0x10,0x01,0x50,0x22,0x0A,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3E,0x01,0x00,0x00,0x00,0x00,0x00,0xC0,0x3E,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xB0,0x4B,0x1F,0xF0,0x00,0x00,0x00,0x04};
static bool hit(const uint8_t*b,size_t n,const uint8_t*p,size_t m,uint64_t&at){for(size_t i=0;i+m<=n;i++)if(!memcmp(b+i,p,m)){at=i;return true;}return false;}
static void dumpreg(int fd,uint64_t s,uint64_t e,const char*out){int of=open(out,O_CREAT|O_TRUNC|O_WRONLY,0644);if(of<0)return;std::vector<uint8_t>b(4*1024*1024);for(uint64_t p=s;p<e;){size_t w=std::min<uint64_t>(b.size(),e-p);ssize_t g=pread(fd,b.data(),w,p);if(g<=0)break;write(of,b.data(),g);p+=g;}close(of);}
static void* worker(void*){sleep(3);const char*dir="/data/user/0/com.stand.cherry.prod/files/standdump";mkdir(dir,0771);int fd=open("/proc/self/mem",O_RDONLY);if(fd<0)return 0;FILE*m=fopen("/proc/self/maps","r");if(!m){close(fd);return 0;}char line[1024];int seq=0;std::vector<uint8_t>b(4*1024*1024+128);
while(fgets(line,sizeof(line),m)){unsigned long long s,e;char perm[5]={},path[512]={};if(sscanf(line,"%llx-%llx %4s %*s %*s %*s %511[\n]",&s,&e,perm,path)<3)continue;if(perm[0]!='r'||e<=s||e-s>300*1024*1024)continue;uint64_t pos=s;size_t ov=0;bool ok=0;uint64_t ha=0;
while(pos<e){size_t w=std::min<uint64_t>(4*1024*1024,e-pos);ssize_t g=pread(fd,b.data()+ov,w,pos);if(g<=0)break;size_t n=ov+g,a;if(hit(b.data(),n,magic,4,a)||hit(b.data(),n,pat,sizeof(pat),a)||hit(b.data(),n,(const uint8_t*)"Assembly-CSharp.dll",18,a)||hit(b.data(),n,(const uint8_t*)"Axlebolt.Standoff",17,a)||hit(b.data(),n,(const uint8_t*)"global-metadata.dat",19,a)){ok=1;ha=pos+a-ov;break;}ov=std::min<size_t>(128,n);memmove(b.data(),b.data()+n-ov,ov);pos+=g;}
if(ok){char out[640];snprintf(out,sizeof(out),"%s/map-%02d-%llx-%llx.bin",dir,seq++,s,e);dprintf(2,"STANDDUMP HIT 0x%llx map 0x%llx-0x%llx %s\n",ha,s,e,path);dumpreg(fd,s,e,out);}}
fclose(m);close(fd);return 0;}
__attribute__((constructor))static void start(){pthread_t t;pthread_create(&t,0,worker,0);pthread_detach(t);}
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM*,void*){return JNI_VERSION_1_6;}