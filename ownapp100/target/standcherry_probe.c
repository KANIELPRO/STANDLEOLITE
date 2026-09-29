#include <jni.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
typedef struct { uint64_t s,e; int x,w; } Map;
static Map maps[128]; static int mc;
static const Map* own(uint64_t v){for(int i=0;i<mc;i++)if(v>=maps[i].s&&v<maps[i].e)return &maps[i];return 0;}
static int readstr(int fd,uint64_t a,char*out,size_t cap){char b[192];ssize_t n=pread(fd,b,sizeof(b)-1,a);if(n<=0)return 0;size_t i=0;while(i<(size_t)n&&b[i]>=0x20&&b[i]<0x7f)i++;if(i<4||i>=cap)return 0;b[i]=0;memcpy(out,b,i+1);return (int)i;}
static void dumpq(FILE*f,int fd,uint64_t a,int n,const char*tag){fprintf(f,"%s @0x%llx\n",tag,(unsigned long long)a);for(int i=0;i<n;i++){uint64_t v=0;if(pread(fd,&v,8,a+i*8)!=8)break;fprintf(f," +0x%02x = 0x%016llx\n",i*8,(unsigned long long)v);}fflush(f);}
static void* worker(void*arg){
(void)arg;sleep(10);
const char*dir="/sdcard/Android/data/com.stand.cherry.prod/files/standdump";
mkdir("/sdcard/Android/data/com.stand.cherry.prod",0771);mkdir("/sdcard/Android/data/com.stand.cherry.prod/files",0771);mkdir(dir,0771);
FILE*out=fopen("/sdcard/Android/data/com.stand.cherry.prod/files/standcherry_probe.txt","w");if(!out)return 0;fprintf(out,"PROBE_START\n");
FILE*mf=fopen("/proc/self/maps","r");if(!mf){fprintf(out,"MAP_FAIL\n");fclose(out);return 0;}
char line[1024],perm[8];unsigned long long s,e;int n;
while(fgets(line,sizeof(line),mf)&&mc<128){perm[0]=0;n=sscanf(line,"%llx-%llx %7s",&s,&e,perm);if(n>=3&&perm[0]=='r'&&(strstr(line,"libunity.so")||strstr(line,"[anon:.bss"))&&e>s)maps[mc++]=(Map){s,e,perm[2]=='x',perm[1]=='w'};}
fclose(mf);fprintf(out,"MAPS=%d\n",mc);fflush(out);
int fd=open("/proc/self/mem",O_RDONLY);if(fd<0){fprintf(out,"MEM_FAIL\n");fclose(out);return 0;}
uint8_t*buf=(uint8_t*)malloc(4*1024*1024+136);if(!buf){fclose(out);return 0;}int hits=0;
