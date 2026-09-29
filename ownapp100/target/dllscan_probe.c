#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

typedef struct { uint64_t s,e; char p[5],path[512]; } Map;

static int parse_maps(Map*ms,int max){
    FILE*f=fopen("/proc/self/maps","r"); if(!f)return -1;
    char line[1024],per[8],path[512]; unsigned long long s,e,o; int nmap=0;
    while(fgets(line,sizeof(line),f)&&nmap<max){
        per[0]=path[0]=0;
        int n=sscanf(line,"%llx-%llx %7s %llx %*s %*s %511[^\n]",&s,&e,per,&o,path);
        if(n<4||per[0]!='r'||e<=s)continue;
        Map*m=&ms[nmap++];m->s=s;m->e=e;
        snprintf(m->p,sizeof(m->p),"%s",per);
        snprintf(m->path,sizeof(m->path),"%s",n>=5?path:"");
    }
    fclose(f);return nmap;
}static void*worker(void*unused){
    (void)unused;sleep(8);
    const char*dir="/sdcard/Android/data/com.stand.cherry.prod/files/dllscan";
    mkdir("/sdcard/Android/data/com.stand.cherry.prod/files",0771);
    mkdir(dir,0771);
    FILE*r=fopen("/sdcard/Android/data/com.stand.cherry.prod/files/dllscan/report.txt","w");
    if(!r)return 0;
    Map ms[512];int nm=parse_maps(ms,512);
    fprintf(r,"DLLSCAN PID=%d MAPS=%d\n",getpid(),nm);fflush(r);
    int fd=open("/proc/self/mem",O_RDONLY);if(fd<0)return 0;
    uint8_t*b=(uint8_t*)malloc(4*1024*1024+64); if(!b){close(fd);return 0;}
    int total=0;
    for(int mi=0;mi<nm&&total<1500;mi++){
        uint64_t s=ms[mi].s,e=ms[mi].e;
        if(e-s>128ull*1024*1024)continue;
        if(ms[mi].path[0]&&!strstr(ms[mi].path,"[anon")&&!strstr(ms[mi].path,"libunity.so"))continue;
        uint64_t pos=s;size_t ov=0;
        while(pos<e&&total<1500){
            size_t w=(size_t)((e-pos)>4ull*1024*1024?4ull*1024*1024:(e-pos));
            ssize_t g=pread(fd,b+ov,w,(off_t)pos);if(g<=0)break;
            size_t n=ov+(size_t)g;
            for(size_t i=0;i+4<n&&total<1500;i++){
                if(b[i]!='.'||b[i+1]!='d'||b[i+2]!='l'||b[i+3]!='l')continue;
                size_t j=i;
                while(j>0&&b[j-1]>=0x20&&b[j-1]<0x7f&&i-j<96)j--;
                size_t k=i+4;
                while(k<n&&b[k]>=0x20&&b[k]<0x7f&&k-i<160)k++;
                if(k<=i+4)continue;
                char str[192];size_t len=k-j;if(len>=sizeof(str))len=sizeof(str)-1;
                memcpy(str,b+j,len);str[len]=0;
                uint64_t a=pos+j-ov;
                fprintf(r,"DLL 0x%llx map=0x%llx-0x%llx %s :: %s\n",
                        (unsigned long long)a,(unsigned long long)s,(unsigned long long)e,ms[mi].p,str);
                fflush(r);total++;
            }
            ov=n<64?n:64;if(ov)memmove(b,b+n-ov,ov);pos+=g;
        }
    }
    fprintf(r,"TOTAL=%d\n",total);fflush(r);
    free(b);close(fd);fclose(r);return 0;
}
__attribute__((constructor))static void init(){pthread_t t;if(!pthread_create(&t,0,worker,0))pthread_detach(t);}
