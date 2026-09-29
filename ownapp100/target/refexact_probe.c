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
static uint64_t untag(uint64_t x){ return x & 0x00ffffffffffffffULL; }
static int parse_maps(Map*ms,int max){
    FILE*f=fopen("/proc/self/maps","r");if(!f)return -1;
    char line[1024],per[8],path[512];unsigned long long s,e,o;int nmap=0;
    while(fgets(line,sizeof(line),f)&&nmap<max){
        per[0]=path[0]=0;
        int n=sscanf(line,"%llx-%llx %7s %llx %*s %*s %511[^\n]",&s,&e,per,&o,path);
        if(n<4||per[0]!='r'||e<=s)continue;
        Map*m=&ms[nmap++];m->s=s;m->e=e;
        snprintf(m->p,sizeof(m->p),"%s",per);
        snprintf(m->path,sizeof(m->path),"%s",n>=5?path:"");
    }
    fclose(f);return nmap;
}
static const Map*owner(Map*ms,int nm,uint64_t a){
    uint64_t u=untag(a);
    for(int i=0;i<nm;i++)if(u>=ms[i].s&&u<ms[i].e)return &ms[i];
    return 0;
}
static int rd(int fd,uint64_t a,void*out,size_t n){
    return pread(fd,out,n,(off_t)untag(a))==(ssize_t)n;
}static int str_ok(int fd,uint64_t a,char*out,size_t cap){
    if(!a)return 0;ssize_t g=pread(fd,out,cap-1,(off_t)untag(a));if(g<=0)return 0;
    size_t i=0;while(i<(size_t)g&&out[i]>=0x20&&out[i]<0x7f)i++;
    if(i<4)return 0;out[i]=0;return (int)i;
}
static int dllname(const char*s){
    size_t n=strlen(s);return n>=4&&!strcmp(s+n-4,".dll");
}
static int image_check(int fd,Map*ms,int nm,uint64_t a,FILE*r,int verbose){
    uint64_t q[11]={0};if(!rd(fd,a,q,sizeof(q)))return 0;
    uint64_t q0=untag(q[0]);if(q0!=untag(a))return 0;
    if(!owner(ms,nm,q0))return 0;
    char n0[160]={0},n1[160]={0};
    if(!str_ok(fd,q0,n0,sizeof(n0))||!dllname(n0))return 0;
    if(q[1]&&!str_ok(fd,q[1],n1,sizeof(n1)))return 0;
    if(q[3]>1000000||q[4]>q[3]||q[5]>1000000)return 0;
    if(q[8]&&!owner(ms,nm,q[8]))return 0;
    fprintf(r,"IMAGE_CAND 0x%llx name=%s nameNoExt=%s typeCount=%llu exported=%llu codeGen=0x%llx token=0x%llx\n",
            (unsigned long long)a,n0,n1,(unsigned long long)q[3],
            (unsigned long long)q[4],(unsigned long long)q[8],
            (unsigned long long)q[9]);
    for(int i=0;i<11;i++)fprintf(r,"  iq%d=0x%llx\n",i,(unsigned long long)q[i]);
    fflush(r);return 1;
}
static void*worker(void*unused){
    (void)unused;sleep(8);
    const char*dir="/sdcard/Android/data/com.stand.cherry.prod/files/refexact";
    mkdir("/sdcard/Android/data/com.stand.cherry.prod/files",0771);
    mkdir(dir,0771);
    FILE*r=fopen("/sdcard/Android/data/com.stand.cherry.prod/files/refexact/report.txt","w");
    if(!r)return 0;
    Map ms[1024];int nm=parse_maps(ms,1024);
    fprintf(r,"REFEXACT PID=%d MAPS=%d\n",getpid(),nm);fflush(r);
    int fd=open("/proc/self/mem",O_RDONLY);if(fd<0)return 0;
    const char*needles[]={"Assembly-CSharp.dll","Axlebolt.Standoff.Game.dll",
                          "Gameplay.Bomb.dll","UnityEngine.CoreModule.dll",
                          "global-metadata.dat"};
    uint64_t targets[32];const char*tn[32];int tc=0;
    uint8_t*b=(uint8_t*)malloc(4*1024*1024+128);if(!b){close(fd);fclose(r);return 0;}    for(int ni=0;ni<5;ni++){
        size_t pn=strlen(needles[ni]);
        for(int mi=0;mi<nm;mi++){
            uint64_t s=ms[mi].s,e=ms[mi].e,pos=s;size_t ov=0;
            while(pos<e){
                size_t w=(size_t)((e-pos)>4ull*1024*1024?4ull*1024*1024:(e-pos));
                ssize_t g=pread(fd,b+ov,w,(off_t)pos);if(g<=0)break;
                size_t n=ov+(size_t)g;
                for(size_t i=0;i+pn<=n;i++){
                    if(memcmp(b+i,needles[ni],pn))continue;
                    uint64_t a=pos+i-ov;int seen=0;
                    for(int t=0;t<tc;t++)if(targets[t]==a)seen=1;
                    if(!seen&&tc<32){targets[tc]=a;tn[tc]=needles[ni];tc++;}
                }
                ov=n<128?n:128;if(ov)memmove(b,b+n-ov,ov);pos+=g;
            }
        }
    }
    fprintf(r,"TARGETS=%d\n",tc);
    for(int t=0;t<tc;t++)fprintf(r,"TARGET[%d] %s 0x%llx\n",t,tn[t],(unsigned long long)targets[t]);
    fflush(r);    int refc=0;
    for(int mi=0;mi<nm&&refc<2000;mi++){
        // Focus on writable/anonymous maps, plus libunity. This includes large heaps.
        if(ms[mi].p[0]!='r')continue;
        if(!ms[mi].p[1]=='w'){}
        if(ms[mi].path[0] && !strstr(ms[mi].path,"[anon") &&
           !strstr(ms[mi].path,"libunity.so") && ms[mi].p[1]!='w')continue;
        uint64_t s=ms[mi].s,e=ms[mi].e,pos=s;size_t ov=0;
        while(pos<e&&refc<2000){
            size_t w=(size_t)((e-pos)>4ull*1024*1024?4ull*1024*1024:(e-pos));
            ssize_t g=pread(fd,b+ov,w,(off_t)pos);if(g<=0)break;
            size_t n=ov+(size_t)g;
            size_t lim=n>=8?n-8:0;
            for(size_t i=0;i<=lim&&refc<2000;i++){
                uint64_t v=0;memcpy(&v,b+i,8);uint64_t uv=untag(v);
                for(int t=0;t<tc;t++){
                    if(uv!=untag(targets[t]))continue;
                    uint64_t cand=pos+i-ov;
                    fprintf(r,"REF 0x%llx -> %s 0x%llx map=0x%llx-0x%llx %s\n",
                            (unsigned long long)cand,tn[t],(unsigned long long)targets[t],
                            (unsigned long long)s,(unsigned long long)e,ms[mi].path);
                    fflush(r);
                    if(image_check(fd,ms,nm,cand,r,0)){}
                    refc++;break;
                }
            }
            ov=n<8?n:8;if(ov)memmove(b,b+n-ov,ov);pos+=g;
        }
    }
    fprintf(r,"REFS=%d\n",refc);fflush(r);
    free(b);close(fd);fclose(r);return 0;
}
__attribute__((constructor))static void init(){pthread_t t;if(!pthread_create(&t,0,worker,0))pthread_detach(t);}
