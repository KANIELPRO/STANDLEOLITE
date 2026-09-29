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

typedef struct { uint64_t s,e; char p[5],path[700]; } Map;

static uint64_t U(uint64_t x){return x&0x00ffffffffffffffULL;}
static int parse(Map*ms,int max){
    FILE*f=fopen("/proc/self/maps","r");if(!f)return -1;
    char line[1200],per[8],path[700];unsigned long long s,e,o;int n=0;
    while(fgets(line,sizeof(line),f)&&n<max){
        per[0]=path[0]=0;
        int z=sscanf(line,"%llx-%llx %7s %llx %*s %*s %699[^\n]",
                     &s,&e,per,&o,path);
        if(z<4||e<=s||per[0]!='r')continue;
        Map*m=&ms[n++];m->s=s;m->e=e;
        snprintf(m->p,sizeof(m->p),"%s",per);
        snprintf(m->path,sizeof(m->path),"%s",z>=5?path:"");
    }
    fclose(f);return n;
}
static const Map*own(Map*ms,int n,uint64_t a){
    uint64_t x=U(a);
    for(int i=0;i<n;i++)if(x>=ms[i].s&&x<ms[i].e)return &ms[i];
    return 0;
}
static int rd(int fd,uint64_t a,void*out,size_t n){
    return pread(fd,out,n,(off_t)U(a))==(ssize_t)n;
}
static int str_ok(int fd,uint64_t a,char*out,size_t cap){
    const Map*mm=0;
    if(!a)return 0;
    // owner check is performed by caller; this just reads a short C string.
    ssize_t g=pread(fd,out,cap-1,(off_t)U(a));if(g<=0)return 0;
    size_t i=0;while(i<(size_t)g&&out[i]>=0x20&&out[i]<0x7f)i++;
    if(i<4)return 0;out[i]=0;return (int)i;
}
static int module_ok(int fd,Map*ms,int nm,uint64_t a,uint64_t codeReg,FILE*r,int print){
    uint64_t q[17]={0};char name[192]={0};
    if(!rd(fd,a,q,sizeof(q)))return 0;
    if(!q[0]||!own(ms,nm,q[0])||!str_ok(fd,q[0],name,sizeof(name)))return 0;
    size_t ln=strlen(name);if(ln<4||strcmp(name+ln-4,".dll"))return 0;
    if(q[1]>20000000||!q[2]||!own(ms,nm,q[2]))return 0;
    if(q[3]>5000000||q[6]>5000000||q[8]>5000000||q[10]>5000000)return 0;
    if(q[16] && U(q[16])!=U(codeReg))return 0;
    if(!q[15]||!own(ms,nm,q[15]))return 0;
    if(print){
        fprintf(r,"  MODULE 0x%llx %s\n",(unsigned long long)a,name);
        for(int i=0;i<17;i++)fprintf(r,"   mq%d=0x%llx\n",i,(unsigned long long)q[i]);
    }
    return 1;
}
static int code_reg_ok(int fd,Map*ms,int nm,uint64_t a,FILE*r){
    uint64_t q[17]={0};
    if(!rd(fd,a,q,sizeof(q)))return 0;
    uint64_t count=q[15],arr=U(q[16]);
    if(count<4||count>5000||!arr||!own(ms,nm,arr))return 0;
    const Map*am=own(ms,nm,arr);
    if(arr+count*8 > am->e || arr+count*8 < arr)return 0;
    // Sample beginning, middle, and end; modules must point back to this CodeRegistration.
    uint64_t idx[3]={0,count/2,count-1};
    int good=0;
    for(int k=0;k<3;k++){
        uint64_t mod=0;if(!rd(fd,arr+idx[k]*8,&mod,8))return 0;
        if(!module_ok(fd,ms,nm,mod,a,r,0))return 0;
        good++;
    }
    if(good!=3)return 0;
    fprintf(r,"CODEREG_CAND 0x%llx modules=%llu array=0x%llx\n",
            (unsigned long long)a,(unsigned long long)count,(unsigned long long)arr);
    for(int i=0;i<17;i++)fprintf(r," cr%d=0x%llx\n",i,(unsigned long long)q[i]);
    for(int k=0;k<3;k++){
        uint64_t mod=0;rd(fd,arr+idx[k]*8,&mod,8);
        module_ok(fd,ms,nm,mod,a,r,1);
    }
    fflush(r);
    return 1;
}static void*worker(void*unused){
    (void)unused;sleep(10);
    const char*dir="/sdcard/Android/data/com.stand.cherry.prod/files/regscan";
    mkdir("/sdcard/Android/data/com.stand.cherry.prod/files",0771);
    mkdir(dir,0771);
    FILE*r=fopen("/sdcard/Android/data/com.stand.cherry.prod/files/regscan/report.txt","w");
    if(!r)return 0;
    Map ms[1024];int nm=parse(ms,1024);
    fprintf(r,"REGSCAN PID=%d MAPS=%d\n",getpid(),nm);fflush(r);
    int fd=open("/proc/self/mem",O_RDONLY);
    if(fd<0){fprintf(r,"MEMERR %d %s\n",errno,strerror(errno));fclose(r);return 0;}
    uint8_t*b=(uint8_t*)malloc(4*1024*1024+16);if(!b){close(fd);fclose(r);return 0;}
    int hits=0;
    for(int mi=0;mi<nm;mi++){
        // Registration objects are expected in writable runtime state or libunity mappings.
        if(ms[mi].p[1]!='w' && !strstr(ms[mi].path,"libunity.so") && !strstr(ms[mi].path,"[anon") && ms[mi].path[0])continue;
        uint64_t s=ms[mi].s,e=ms[mi].e,pos=s;size_t ov=0;
        if(e-s>256ull*1024*1024)continue;
        while(pos<e){
            size_t w=(size_t)((e-pos)>4ull*1024*1024?4ull*1024*1024:(e-pos));
            ssize_t g=pread(fd,b+ov,w,(off_t)pos);if(g<=0)break;
            size_t n=ov+(size_t)g;size_t lim=n>=136?n-136:0;
            for(size_t o=0;o<=lim;o+=8){
                uint64_t q15=0,q16=0;
                memcpy(&q15,b+o+15*8,8);memcpy(&q16,b+o+16*8,8);
                if(q15<4||q15>5000||!q16)continue;
                uint64_t va=pos+o-ov;
                if(code_reg_ok(fd,ms,nm,va,r)){hits++;if(hits>=30)break;}
            }
            if(hits>=30)break;
            ov=n<16?n:16;if(ov)memmove(b,b+n-ov,ov);pos+=g;
        }
        if(hits>=30)break;
    }
    fprintf(r,"HITS=%d\n",hits);fflush(r);
    free(b);close(fd);fclose(r);return 0;
}
__attribute__((constructor))static void init(){pthread_t t;if(!pthread_create(&t,0,worker,0))pthread_detach(t);}
