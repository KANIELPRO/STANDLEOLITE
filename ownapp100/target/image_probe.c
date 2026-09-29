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

typedef struct { uint64_t s,e,off; char p[5],path[512]; } Map;

static int parse_maps(Map *ms,int max){
    FILE*f=fopen("/proc/self/maps","r"); if(!f) return -1;
    char line[1024],per[8],path[512]; unsigned long long s,e,o;
    int nmap=0;
    while(fgets(line,sizeof(line),f)&&nmap<max){
        per[0]=path[0]=0;
        int n=sscanf(line,"%llx-%llx %7s %llx %*s %*s %511[^\\n]",
                     &s,&e,per,&o,path);
        if(n<4||per[0]!='r'||e<=s) continue;
        Map*m=&ms[nmap++]; m->s=s; m->e=e; m->off=o;
        snprintf(m->p,sizeof(m->p),"%s",per);
        snprintf(m->path,sizeof(m->path),"%s",n>=5?path:"");
    }
    fclose(f); return nmap;
}

static const Map* owner(Map*ms,int n,uint64_t a){
    for(int i=0;i<n;i++) if(a>=ms[i].s&&a<ms[i].e) return &ms[i];
    return 0;
}
static int readable_candidate(const Map*m){
    if(!m)return 0;
    if(strstr(m->path,"libunity.so")||strstr(m->path,"[anon:.bss")||
       strstr(m->path,"[anon:libc_malloc")) return 1;
    return m->e-m->s <= 64ull*1024*1024 && m->path[0]==0;
}
static int find_bytes(int fd,uint64_t s,uint64_t e,const uint8_t*pat,size_t pn,uint64_t*out,int max){
    uint8_t*b=(uint8_t*)malloc(4*1024*1024+128); if(!b)return 0;
    uint64_t pos=s; size_t ov=0; int hits=0;
    while(pos<e && hits<max){
        size_t w=(size_t)((e-pos)>4ull*1024*1024?4ull*1024*1024:(e-pos));
        ssize_t g=pread(fd,b+ov,w,(off_t)pos); if(g<=0)break;
        size_t n=ov+(size_t)g;
        for(size_t i=0;i+pn<=n;i++) if(!memcmp(b+i,pat,pn)){
            uint64_t a=pos+i-ov; out[hits++]=a;
        }
        ov=n<128?n:128; memmove(b,b+n-ov,ov); pos+=g;
    }
    free(b); return hits;
}
static int rd(int fd,uint64_t a,void*out,size_t n){return pread(fd,out,n,(off_t)a)==(ssize_t)n;}
static int is_ptr(Map*ms,int n,uint64_t a){return owner(ms,n,a)!=0;}
static int str_ok(int fd,uint64_t a,char*out,size_t cap){
    if(!a||cap<4)return 0;
    if(pread(fd,out,cap-1,(off_t)a)<=0)return 0;
    size_t i=0; while(i<cap-1 && out[i]>=0x20 && out[i]<0x7f)i++;
    if(i<4)return 0; out[i]=0; return (int)i;
}
static int ends(const char*s,const char*suf){
    size_t a=strlen(s),b=strlen(suf); return a>=b&&!strcmp(s+a-b,suf);
}
static void dump_near(int fd,const char*dir,uint64_t a,uint64_t bytes,const char*tag){
    const Map*mm=0;
    char fn[700];
    snprintf(fn,sizeof(fn),"%s/%s-%llx.bin",dir,tag,(unsigned long long)a);
    // Find a readable source map containing a.
    // Clamp the capture so a bad address cannot escape its map.
    Map tmp;
    FILE*mf=fopen("/proc/self/maps","r");
    if(!mf)return;
    char line[1024],per[8],path[512]; unsigned long long s,e,o;
    while(fgets(line,sizeof(line),mf)){
        per[0]=path[0]=0;
        int n=sscanf(line,"%llx-%llx %7s %llx %*s %*s %511[^\\n]",&s,&e,per,&o,path);
        if(n>=4&&a>=s&&a<e){tmp.s=s;tmp.e=e;mm=&tmp;break;}
    }
    fclose(mf); if(!mm)return;
    uint64_t half=bytes/2, start=a>half?a-half:mm->s;
    if(start<mm->s)start=mm->s;
    if(start+bytes>mm->e) bytes=mm->e-start;
    int of=open(fn,O_CREAT|O_TRUNC|O_WRONLY,0644); if(of<0)return;
    uint8_t*b=(uint8_t*)malloc(1024*1024); if(!b){close(of);return;}
    uint64_t pos=start,left=bytes;
    while(left){size_t w=(size_t)(left>1024*1024?1024*1024:left);ssize_t g=pread(fd,b,w,pos);if(g<=0)break;write(of,b,g);pos+=g;left-=g;}
    close(of);free(b);
}
static void inspect_image(int fd,Map*ms,int nm,const char*dir,uint64_t a,FILE*r){
    uint64_t q[11]={0};
    if(!rd(fd,a,q,sizeof(q)))return;
    if(!is_ptr(ms,nm,q[0])||q[0]!=a)return;
    char n0[160]={0},n1[160]={0};
    if(!str_ok(fd,q[0],n0,sizeof(n0)))return;
    if(q[1]&&!str_ok(fd,q[1],n1,sizeof(n1)))return;
    if(q[3]>1000000||q[4]>q[3]||q[5]>1000000)return;
    if(q[8]&&!is_ptr(ms,nm,q[8]))return;
    fprintf(r,"IMAGE 0x%llx name=%s nameNoExt=%s typeCount=%llu exported=%llu codeGen=0x%llx token=0x%llx\n",
            (unsigned long long)a,n0,n1,(unsigned long long)q[3],(unsigned long long)q[4],
            (unsigned long long)q[8],(unsigned long long)q[9]);
    fflush(r);
    dump_near(fd,dir,a,8192,"image");
}
static void inspect_module(int fd,Map*ms,int nm,const char*dir,uint64_t a,FILE*r){
    uint64_t q[17]={0};
    if(!rd(fd,a,q,sizeof(q)))return;
    char name[160]={0};
    if(!q[0]||!is_ptr(ms,nm,q[0])||!str_ok(fd,q[0],name,sizeof(name))||!ends(name,".dll"))return;
    if(q[1]>10000000||!q[2]||!is_ptr(ms,nm,q[2]))return;
    if(q[3]>2000000)return;
    if(q[4]&&!is_ptr(ms,nm,q[4]))return;
    if(q[5]&&!is_ptr(ms,nm,q[5]))return;
    if(q[6]>2000000)return;
    if(q[7]&&!is_ptr(ms,nm,q[7]))return;
    if(q[8]>2000000)return;
    if(q[9]&&!is_ptr(ms,nm,q[9]))return;
    if(q[10]>2000000)return;
    if(q[11]&&!is_ptr(ms,nm,q[11]))return;
    if(q[12]&&!is_ptr(ms,nm,q[12]))return;
    if(q[13]&&!is_ptr(ms,nm,q[13]))return;
    if(q[14]&&!is_ptr(ms,nm,q[14]))return;
    if(q[15]&&!is_ptr(ms,nm,q[15]))return;
    if(q[16]&&!is_ptr(ms,nm,q[16]))return;
    fprintf(r,"MODULE 0x%llx name=%s\n",(unsigned long long)a,name);
    for(int i=0;i<17;i++) fprintf(r," q%d=0x%llx\n",i,(unsigned long long)q[i]);
    fflush(r);
    dump_near(fd,dir,a,65536,"module");
}
static void find_refs_in_map(int fd,Map*ms,int nm,int mi,const char*dir,uint64_t target,FILE*r){
    if(mi<0||mi>=nm)return;
    uint64_t s=ms[mi].s,e=ms[mi].e;
    uint8_t*b=(uint8_t*)malloc(4*1024*1024+8);
    if(!b)return;
    uint64_t pos=s; size_t ov=0; int refs=0;
    while(pos<e && refs<128){
        size_t w=(size_t)((e-pos)>4ull*1024*1024?4ull*1024*1024:(e-pos));
        ssize_t g=pread(fd,b+ov,w,(off_t)pos);
        if(g<=0)break;
        size_t n=ov+(size_t)g;
        size_t lim=n>=8?n-8:0;
        for(size_t i=0;i<=lim && refs<128;i++){
            uint64_t v=0; memcpy(&v,b+i,8);
            if(v!=target)continue;
            uint64_t cand=pos+i-ov;
            fprintf(r," REF target=0x%llx at=0x%llx map=0x%llx-0x%llx\n",
                    (unsigned long long)target,(unsigned long long)cand,
                    (unsigned long long)s,(unsigned long long)e);
            fflush(r);
            uint64_t iq[11]={0};
            if(rd(fd,cand,iq,sizeof(iq))){
                inspect_image(fd,ms,nm,dir,cand,r);
                inspect_module(fd,ms,nm,dir,cand,r);
                if(iq[8]) inspect_module(fd,ms,nm,dir,iq[8],r);
            }
            refs++;
        }        ov=n<8?n:8;
        if(ov)memmove(b,b+n-ov,ov);
        pos+=g;
    }
    free(b);
}
static void scan_all_for_range(int fd,Map*ms,int nm,const char*dir,
                               uint64_t ts,uint64_t te,FILE*r){
    uint8_t*b=(uint8_t*)malloc(4*1024*1024+8);
    if(!b)return;
    int refs=0;
    for(int mi=0;mi<nm && refs<512;mi++){
        uint64_t s=ms[mi].s,e=ms[mi].e;
        if(e<=s||e-s>128ull*1024*1024)continue;
        if(ms[mi].path[0] && !strstr(ms[mi].path,"libunity.so") &&
           !strstr(ms[mi].path,"[anon")) continue;
        uint64_t pos=s; size_t ov=0;
        while(pos<e && refs<512){
            size_t w=(size_t)((e-pos)>4ull*1024*1024?4ull*1024*1024:(e-pos));
            ssize_t g=pread(fd,b+ov,w,(off_t)pos); if(g<=0)break;
            size_t n=ov+(size_t)g;
            size_t lim=n>=8?n-8:0;
            for(size_t i=0;i<=lim && refs<512;i++){
                uint64_t v=0; memcpy(&v,b+i,8);
                if(v<ts||v>=te)continue;
                uint64_t cand=pos+i-ov;
                uint64_t iq[11]={0};
                if(!rd(fd,cand,iq,sizeof(iq)))continue;
                if(iq[0]!=v)continue;
                fprintf(r," RANGE_REF 0x%llx -> 0x%llx map=0x%llx-0x%llx\n",
                        (unsigned long long)cand,(unsigned long long)v,
                        (unsigned long long)s,(unsigned long long)e);
                fflush(r);
                inspect_image(fd,ms,nm,dir,cand,r);
                inspect_module(fd,ms,nm,dir,cand,r);
                if(iq[8]) inspect_module(fd,ms,nm,dir,iq[8],r);
                refs++;
            }
            ov=n<8?n:8;
            if(ov)memmove(b,b+n-ov,ov);
            pos+=g;
        }
    }
    free(b);
}
static void *worker(void*unused){
    (void)unused; sleep(10);
    const char*dir="/sdcard/Android/data/com.stand.cherry.prod/files/imageprobe";
    mkdir("/sdcard/Android/data/com.stand.cherry.prod/files",0771);
    mkdir(dir,0771);
    FILE*r=fopen("/sdcard/Android/data/com.stand.cherry.prod/files/imageprobe/report.txt","w");
    if(!r)return 0;
    fprintf(r,"IMAGE_PROBE_START PID=%d\n",getpid()); fflush(r);
    Map ms[512]; int nm=parse_maps(ms,512);
    fprintf(r,"MAPS=%d\n",nm);
    Map targets[16]; int tc=0;
    int fd=open("/proc/self/mem",O_RDONLY);
    if(fd<0){fprintf(r,"MEM_ERR=%d:%s\n",errno,strerror(errno));fclose(r);return 0;}
    const char*needles[]={"Assembly-CSharp.dll","Axlebolt.Standoff.Game.dll","Gameplay.Bomb.dll","global-metadata.dat"};
    for(size_t ni=0;ni<sizeof(needles)/sizeof(needles[0]);ni++){
        const uint8_t*p=(const uint8_t*)needles[ni];
        size_t pn=strlen(needles[ni]);
        fprintf(r,"NEEDLE %s\n",needles[ni]);
        for(int mi=0;mi<nm;mi++){
            if(!readable_candidate(&ms[mi]))continue;
            uint64_t hits[64]; int hc=find_bytes(fd,ms[mi].s,ms[mi].e,p,pn,hits,64);
            for(int hi=0;hi<hc;hi++){
                uint64_t a=hits[hi];
                int seen=0; for(int ti=0;ti<tc;ti++) if(targets[ti].s==ms[mi].s && targets[ti].e==ms[mi].e) seen=1;
                if(!seen && tc<16) targets[tc++]=ms[mi];
                fprintf(r," HIT 0x%llx map=0x%llx-0x%llx path=%s\n",
                        (unsigned long long)a,(unsigned long long)ms[mi].s,
                        (unsigned long long)ms[mi].e,ms[mi].path); fflush(r);
                // Look for an Il2CppImage whose name pointer is this exact string.
                dump_near(fd,dir,a,262144,"str");
                find_refs_in_map(fd,ms,nm,mi,dir,a,r);
                uint64_t qv=0;
                for(int back=0;back<=0x4000;back+=8){
                    if(a<(uint64_t)back)break;
                    uint64_t cand=a-(uint64_t)back;
                    if(rd(fd,cand,&qv,8)&&qv==a) inspect_image(fd,ms,nm,dir,cand,r);
                }
            }
        }
    }
    fprintf(r,"TARGET_RANGES=%d\n",tc); fflush(r);
    for(int ti=0;ti<tc;ti++) scan_all_for_range(fd,ms,nm,dir,targets[ti].s,targets[ti].e,r);
    fclose(r);
    close(fd);
    return 0;
}
__attribute__((constructor)) static void init(){pthread_t t;if(!pthread_create(&t,0,worker,0))pthread_detach(t);}
