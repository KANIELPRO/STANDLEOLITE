#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <signal.h>
#include <asm/ptrace.h>
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

static bool getregs(int pid,user_pt_regs& r){struct iovec iov{&r,sizeof(r)};return ptrace(PTRACE_GETREGSET,pid,(void*)NT_PRSTATUS,&iov)==0;}
static bool setregs(int pid,const user_pt_regs& r){struct iovec iov{(void*)&r,sizeof(r)};return ptrace(PTRACE_SETREGSET,pid,(void*)NT_PRSTATUS,&iov)==0;}

struct Map{uint64_t s,e,off;bool x;std::string p;};
static std::vector<Map> maps(int pid){
 std::vector<Map> out;std::ifstream f("/proc/"+std::to_string(pid)+"/maps");std::string line;
 while(std::getline(f,line)){std::istringstream is(line);std::string rg,perm,off,dev,ino,p;is>>rg>>perm>>off>>dev>>ino;std::getline(is,p);while(!p.empty()&&p[0]==' ')p.erase(p.begin());
  auto d=rg.find('-');if(d==std::string::npos)continue;Map m{strtoull(rg.substr(0,d).c_str(),0,16),strtoull(rg.substr(d+1).c_str(),0,16),strtoull(off.c_str(),0,16),perm.size()>=3&&perm[2]=='x',p};out.push_back(m);}
 return out;
}
static uint64_t remoteLibcBase(int pid){
 for(auto&m:maps(pid)) if(m.s&&m.p.find("libc.so")!=std::string::npos && m.off==0) return m.s;
 return 0;
}
static uint64_t findBrk(int pid){
 int fd=open(("/proc/"+std::to_string(pid)+"/mem").c_str(),O_RDONLY);if(fd<0)return 0;const uint32_t pat=0xd4200000u;
 std::vector<uint8_t>b(1<<20);for(auto&m:maps(pid)){if(!m.x||m.e<=m.s||m.e-m.s>256ull*1024*1024)continue;for(uint64_t p=m.s;p<m.e;){size_t w=std::min<uint64_t>(b.size(),m.e-p);ssize_t g=pread(fd,b.data(),w,p);if(g<=0)break;for(size_t o=0;o+4<=g;o+=4)if(*(uint32_t*)(b.data()+o)==pat){close(fd);return p+o;}p+=g;}}close(fd);return 0;
}
static uint32_t movz(int rd,uint16_t imm,int hw){return 0xd2800000u | ((uint32_t)imm<<5) | ((uint32_t)hw<<21) | rd;}
static uint32_t movk(int rd,uint16_t imm,int hw){return 0xf2800000u | ((uint32_t)imm<<5) | ((uint32_t)hw<<21) | rd;}
static void loadimm(std::vector<uint32_t>&s,int rd,uint64_t v){s.push_back(movz(rd,(uint16_t)(v&0xffff),0));for(int hw=1;hw<4;hw++)s.push_back(movk(rd,(uint16_t)((v>>(hw*16))&0xffff),hw));}
static bool poke(int pid,uint64_t a,uint64_t v){errno=0;long r=ptrace(PTRACE_POKEDATA,pid,(void*)a,(void*)v);return r!=-1||errno==0;}
static bool pokebytes(int pid,uint64_t a,const void*p,size_t n){const uint8_t*b=(const uint8_t*)p;for(size_t o=0;o<n;){uint64_t v=0;size_t k=std::min<size_t>(8,n-o);memcpy(&v,b+o,k);if(!poke(pid,a+o,v))return false;o+=8;}return true;}
static bool contTrap(int pid){if(ptrace(PTRACE_CONT,pid,0,0)!=0)return false;int st=0;if(waitpid(pid,&st,0)<0)return false;return WIFSTOPPED(st)&&(WSTOPSIG(st)==SIGTRAP||WSTOPSIG(st)==SIGSTOP);}
int main(int ac,char**av){
 if(ac<3){fprintf(stderr,"usage pid lib.so\n");return 2;}int pid=atoi(av[1]);const char*lib=av[2];
 if(ptrace(PTRACE_ATTACH,pid,0,0)!=0){perror("attach");return 3;}int st=0;if(waitpid(pid,&st,0)<0){perror("wait");return 4;}
 user_pt_regs orig{};if(!getregs(pid,orig)){perror("getregs");ptrace(PTRACE_DETACH,pid,0,0);return 5;}
 Dl_info di{};if(!dladdr((void*)dlopen,&di)){fprintf(stderr,"dladdr failed\n");return 6;}uint64_t localLib=(uint64_t)di.dli_fbase, dlOff=(uint64_t)dlopen-localLib;
 Dl_info di2{};if(!dladdr((void*)mmap,&di2)){fprintf(stderr,"dladdr mmap failed\n");return 7;}uint64_t mmOff=(uint64_t)mmap-(uint64_t)di2.dli_fbase;
 uint64_t rbase=remoteLibcBase(pid),brk=findBrk(pid);if(!rbase||!brk){fprintf(stderr,"bases brk=0x%llx libc=0x%llx\n",(unsigned long long)brk,(unsigned long long)rbase);ptrace(PTRACE_DETACH,pid,0,0);return 8;}
 uint64_t rdl=rbase+dlOff,rmm=rbase+mmOff;fprintf(stderr,"remote libc=0x%llx dlopen=0x%llx mmap=0x%llx brk=0x%llx\n",(unsigned long long)rbase,(unsigned long long)rdl,(unsigned long long)rmm,(unsigned long long)brk);
 user_pt_regs r=orig;
 r.regs[0]=0;r.regs[1]=0x4000;r.regs[2]=PROT_READ|PROT_WRITE|PROT_EXEC;r.regs[3]=MAP_PRIVATE|MAP_ANONYMOUS;r.regs[4]=(uint64_t)-1;r.regs[5]=0;r.regs[30]=brk;r.pc=rmm;
 if(!setregs(pid,r)||!contTrap(pid)){fprintf(stderr,"remote mmap failed\n");setregs(pid,orig);ptrace(PTRACE_DETACH,pid,0,0);return 9;}
 if(!getregs(pid,r)){fprintf(stderr,"getregs after mmap failed\n");setregs(pid,orig);ptrace(PTRACE_DETACH,pid,0,0);return 10;}
 uint64_t mem=r.regs[0];fprintf(stderr,"remote mem=0x%llx\n",(unsigned long long)mem);if(mem<0x10000){fprintf(stderr,"mmap invalid\n");setregs(pid,orig);ptrace(PTRACE_DETACH,pid,0,0);return 11;}
 uint64_t pathAddr=mem+0x1000;std::vector<uint32_t>sc;loadimm(sc,0,pathAddr);sc.push_back(0x52800021u);loadimm(sc,16,rdl);sc.push_back(0xd63f0200u);sc.push_back(0xd4200000u);std::vector<uint8_t>scb(sc.size()*4);memcpy(scb.data(),sc.data(),scb.size());
 std::string pth=lib;std::vector<uint8_t>str(pth.begin(),pth.end());str.push_back(0);
 if(!pokebytes(pid,pathAddr,str.data(),str.size())||!pokebytes(pid,mem,scb.data(),scb.size())){fprintf(stderr,"write failed\n");setregs(pid,orig);ptrace(PTRACE_DETACH,pid,0,0);return 12;}
 r=orig;r.pc=mem;r.regs[30]=brk;
 if(!setregs(pid,r)||!contTrap(pid)){fprintf(stderr,"dlopen call failed\n");setregs(pid,orig);ptrace(PTRACE_DETACH,pid,0,0);return 13;}
 if(!getregs(pid,r)){fprintf(stderr,"getregs after dlopen failed\n");}
 fprintf(stderr,"dlopen result=0x%llx\n",(unsigned long long)r.regs[0]);
 setregs(pid,orig);ptrace(PTRACE_DETACH,pid,0,0);fprintf(stderr,"DONE\n");return r.regs[0]?0:14;
}
