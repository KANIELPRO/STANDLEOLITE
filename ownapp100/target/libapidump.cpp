#include <jni.h>
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <fstream>
#include <type_traits>
struct Il2CppDomain; struct Il2CppAssembly; struct Il2CppImage; struct Il2CppClass; struct FieldInfo; struct MethodInfo; struct Il2CppType; struct Il2CppThread;
using D=Il2CppDomain*(*)(); using DA=const Il2CppAssembly**(*)(const Il2CppDomain*,size_t*);
using AI=const Il2CppImage*(*)(const Il2CppAssembly*); using IN=const char*(*)(const Il2CppImage*);
using IC=size_t(*)(const Il2CppImage*); using IG=const Il2CppClass*(*)(const Il2CppImage*,size_t);
using CN=const char*(*)(Il2CppClass*); using NS=const char*(*)(Il2CppClass*);
using CFN=FieldInfo*(*)(Il2CppClass*,void**); using CMN=const MethodInfo*(*)(Il2CppClass*,void**);
using FGN=const char*(*)(FieldInfo*); using FGO=size_t(*)(FieldInfo*); using FGF=int(*)(FieldInfo*); using FGT=const Il2CppType*(*)(FieldInfo*);
using MGN=const char*(*)(const MethodInfo*); using MGT=uint32_t(*)(const MethodInfo*); using MGF=uint32_t(*)(const MethodInfo*,uint32_t*);
using MPC=uint32_t(*)(const MethodInfo*); using MGP=const Il2CppType*(*)(const MethodInfo*,uint32_t); using MGNM=const char*(*)(const MethodInfo*,uint32_t);
using MRT=const Il2CppType*(*)(const MethodInfo*); using TN=char*(*)(const Il2CppType*); using TA=Il2CppThread*(*)(Il2CppDomain*);
struct MH{void* p;};
static void* S(const char*n){void*p=dlsym(RTLD_DEFAULT,n);if(!p){void*h=dlopen("libunity.so",RTLD_NOW|RTLD_NOLOAD);if(h)p=dlsym(h,n);}return p;}
static std::string T(TN f,const Il2CppType*t){if(!t)return "void";char*s=f?f(t):nullptr;return s?s:"<type>";}
static const char* A(int f){switch(f&7){case 6:return "public";case 4:return "protected";case 2:return "private";default:return "private";}}
static void* run(void*){
sleep(3);mkdir("/data/local/tmp/standdump",0777);
std::ofstream log("/data/local/tmp/standdump/api-status.txt"); std::ofstream out("/data/local/tmp/standdump/dump.cs");
auto d=(D)S("il2cpp_domain_get"); auto da=(DA)S("il2cpp_domain_get_assemblies"); auto ai=(AI)S("il2cpp_assembly_get_image");
auto in=(IN)S("il2cpp_image_get_name"); auto ic=(IC)S("il2cpp_image_get_class_count"); auto ig=(IG)S("il2cpp_image_get_class");
auto cn=(CN)S("il2cpp_class_get_name"); auto ns=(NS)S("il2cpp_class_get_namespace"); auto cfn=(CFN)S("il2cpp_class_get_fields"); auto cmn=(CMN)S("il2cpp_class_get_methods");
auto fgn=(FGN)S("il2cpp_field_get_name"); auto fgo=(FGO)S("il2cpp_field_get_offset"); auto fgf=(FGF)S("il2cpp_field_get_flags"); auto fgt=(FGT)S("il2cpp_field_get_type");
auto mgn=(MGN)S("il2cpp_method_get_name"); auto mgt=(MGT)S("il2cpp_method_get_token"); auto mgf=(MGF)S("il2cpp_method_get_flags"); auto mpc=(MPC)S("il2cpp_method_get_param_count");
auto mgp=(MGP)S("il2cpp_method_get_param"); auto mgpn=(MGNM)S("il2cpp_method_get_param_name"); auto mrt=(MRT)S("il2cpp_method_get_return_type"); auto tn=(TN)S("il2cpp_type_get_name"); auto ta=(TA)S("il2cpp_thread_attach");
bool ok=d&&da&&ai&&in&&ic&&ig&&cn&&ns&&cfn&&cmn&&fgn&&fgo&&fgf&&fgt&&mgn&&mgt&&mgf&&mpc&&mgp&&mrt&&tn&&ta;
log<<"api_ok="<<ok<<" d="<<(void*)d<<std::endl; if(!ok)return nullptr;
Il2CppDomain*dom=d(); if(ta)ta(dom); size_t ac=0; const Il2CppAssembly**as=da(dom,&ac); log<<"assemblies="<<ac<<std::endl;
out<<"// Runtime IL2CPP dump"<<std::endl<<std::endl; uint64_t base=0; Dl_info di{}; if(dladdr((void*)d,&di))base=(uint64_t)di.dli_fbase;
size_t total=0;
for(size_t ai0=0;ai0<ac;ai0++){const Il2CppImage*im=ai(as[ai0]); if(!im)continue; const char*an=in(im); out<<"// Assembly: "<<(an?an:"<null>")<<std::endl<<std::endl;
size_t cc=ic(im); log<<"image "<<ai0<<" "<<(an?an:"<null>")<<" classes="<<cc<<std::endl;
for(size_t ci=0;ci<cc;ci++){const Il2CppClass*k=ig(im,ci); if(!k)continue; const char*nm=cn((Il2CppClass*)k); const char*qn=ns((Il2CppClass*)k);
out<<"public class "<<(nm?nm:"<anon>"); if(qn&&*qn)out<<" // namespace "<<qn; out<<std::endl<<"{"<<std::endl;
if(cfn){void*it=nullptr; while(FieldInfo*f=cfn((Il2CppClass*)k,&it)){out<<"    "<<A(fgf(f))<<" "<<T(tn,fgt(f))<<" "<<(fgn(f)?fgn(f):"<field>")<<"; // offset 0x"<<std::hex<<fgo(f)<<std::dec<<std::endl;}}
if(cmn){void*it=nullptr; while(const MethodInfo*m=cmn((Il2CppClass*)k,&it)){uint32_t pc=mpc(m); out<<"    "<<A(mgf(m,nullptr))<<" "<<T(tn,mrt(m))<<" "<<(mgn(m)?mgn(m):"<method>")<<"("; for(uint32_t pi=0;pi<pc;pi++){if(pi)out<<", "; out<<T(tn,mgp(m,pi))<<" "<<(mgpn?mgpn(m,pi):"arg");}out<<"); // Token 0x"<<std::hex<<mgt(m)<<std::dec<<std::endl; total++;}}
out<<"}"<<std::endl<<std::endl;}}
log<<"total_methods="<<total<<std::endl; return nullptr; }
__attribute__((constructor)) static void init(){pthread_t t;pthread_create(&t,nullptr,run,nullptr);pthread_detach(t);}
extern "C" int JNI_OnLoad(JavaVM*,void*){return JNI_VERSION_1_6;}
