#include <dlfcn.h>
#include <cstdio>
#include <cstdint>
#include <sys/mman.h>
int main(){Dl_info a{},b{};dladdr((void*)dlopen,&a);dladdr((void*)mmap,&b);printf("dlopen=%p libc_dl_base=%p off=0x%llx\n",(void*)dlopen,a.dli_fbase,(unsigned long long)((uintptr_t)dlopen-(uintptr_t)a.dli_fbase));printf("mmap=%p libc_mm_base=%p off=0x%llx\n",(void*)mmap,b.dli_fbase,(unsigned long long)((uintptr_t)mmap-(uintptr_t)b.dli_fbase));return 0;}
