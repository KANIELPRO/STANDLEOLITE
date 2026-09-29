#include <jni.h>
#include <dlfcn.h>

typedef jint (*OnLoadFn)(JavaVM *, void *);

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;

    void *IrcxxHandle = dlopen("librealmain.so", RTLD_NOW);
    if (IrcxxHandle != NULL) {
        OnLoadFn OnLoad = (OnLoadFn)dlsym(IrcxxHandle, "JNI_OnLoad");
        if (OnLoad != NULL)
            OnLoad(vm, NULL);
    }

    return JNI_VERSION_1_6;
}
