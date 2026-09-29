# Test lib checkpoint — 2026-09-29 12:48 +03

Target: com.stand.cherry.prod
Emulator ABI: x86_64 with Houdini/nativebridge for arm64 app libraries.

## Built
- Source: ownapp100/target/libSTANDCHERRY.test.c
- ARM64 test library: ownapp100/target/libSTANDCHERRY.arm64.so
- Size: 5616 bytes
- ELF: AArch64 shared object
- Export: JNI_OnLoad
- NEEDED: libdl.so, libc.so
- JNI_OnLoad attempts dlopen librealmain.so, resolves JNI_OnLoad, then calls it.
- librealmain.so is the existing runtime-dumper binary from libapidump.v2.cpp; deps: libdl.so, liblog.so, libm.so, libc.so.

## Deployed without APK editing
Current package root from pm path:
/data/app/~~xY_F-r8Bo33Gd9ajbzoXEg==/com.stand.cherry.prod-rp0evaGEb2TqgPjOfyC4ZQ==

Created:
/data/app/~~xY_F-r8Bo33Gd9ajbzoXEg==/com.stand.cherry.prod-rp0evaGEb2TqgPjOfyC4ZQ==/lib/arm64/

Deployed there:
- libSTANDCHERRY.so = ARM64 test library
- librealmain.so = runtime dumper binary

The older W91O... install root is stale after reinstall/reboot, so the test library was placed under the current root.

## Test result
The app process starts, but runtime-il2cpp.status and dump.cs have not appeared yet.
The APK itself does not contain libSTANDCHERRY.so; this library is a sidecar artifact.

## State
- No APK was rebuilt or edited.
- wrap.com.stand.cherry.prod is blank after reboot.
- Existing static libunity.so and runtime candidate remain in the work tree.
- Runtime candidate is still not claimed as final verified dump.