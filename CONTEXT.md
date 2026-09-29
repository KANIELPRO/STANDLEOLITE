# STANDOFF IL2CPP dump context
Updated: 2026-09-29

## Target
Package: com.stand.cherry.prod
Version: 1.0.0
versionCode: 203964
targetSdk: 36
ABI: arm64-v8a
Device ID: e833e56d-afd8-44e6-a293-3097502b15b2
ADB serial: NFFEOVKRWCBU4LT4

## Paths
Work root:
C:\Users\pasha\OneDrive\Desktop\STANDOFF_1_0_DUMP_WORK
Target APK:
C:\Users\pasha\OneDrive\Desktop\STANDOFF_1_0_DUMP_WORK\ownapp100\target\base.apk
APK size: 101010215 bytes
libunity:
C:\Users\pasha\OneDrive\Desktop\STANDOFF_1_0_DUMP_WORK\ownapp100\libunity.so
Size: 205920160 bytes

## Important architecture finding
The target does NOT expose a normal standalone libil2cpp.so or standalone global-metadata.dat.
IL2CPP/generated code is merged/scattered through libunity.so and runtime maps.
Current live PID at the latest successful scan: 6048.

Current libunity mappings for PID 6048:
6df3b9e000-6e00000000 r--p offset 00000000 libunity.so
6f53440000-6f5879c000 r--p offset 00000000 libunity.so
6f5879f000-6f5ecc3000 r-xp offset 0535b000 libunity.so
6f5ecc6000-6f5f344000 r--p offset 0b87e000 libunity.so
6f5f347000-6f5f8ad000 rw-p offset 0befb000 libunity.so

This scattered/duplicated mapping is the main reason normal Il2CppDumper auto-mode fails.

## Current concrete runtime finding
A real codegen-module-shaped block was identified in the current r-- mapping at:
0x6f5ef6b810

For the modern Unity 6-style module layout:
q0 = 0x6f54d21623  (module name pointer)
q1 = 0x18          (methodPointerCount = 24)
q2 = 0x6f5f6fb030  (methodPointers)
q3 = 0x5           (adjustorThunkCount)
q4 = 0x0            (adjustorThunks)
q5 = 0x0            (reversePInvokeWrapperCount)
q6 = 0x6f56c0b004  (reversePInvokeWrapperIndices)
q7 = 0x0            (debuggerMetadata)
q8 = 0x0            (moduleInitializer)
q9 = 0x0            (metadataRegistration)
q10 = 0x0           (codeRegistration)

The module-name pointer resolves into a duplicated r-- file mapping. The methodPointers target 0x6f5f6fb030 is inside the current rw libunity mapping and contains pointers into the current r-x code mapping, which supports that this is genuine runtime CodeGenModule data, not a random 64-bit pattern.

An mscorlib-related runtime structure was also observed at 0x6f5efdb1a0, but its field pattern is NOT the CodeGenModule layout (it behaves more like an Il2CppImage/runtime metadata structure). Do not treat it as CodeGenModule.

## Module discovery
A live scanner over 6f5ecc6000-6f5f344000 identified 185 structures that match the broad CodeGenModule name/count/pointer pattern.
No contiguous direct pointer table of these 185 module-head addresses was found in readable memory, suggesting the global codegen-module pointer list may be protected/transformed or stored in a different representation.

## Metadata registration
Broad v108-style alternating count/pointer scans produced false-positive structures, including repeated 0x1500/0x1540 patterns. None is confirmed as Il2CppMetadataRegistration.
Do NOT label these as MetadataRegistration until validated.

## Code registration
No confirmed Il2CppCodeRegistration address yet.
A targeted search for q15 == 185 yielded false positives.
A direct search for contiguous tables of the 185 detected module-head addresses did not find one.
Next high-value approach: use the 185 genuine module definitions plus Unity/C++ current-source CodeRegistration layout to locate the encoded/indirect module-list pointer, then validate the 17-qword CodeRegistration object.

## Tools and sources
Current Il2CppDumper:
ownapp100\Il2CppDumper-6.7.46
Cpp2IL current source:
ownapp100\tools\Cpp2IL-current

Native helpers created under:
ownapp100\target\
- dump_range
- read_qwords
- scan_ptr_refs
- scan_ptr_multi
- scan_module_heads2
- find_q185
- find_module_ptr_tables2
- find_named_modules
- find_mscorlib_module
- scan_codegen_live
- scan_metareg_v108
- scan_registrations
- and related analysis scripts

## OBB / assets
OBB:
 /sdcard/Android/obb/com.stand.cherry.prod/main.203964.com.axlebolt.standoff2.obb
Contains:
 assets/bin/Data/data.unity3d
Extracted local:
 ownapp100\target\data.unity3d
OBB UnityFS:
version 8, Unity 6000.3.13f1, flags 0xF3 (LZHAM block compression).
A first-pass LZ4-only parser is insufficient for this OBB.

APK assets also contain assets/bin/Data/data.unity3d (~1.375 MB), but no standalone global-metadata.dat.

## External il2cpp folder
/storage/emulated/0/Android/data/com.stand.cherry.prod/files/il2cpp/
contains Unity resource .dat files and unity.ver, but no standalone global-metadata.dat was found.

## Important policy/workflow note
Operate on com.stand.cherry.prod only.
Do not use or foreground com.pasha.metadatadumper.
Use non-invasive reads, static analysis, and /proc/<pid>/mem reads only. Do not overwrite target APK or target native binaries.

## Current status
The work tree and context are being kept under the requested STANDOFF_1_0_DUMP_WORK folder.
