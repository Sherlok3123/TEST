# NEVERLOSE LOADER MAPPING CORRELATION
======================================
Phase 8 — What the loader source (`FemboyLose-main/injector/main.cpp`) and
the DLL source (`FemboyLose-main/neverlose/`) prove about allocation,
mapping, transformations, and image ownership.

Read-only source analysis. No binaries or source files were modified.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. INJECTOR SOURCE: `FemboyLose-main/injector/main.cpp`
=========================================================

The injector (`loader.exe`) uses **standard Windows loader** mechanics, NOT
manual mapping:

| Step | Code location | Action | Confidence |
|------|--------------|--------|------------|
| Find csgo.exe | `FindProcessId()` (line 425) | Toolhelp32 process snapshot | CONFIRMED |
| Open target | `OpenProcess(kProcessAccess, ...)` (line 102) | PROCESS_CREATE_THREAD \| VM_OPERATION \| VM_WRITE \| VM_READ | CONFIRMED |
| Allocate path string | `VirtualAllocEx(process, nullptr, path_length, MEM_RESERVE\|MEM_COMMIT, PAGE_READWRITE)` (line 112) | Remote memory for DLL path | CONFIRMED |
| Write path | `WriteProcessMemory(process, remote_path, full_dll_path, ...)` (line 122) | Write DLL path to remote memory | CONFIRMED |
| Get LoadLibraryA | `GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")` (line 130) | Resolve LoadLibraryA | CONFIRMED |
| Remote thread | `CreateRemoteThread(process, ..., load_library, remote_path, ...)` (line 141) | Load DLL via LoadLibraryA | CONFIRMED |

**KEY FINDING:** The injector does NOT perform manual mapping. It uses the
standard Windows loader (`LoadLibraryA`) to load `neverlose.dll` into the
target process. This means `neverlose.dll` is initially mapped as a
**MEM_IMAGE** module at whatever base the Windows loader chooses (typically
near its preferred ImageBase `0x10000000` or rebased).

The injector source does NOT contain any manual mapping, section-by-section
copying, or PE header manipulation. It is a simple DLL injector.

========================================
2. DLL SOURCE: `FemboyLose-main/neverlose/`
=============================================

The DLL (`neverlose.dll`) performs its own **self-mapping** after being
loaded by the Windows loader:

**a) `neverlose::map(HMODULE hModule)`** (`neverlose.cpp:16-47`):

```cpp
void neverlose::map(HMODULE hModule)
{
    hThis = hModule;
    HRSRC hRes = FindResource(hThis, MAKEINTRESOURCE(IDR_BINARY), L"BINARY");
    if (!hRes) panic("Failed to locate cheat binary!");

    HGLOBAL hResData = LoadResource(hThis, hRes);
    if (!hResData) panic("Failed to load cheat binary!");

    LPVOID pData = LockResource(hResData);
    if (!pData) panic("Failed to lock cheat binary!");

    DWORD Size = SizeofResource(hThis, hRes);
    if (Size) imageSize = Size;   // "Stupid fallback?"

    if (!NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &baseAddr, NULL,
        &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
        panic("Failed to allocate cheat base!");

    if (!NT_SUCCESS(NtWriteVirtualMemory(NtCurrentProcess(), baseAddr, pData,
        imageSize, NULL)))
        panic("Failed to write cheat image!");
}
```

This function:
1. Finds resource `IDR_BINARY` (type `L"BINARY"`) — **resource #101**
2. Loads and locks the resource data
3. Allocates `MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE` at `baseAddr`
4. Writes the entire resource to the allocated memory

**b) Hardcoded base address** (`neverlose.h:28`):

```cpp
neverlose() : baseAddr((PVOID)0x412A0000), imageSize(0x3501000), hThis(nullptr) {};
```

The base address `0x412A0000` is **hardcoded** in the source. This matches
exactly the observed live allocation base (CONFIRMED via VirtualQueryEx).

**c) `load_res_to_mem()`** (`neverlose.cpp:49-76`):

A similar function that loads any resource by IDR into a freshly allocated
MEM_PRIVATE EXECUTE_READWRITE region. Used for additional resources
(possibly Block 2 at `0x4205a000`).

**d) Initialization order** (`main.cpp:4-19`):

```
DllMain(DLL_PROCESS_ATTACH)
    -> DisableThreadLibraryCalls
    -> apply_missing_entity_fix()
    -> NtCreateThreadEx(MainThread, hinstDLL)

MainThread(hinstDLL)
    -> g_neverlose.map(hinstDLL)          [manual self-map: resource #101 -> 0x412a0000]
    -> wait for serverbrowser.dll
    -> g_neverlose.fix_dump()             [fix imports, spoof, hooks, etc.]
    -> g_neverlose.set_veh()
    -> g_neverlose.setup_hooks()
    -> g_neverlose.spoof()
    -> g_neverlose.entry()
```

========================================
3. CORRELATION WITH LIVE MEMORY OBSERVATIONS
============================================

| Source claim | Live observation | Match? | Confidence |
|--------------|-----------------|--------|------------|
| `baseAddr = 0x412A0000` (neverlose.h:28) | Block 1 base = `0x412a0000` (VirtualQueryEx) | YES | CONFIRMED |
| `PAGE_EXECUTE_READWRITE` allocation | Block 1 protect = EXECUTE_READWRITE | YES | CONFIRMED |
| `MEM_COMMIT | MEM_RESERVE` | Block 1 State = MEM_COMMIT, Type = MEM_PRIVATE | YES | CONFIRMED |
| Writes `imageSize` bytes from resource | Block 1 size = `0x00dba000` | PARTIAL | Source says `0x3501000` (~53 MB), observed `0x00dba000` (~14 MB) — see §4 |
| Resource `IDR_BINARY` (#101) is the cheat binary | Resource #101 = 53 MB blob in .rsrc | YES | CONFIRMED |
| Loader uses LoadLibraryA | Injector source confirms | YES | CONFIRMED |
| DLL self-maps via map() | DLL source confirms | YES | CONFIRMED |

**Note on imageSize discrepancy:** Source code has `imageSize(0x3501000)` (~53 MB)
but observed Block 1 size is `0x00dba000` (~14 MB). Possible explanations:
- Source code version differs from running binary
- `imageSize` is the intended full size but allocation was truncated/partial
- `NtAllocateVirtualMemory` may round down or fail to allocate the full
  requested size at the requested address
- The source we have may be a different revision than the running binary

========================================
4. WHAT THE SOURCE PROVES vs ASSUMES
=====================================

**SOURCE-CONFIRMED (from FemboyLose-main/):**

| Claim | Source location |
|-------|-----------------|
| `baseAddr = 0x412A0000` hardcoded | `neverlose.h:28` |
| `map()` reads resource `IDR_BINARY` (#101) | `neverlose.cpp:19` |
| `map()` allocates `MEM_COMMIT\|MEM_RESERVE, PAGE_EXECUTE_READWRITE` | `neverlose.cpp:40` |
| `map()` writes resource via `NtWriteVirtualMemory` | `neverlose.cpp:45` |
| Injector uses `LoadLibraryA` via `CreateRemoteThread` | `injector/main.cpp:130-149` |
| `IDR_BINARY = 101` | `resource.h` |

**INFERRED (not directly in source, but strongly supported):**

| Claim | Basis |
|-------|-------|
| Resource #101 (53 MB blob) is the real cheat binary | Only large resource; `map()` copies it to executable memory |
| `map()` is called during DLL initialization | `main.cpp:6` calls `g_neverlose.map()` in MainThread |
| The live code at 0x412a0000+ is decrypted/de-serialized resource #101 | `map()` does a straight `NtWriteVirtualMemory` of resource bytes; live code is valid x86 while resource bytes are `a6 c0 4e c9…` |

**NOT PROVEN by source:**

| Claim | Why not proven |
|-------|----------------|
| How resource #101 is decrypted/decoded | `map()` does a straight memory copy; no decryption routine visible |
| The exact relationship between on-disk `.rsrc` #101 and live code | Source shows copy, but live code bytes differ from resource bytes |
| Whether `fix_dump()` modifies the mapped image after `map()` | Source exists but not fully analyzed for this purpose |

========================================
5. CONTRADICTIONS RESOLVED
=====================================

| Previous claim | Resolution | Basis |
|---------------|------------|-------|
| "neverlose.dll is manually mapped at 0x412a0000" | Partially correct: the DLL is first loaded via LoadLibraryA, THEN `neverlose::map()` copies resource #101 to 0x412a0000 | Injector source (LoadLibraryA) + DLL source (map()) |
| "0x412a0000 is the PE image base" | CONTRADICTED: base has no PE header; it's a private allocation filled with resource bytes | Live memory + source |
| "0x412a0000-0x4205a000 is the neverlose.dll image" | Partially correct: it contains the cheat code from resource #101, but it's not a PE image | VirtualQueryEx + source |

========================================
6. LIMITATIONS
================================

- The loader source (`injector/main.cpp`) confirms `LoadLibraryA` injection,
  but we cannot confirm that this exact source built the `loader.exe` on disk
  (no loader source was verified against the loader binary).
- The `neverlose::map()` source shows a straight memory copy of resource
  #101, but the live code bytes differ from the resource bytes on disk.
  Either the resource is already executable (obfuscated/packed), or
  decryption happens in a step not visible in the source we reviewed
  (e.g., `fix_dump()`, `install_crypto_capture()`, or `entry()`).
- `imageSize` in source (`0x3501000`) doesn't match observed Block 1 size
  (`0x00dba000`). Source version mismatch or partial allocation.

========================================
END
========================================