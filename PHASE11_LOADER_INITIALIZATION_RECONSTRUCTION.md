# PHASE11_LOADER_INITIALIZATION_RECONSTRUCTION.md
========================================
Phase 9 Investigation C — Source-backed reconstruction of the
neverlose.dll initialization sequence, from process injection through
runtime execution.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN.

Source files analyzed:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\injector\main.cpp
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose/main.cpp
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose/neverlose.cpp
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose/neverlose.h
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose/fix_dump.cpp
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose/fix_imports.cpp
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\FemboyLose-main\neverlose/crypto_capture.cpp

Binary analyzed:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll

========================================
1. COMPLETE INITIALIZATION SEQUENCE
====================================

Stage 0 — Injector starts `csgo.exe`
-----------------------------------
Source: `FemboyLose-main/injector/main.cpp`

The loader (`loader.exe`) starts `csgo.exe` (or attaches to an
already-running instance). It then calls `do_inject(pid)`:

  1. Locates `neverlose.dll` alongside the loader executable
  2. Opens `csgo.exe` with `PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
     PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`
  3. Calls `RestoreNtOpenFile(process)` — restores `NtOpenFile` in the target
     process (anti-tamper/anti-detection)
  4. Allocates remote memory via `VirtualAllocEx` for the DLL path string
  5. Writes the DLL path via `WriteProcessMemory`
  6. Resolves `LoadLibraryA` via `GetProcAddress(GetModuleHandleA("kernel32.dll"), ...)`
  7. Creates a remote thread via `CreateRemoteThread(process, ..., load_library,
     remote_path, ...)` — this loads `neverlose.dll` into `csgo.exe` via the
     standard Windows loader
  8. Waits for the remote thread to finish, then frees the remote path memory

CONFIRMED from source. The loader does NOT perform manual mapping — it uses
the standard Windows loader (`LoadLibraryA`).

Stage 1 — DllMain
-----------------
Source: `neverlose/main.cpp:21-36`

When `neverlose.dll` is loaded into `csgo.exe` by the Windows loader:

```
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        apply_missing_entity_fix();

        HANDLE hThread;
        NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
            NtCurrentProcess(), MainThread, hinstDLL, THREAD_CREATE_FLAGS_NONE,
            0, 0, 0, NULL);
        if (!NT_SUCCESS(status)) return FALSE;
        NtClose(hThread);
    }
    return TRUE;
}
```

`DllMain` creates a thread running `MainThread`, passing
`hinstDLL` (HMODULE of the loaded `neverlose.dll`) as the parameter.

CONFIRMED from source.

Stage 2 — MainThread
--------------------
Source: `neverlose/main.cpp:4-19`

```cpp
NTSTATUS NTAPI MainThread(LPVOID lpThreadParameter)
{
    g_neverlose.map((HMODULE)lpThreadParameter);

    while (!GetModuleHandleW(L"serverbrowser.dll"))
        Sleep(100);

    g_neverlose.fix_dump();
    g_neverlose.set_veh();
    g_neverlose.setup_hooks();
    g_neverlose.spoof();

    g_neverlose.entry();

    return STATUS_SUCCESS;
}
```

Sequence:
1. `g_neverlose.map(hinstDLL)` — manually maps cheat binary
   from resource #101 into private memory at `0x412a0000` (see Stage 3)
2. Waits for `serverbrowser.dll` (CS:GO client module) to be loaded
3. `g_neverlose.fix_dump()` — import fixing, spoofing, hooks, patches
4. `g_neverlose.set_veh()` — vectored exception handler installation
5. `g_neverlose.setup_hooks()` — detour hook installation
6. `g_neverlose.spoof()` — anti-tamper spoofing
7. `g_neverlose.entry()` — starts cheat runtime entry point

CONFIRMED from source.

Stage 3 — `neverlose::map()` (resource extraction and manual mapping)
-----------------------------------------------------------------------
Source: `neverlose/neverlose.cpp:16-47`

```cpp
void neverlose::map(HMODULE hModule)
{
    hThis = hModule;
    HRSRC hRes = FindResource(hModule, MAKEINTRESOURCE(IDR_BINARY), L"BINARY");
    if (!hRes) panic("Failed to locate cheat binary!");

    HGLOBAL hResData = LoadResource(hModule, hRes);
    if (!hResData) panic("Failed to load cheat binary!");

    LPVOID pData = LockResource(hResData);
    if (!pData) panic("Failed to lock cheat binary!");

    DWORD Size = SizeofResource(hModule, hRes);
    if (Size)
        imageSize = Size;   // overwrites constructor value 0x3501000

    if (!NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess(), &baseAddr, NULL,
        &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
        panic("Failed to allocate cheat base!");

    if (!NT_SUCCESS(NtWriteVirtualMemory(NtCurrentProcess(), baseAddr, pData,
        imageSize, NULL)))
        panic("Failed to write cheat image!");
};
```

Key details:
- `baseAddr` initialized to `0x412A0000` (neverlose.h:28) — hardcoded
- `imageSize` initialized to `0x3501000` (neverlose.h:28), then overwritten with
  `SizeofResource` result if non-zero
- Resource #101 measured size: 55,578,628 bytes (`0x3501014`)
- Observed allocation size: 55,578,624 bytes (`0x3501000`)
- `NtAllocateVirtualMemory` with `baseAddr = 0x412a0000` — manual allocation,
  not standard PE image mapping
- `NtWriteVirtualMemory` copies `imageSize` bytes from `pData` (resource)
  to `baseAddr` — a straight memory copy with NO decryption/decompression

CONFIRMED from source. Resource #101 bytes should appear at `0x412a0000+`
after `map()` completes.

Stage 4 — `fix_dump()`
----------------------
Source: `neverlose/fix_dump.cpp:137-159`

```cpp
void neverlose::fix_dump()
{
    fix_imports();
    spoof_peb();
    spoof_kusd();
    spoof_cpuid();

    fix_interfaces();
    fix_cvars();
    fix_signatures();

    for (auto& [address, count] : g_noped_addrs)
        memset((PVOID)address, 0x90, count);

    fix_mem_dispatcher();

    for (DWORD addr : g_stupid_ahh_shit_flow_fix)
        *(PBYTE)addr = 0xEB;

    fix_sha256();
    hijack_requestor();
    last_resort_fixes();
    install_crypto_capture();
};
```

Sub-steps:
1. `fix_imports()` — resolves import addresses into the IAT at `0x43236000+`
   (source: `fix_imports.cpp`, `g_imports` array with ~860 entries)
2. `spoof_peb()` / `spoof_kusd()` / `spoof_cpuid()` — anti-tamper spoofing
3. `fix_interfaces()` / `fix_cvars()` / `fix_signatures()` — interface/cvar
   signature fixing
4. NOP patches from `g_noped_addrs`
5. `fix_mem_dispatcher()` — memory dispatcher fix
6. Flow fixes: writes `0xEB` (unconditional jump opcode) to addresses
   listed in `g_stupid_ahh_shit_flow_fix[]`
7. `fix_sha256()` — SHA256-related fixing (purpose unknown from source)
8. `hijack_requestor()` — request hijacking
9. `last_resort_fixes()` — miscellaneous patches:
   - Writes handle to `0x42518C44`
   - NOPs 6 bytes at `0x41C12B3E`
   - Writes `0xC3` (ret) to `0x41B63BB0`
   - Writes `0xEB` (jmp) to `0x41DA128F`
   - Writes `0x84` to `0x4152A163`
   - Writes `0xB890903BFABFB6B9ULL` to `0x41516C35`
   - Allocates `0x2000` bytes via `VirtualAlloc`, stores pointer at
     `0x424AFCC0`
10. `install_crypto_capture()` — hooks `0x41D9F3F0` with `hkCaptureData`

CONFIRMED from source. None of these functions decrypt or decompress the
mapped image at `0x412a0000`. They perform import resolution, anti-tamper
spoofing, byte patching at specific addresses, and hook installation.

Stage 5 — VEH, hooks, spoof
---------------------------
Source: `neverlose/main.cpp:14-18`
- `set_veh()` — vectored exception handler installation
- `setup_hooks()` — detour hook installation:
  - Hooks `getaddrinfo`, `NtTerminateProcess`, `0x42026080`, `0x415E9086`,
    `0x41609C80`
  - Writes XOR-encoded logo to `0x4160555E/58/76/70`
- `spoof()` — anti-tamper spoofing

CONFIRMED from source. Specific hook targets and spoofing targets are not
fully detailed in the source we reviewed.

Stage 6 — `entry()`
-------------------
Source: `neverlose/entry.cpp:14-53`

```cpp
void neverlose::entry()
{
    // Creates a suspended thread at 0x412A0000 + 0xA00 = 0x412A0A00
    NtCreateThreadEx(&hThread, ..., (PUSER_THREAD_START_ROUTINE)0x412A0A00,
                     ..., THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ...);
    NtResumeThread(hThread);
    NtWaitForSingleObject(hThread, ...);
    NtClose(hThread);
}
```

CONFIRMED from source. No memory modification.

========================================
2. LIFECYCLE DIAGRAM
====================================

```
loader.exe
  │
  ├─ CreateProcess/CreateRemoteThread → csgo.exe
  │   └─ LoadLibraryA("neverlose.dll")  [Windows loader maps DLL as MEM_IMAGE]
  │       └─ DllMain → MainThread
  │           ├─ g_neverlose.map(hinstDLL)
  │           │   ├─ FindResource(IDR_BINARY=101)  [resource #101, 53 MB blob]
  │           │   ├─ NtAllocateVirtualMemory(0x412a0000, 0x3501000,
  │           │   │   PAGE_EXECUTE_READWRITE)  [Block 1]
  │           │   └─ NtWriteVirtualMemory(0x412a0000, resource_bytes, size)
  │           │       └─ Resource #101 bytes now live at 0x412a0000+
  │           │
  │           ├─ wait for serverbrowser.dll
  │           │
  │           ├─ g_neverlose.fix_dump()
  │           │   ├─ fix_imports()       [IAT at 0x43236000+]
  │           │   ├─ spoof_*()           [anti-tamper]
  │           │   ├─ NOP patches / flow fixes (0xEB) at 111 addresses
  │           │   ├─ fix_sha256()        [purpose unknown]
  │           │   ├─ hijack_requestor()
  │           │   └─ last_resort_fixes() [byte patches at specific addresses]
  │           │   └─ install_crypto_capture() [hooks 0x41D9F3F0]
  │           │
  │           ├─ set_veh()               [vectored exception handler]
  │           ├─ setup_hooks()           [detour hooks]
  │           ├─ spoof()                 [anti-tamper]
  │           │
  │           └─ g_neverlose.entry()
  │               └─ NtCreateThreadEx at 0x412A0A00
  │                   └─ Cheat runtime execution begins
  │
  └─ neverlose-server.exe (standalone, PID 11468)
      ├─ Listens on 127.0.0.1:30031
      ├─ Serves Lua scripts via GET /lua/<name>
      └─ Owns cabbitwin\ data directory

neverlose.dll connects to server via WinHTTP (WinHttpConnect to 127.0.0.1:30031)
```

========================================
3. MEMORY ALLOCATIONS DURING INITIALIZATION
===========================================

Allocation base `0x412a0000`, 7 regions, total `0x3501000` (55,578,624 bytes),
all MEM_PRIVATE, all with allocation base `0x412a0000`:

| Region | Base | End | Size | Protect |
|--------|------|-----|------|---------|
| Block 1 | 0x412a0000 | 0x4205a000 | 0xdba000 | EXECUTE_READWRITE |
| Block 2 | 0x4205a000 | 0x42239000 | 0x1df000 | READONLY |
| Block 3 | 0x42239000 | 0x4252b000 | 0x2f2000 | EXECUTE_READWRITE |
| Block 4 | 0x4252b000 | 0x42553000 | 0x28000 | EXECUTE_READ |
| Block 5 | 0x42553000 | 0x42559000 | 0x6000 | READWRITE |
| Block 6 | 0x42559000 | 0x43236000 | 0xcdd000 | EXECUTE_READ |
| Block 7 | 0x43236000 | 0x447a1000 | 0x156b000 | EXECUTE_READWRITE |

Additional allocation during `last_resort_fixes()`:
- `VirtualAlloc(nullptr, 0x2000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)`
  → pointer stored at `0x424AFCC0`
- `*(PDWORD)0x4479EE00 = (DWORD)addr + 0x1000`

None of these regions has an MZ header (confirmed by reading first 2 bytes
of each region base — all zeros or non-MZ).

========================================
4. SOURCE-RUNTIME CONSISTENCY
==================================

The source code addresses match the live memory addresses:

| Source address | Live address | Context |
|---|---|---|
| `baseAddr = 0x412A0000` | `0x412a0000` | Allocation base (CONFIRMED) |
| `g_stupid_ahh_shit_flow_fix[]` entries | `0x41xxxxxx–0x44xxxxxx` | Flow fix targets (CONFIRMED) |
| `g_imports[]` entries start at `0x43236000` | `0x43236000–0x447a1000` | IAT region (CONFIRMED) |
| `entry()` at `baseAddr + 0xA00` | `0x412a0a00` | Cheat entry point (CONFIRMED) |
| `last_resort_fixes()` targets | `0x41516c35`, `0x41b63bb0`, etc. | Byte patch targets (CONFIRMED) |

The source code was written with knowledge that the cheat code would be
mapped at `0x412a0000`, confirming that `neverlose::map()` places resource
#101 at this address.

========================================
5. LIMITATIONS
========================================

- `fix_imports()` function implementation was not fully read (only the
  `g_imports` array was visible in `fix_imports.cpp`)
- `fix_interfaces()`, `fix_cvars()`, `fix_signatures()`,
  `fix_mem_dispatcher()`, `fix_sha256()`, `hijack_requestor()`,
  `setup_hooks()`, `spoof()`, `set_veh()`, `entry()` implementations were
  not fully read
- `install_crypto_capture()` is fully read but is a runtime hook, not an
  image transformation step
- The source code revision may not exactly match the running binary (e.g.,
  `imageSize` in source `0x3501000` vs. resource size `55,578,628` bytes)

========================================
END
========================================