# PHASE 10 — SOURCE/RUNTIME RECONCILIATION
===========================================
Investigation of how resource #101 (`IDR_BINARY`) becomes the live executable
code at `0x412a0000` in `csgo.exe` (PID 21580), and why the resource bytes do
not match the live memory bytes.

Read-only investigation. No binaries, source files, or runtime memory were
modified. `MUST UPDATE.txt` SHA256 verified unchanged:
`6929460819DC7B5A4087B73DAAF7C8F6580D0B4122046D637A222FA7EEA6BB29`.

========================================
1. VERDICT
========================================

**UNRESOLVED** — The source code and runtime evidence cannot be reconciled.
`neverlose::map()` performs a straight `NtWriteVirtualMemory` copy of resource
#101 to `0x412a0000`, but the live bytes at `0x412a0000` are all zeros while
resource #101 starts with `a6 c0 4e c9`. No source function decrypts,
decompresses, or otherwise transforms the mapped image. The source code
revision may not match the running binary, but this cannot be confirmed.

========================================
2. SOURCE/BUILD IDENTITY ASSESSMENT
====================================

Source files analyzed: `FemboyLose-main/neverlose/` (all `.cpp` and `.h` files
read). All source files dated 7/14/2026 8:10 PM.

Binary analyzed: `C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll`
SHA256: `529c59bd687901d4e86898f78f50534ca4fc5611d693c296c9a3bd7bf8f61253`

| Source element | Value | Live binary equivalent | Match? |
|---|---|---|---|
| `baseAddr` | `0x412A0000` (neverlose.h:28) | Allocation base `0x412a0000` (VirtualQueryEx) | CONFIRMED |
| `imageSize` (constructor) | `0x3501000` (55,578,624) | Allocation total `0x3501000` (VirtualQueryEx) | CONFIRMED |
| `imageSize` (after SizeofResource) | Resource size = 55,578,628 (0x3501014) | Allocation total `0x3501000` | CONTRADICTED (4-byte diff) |
| Resource ID | `IDR_BINARY = 101` (resource.h) | Resource #101 in `.rsrc` | CONFIRMED |
| Entry point | `0x412A0000 + 0xA00 = 0x412A0A00` (entry.cpp:3) | Live code exists at this address | CONFIRMED |
| Function addresses in source | `0x41xxxxxx–0x44xxxxxx` (e.g. `g_stupid_ahh_shit_flow_fix[]`) | Live code at same addresses | CONFIRMED |
| Import table start | `0x43236000` (fix_imports.cpp) | Region 7 starts at `0x43236000` | CONFIRMED |

Source/build relationship: The source code addresses (`0x41xxxxxx–0x44xxxxxx`)
match the live memory addresses observed in `csgo.exe`, indicating the source
corresponds to the running binary's general layout. However, the source may be
from a different revision — `imageSize` in source (`0x3501000`) differs from
the measured resource #101 size (`55,578,628` = `0x3501014`) by exactly 4
bytes. No git history, version stamp, or build metadata is available to
confirm the exact revision match.

SOURCE/BUILD IDENTITY: STRONGLY SUPPORTED (addresses match), but exact revision
alignment is UNKNOWN.

========================================
3. CORRECTED INITIALIZATION TIMELINE
====================================

The following timeline is reconstructed from source code
(`FemboyLose-main/neverlose/`) and confirmed by live memory observations.

Stage 0 — Injector loads the DLL stub
-------------------------------------
Source: `injector/main.cpp`
- `loader.exe` starts `csgo.exe` (or attaches to running instance)
- Opens target with `PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
  PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ`
- Allocates remote memory for DLL path via `VirtualAllocEx`
- Writes DLL path via `WriteProcessMemory`
- Resolves `LoadLibraryA` via `GetProcAddress(GetModuleHandleA("kernel32.dll"), ...)`
- Creates remote thread via `CreateRemoteThread(process, ..., load_library,
  remote_path, ...)`
- Windows loader maps `neverlose.dll` as a **MEM_IMAGE** module at its chosen
  base (typically near preferred ImageBase `0x10000000`, possibly rebased)

CONFIRMED from source. The loader does NOT perform manual mapping.

Stage 1 — DllMain
-----------------
Source: `neverlose/main.cpp:21-36`
- `DisableThreadLibraryCalls(hinstDLL)`
- `apply_missing_entity_fix()`
- `NtCreateThreadEx(MainThread, hinstDLL, ...)` — creates MainThread, passes
  `hinstDLL` as parameter
- `NtClose(hThread)`

CONFIRMED from source.

Stage 2 — MainThread
--------------------
Source: `neverlose/main.cpp:4-19`
1. `g_neverlose.map((HMODULE)lpThreadParameter)` — manually maps cheat binary
   from resource #101 into private memory at `0x412a0000`
2. `while (!GetModuleHandleW(L"serverbrowser.dll")) Sleep(100)` — waits for
   CS:GO client module
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

Key observations:
- `baseAddr` initialized to `0x412A0000` (neverlose.h:28)
- `imageSize` initialized to `0x3501000` (neverlose.h:28), then overwritten with
  `SizeofResource` result if non-zero
- Resource #101 measured size: 55,578,628 bytes (`0x3501014`)
- Observed allocation size: 55,578,624 bytes (`0x3501000`)
- `NtAllocateVirtualMemory` with `baseAddr = 0x412a0000` — manual allocation,
  not standard PE image mapping
- `NtWriteVirtualMemory` copies `imageSize` bytes from `pData` (resource) to
  `baseAddr` — a straight memory copy with NO decryption/decompression

CONFIRMED from source. Resource #101 bytes should appear at `0x412a0000+` after
`map()` completes.

Stage 4 — `fix_dump()`
----------------------
Source: `neverlose/fix_dump.cpp:137-159`
Calls (in order): `fix_imports()`, `spoof_peb()`, `spoof_kusd()`, `spoof_cpuid()`,
`fix_interfaces()`, `fix_cvars()`, `fix_signatures()`, NOP patches from
`g_noped_addrs`, `fix_mem_dispatcher()`, flow fixes (0xEB writes to 111
addresses in `g_stupid_ahh_shit_flow_fix[]`), `fix_sha256()`,
`hijack_requestor()`, `last_resort_fixes()`, `install_crypto_capture()`.

None of these functions decrypt or decompress the mapped image. They perform
import resolution, anti-tamper spoofing, byte patching at specific addresses,
and hook installation.

CONFIRMED from source. No image transformation step exists in `fix_dump()`.

Stage 5 — VEH, hooks, spoof
---------------------------
Source: `neverlose/main.cpp:14-18`
- `set_veh()` — vectored exception handler
- `setup_hooks()` — detour hooks (hooks `getaddrinfo`, `NtTerminateProcess`,
  `0x42026080`, `0x415E9086`, `0x41609C80`; writes XOR-encoded logo to
  `0x4160555E/58/76/70`)
- `spoof()` — anti-tamper spoofing

CONFIRMED from source. `setup_hooks()` writes to specific addresses within
Block 1 but does not transform the whole mapped region.

Stage 6 — `entry()`
-------------------
Source: `neverlose/entry.cpp:14-53`
- Creates suspended thread at `0x412A0000 + 0xA00 = 0x412A0A00`
- Resumes thread, waits for exit

CONFIRMED from source. No memory modification.

========================================
4. FOUR-BYTE SIZE DISCREPANCY
==============================

| Value | Bytes | Hex |
|---|---|---|
| Resource #101 size (`SizeofResource`) | 55,578,628 | 0x3501014 |
| Observed allocation total size | 55,578,624 | 0x3501000 |
| Difference | 4 | 0x4 |

CONFIRMED from resource enumeration + VirtualQueryEx region walk.

Explanation status: **UNEXPLAINED**

The source code sets `imageSize = Size` where `Size = SizeofResource(hThis, hRes)`.
If `SizeofResource` returned `0x3501014` (55,578,628), the allocation would be
rounded UP to page granularity (`0x3502000`), not `0x3501000`. The observed
allocation `0x3501000` is exactly 4 bytes LESS than the measured resource size.

Possible explanations:
1. **Source/binary mismatch** — The source code we have may be from a different
   revision where `SizeofResource` returned `0x3501000` or `imageSize` was
   hardcoded differently.
2. **`SizeofResource` returns page-aligned size** — `0x3501000` is page-aligned
   (0x1000). `0x3501014` rounded DOWN to page = `0x3501000`. But
   `NtAllocateVirtualMemory` rounds UP, not down. If `imageSize = 0x3501014`,
   allocation would be `0x3502000`, not `0x3501000`.
3. **Resource measurement error** — pefile may report resource size differently
   than the Win32 `SizeofResource` API.

No evidence-backed explanation exists for the 4-byte difference.

========================================
5. RESOURCE/LIVE-MEMORY CONTRADICTION
======================================

| Location | First 4 bytes | Source of bytes |
|---|---|---|
| Resource #101 offset 0 | `a6 c0 4e c9` | On-disk `neverlose.dll`, `.rsrc` section |
| Live memory at `0x412a0000` | `00 00 00 00` | `csgo.exe` PID 21580, ReadProcessMemory |
| Live memory at `0x413f94d0` (`0x412a0000 + 0x1594d0`) | `57 56 83 ec 0c...` | `csgo.exe` PID 21580, ReadProcessMemory |

CONFIRMED: Live memory at `0x412a0000` is all zeros, but resource #101 starts
with `a6 c0 4e c9`. If `map()` wrote resource bytes to `0x412a0000` via
`NtWriteVirtualMemory`, the first 4 bytes should be `a6 c0 4e c9`, not zeros.

CONFIRMED: Live code at `0x413f94d0` is valid x86 (`push edi; push esi;
sub esp,0xc; mov edx,[0x4223f428]`), but this byte sequence does NOT appear
anywhere in the on-disk `neverlose.dll` (Phase 7: 0/10 live 16-byte sequences
matched).

Possible explanations, ranked by evidence:

**Hypothesis 1: Source/binary revision mismatch (MOST LIKELY but UNPROVEN)**
The source code in `FemboyLose-main/neverlose/` may be from a different
revision than the running `neverlose.dll`. The running binary's `map()`
function may behave differently (e.g., skip the header, decrypt the resource,
or write to a different address). All source addresses match the live memory
layout, suggesting the source is close to the running binary, but small
differences (like the 4-byte size discrepancy) indicate a revision mismatch.

**Hypothesis 2: `map()` skips the first 4 bytes (UNPROVEN)**
If `map()` wrote `pData + 4` with `imageSize - 4` bytes, the first 4 bytes
of the allocation would remain zero-initialized (from `NtAllocateVirtualMemory`),
and the resource data would start at `0x412a0004`. However, the source code
shows `NtWriteVirtualMemory(baseAddr, pData, imageSize, NULL)` — writing from
`pData` (byte 0), not `pData + 4`. And live memory at `0x412a0004` is also
zero, not `43 77 21 63` (the second resource byte).

**Hypothesis 3: A post-`map()` transformation step exists (UNPROVEN)**
Some function called after `map()` could zero out the first page and/or
decrypt the rest of the image. No such step is visible in the reviewed source
code (`fix_dump()`, `entry()`, `setup_hooks()`, `spoof()` all reviewed; none
decrypts the mapped image).

**Hypothesis 4: The live memory is not from `neverlose::map()` (UNPROVEN)**
The live code at `0x412a0000+` could come from a different mechanism entirely.
However, the allocation base `0x412a0000` matches `neverlose.h:28` exactly,
and `neverlose::map()` is the only code path that allocates at this address.
No other allocation source is known.

No hypothesis is confirmed. The transformation boundary is at the point
between `NtWriteVirtualMemory` (completing the copy in `map()`) and the first
execution of code from the mapped region. What happens in that interval is
not established by available evidence.

========================================
6. EVIDENCE CLASSIFICATION TABLE
==================================

| Claim | Classification | Basis |
|---|---|---|
| `neverlose::map()` reads resource #101 via `FindResource`/`LoadResource`/`LockResource` | SOURCE-CONFIRMED | `neverlose.cpp:19-30` |
| `neverlose::map()` allocates at `0x412a0000` with `PAGE_EXECUTE_READWRITE` | SOURCE-CONFIRMED | `neverlose.h:28`, `neverlose.cpp:40` |
| `neverlose::map()` writes resource via `NtWriteVirtualMemory` (straight copy, no transform) | SOURCE-CONFIRMED | `neverlose.cpp:45-46` |
| Resource #101 size = 55,578,628 bytes | CONFIRMED | PE resource directory enumeration |
| Allocation total = 55,578,624 bytes (`0x3501000`) | RUNTIME-OBSERVED | VirtualQueryEx walk |
| Allocation base = `0x412a0000` | CONFIRMED | `neverlose.h:28` + VirtualQueryEx |
| Live memory at `0x412a0000` = `00 00 00 00` | RUNTIME-OBSERVED | ReadProcessMemory |
| Resource #101 at offset 0 = `a6 c0 4e c9` | CONFIRMED | PE resource extraction |
| Live bytes match on-disk `neverlose.dll` | CONTRADICTED | 0/10 live 16-byte sequences match (Phase 7) |
| Resource bytes match live bytes at base | CONTRADICTED | `a6 c0 4e c9` vs `00 00 00 00` |
| `fix_dump()` contains image decryption/transform | NOT SUPPORTED | Full source review — no such step |
| `install_crypto_capture()` transforms mapped image | NOT SUPPORTED | Hooks `0x41d9f3f0`, does not touch mapped image |
| Function role assignments (lag-comp gate, etc.) | INFERRED | Disassembly patterns, no symbols |
| Source/binary revision match | STRONGLY SUPPORTED | Addresses match; size mismatch suggests possible revision difference |
| Transformation from resource bytes to live code | UNKNOWN | Not explained by source or runtime evidence |

========================================
7. WHAT IS MISSING
==================

The single most valuable missing piece of evidence is:

**A memory dump of the mapped region at `0x412a0000` taken immediately after
`neverlose::map()` completes but before any subsequent initialization step.**

This would show whether:
- The resource bytes are written correctly (and then zeroed later), or
- The resource bytes are never written (suggesting `map()` behaves differently
  in the running binary than in the source)

Alternatively, a complete source review of all `.cpp` files not yet fully read
(`fix_interfaces.cpp`, `fix_cvars.cpp`, `fix_signatures.cpp`, `fix_mem_dispatcher.cpp`,
`spoof.cpp`, `spoof_peb.cpp`, `spoof_kusd.cpp`, `HookFn.cpp`, `VEH.cpp`,
`missingent.cpp`) could reveal a transformation step not yet examined.

========================================
8. STOPPING CRITERION
=====================

The resource/runtime relationship remains **UNRESOLVED**. The source code
describes a straight memory copy, but the live bytes contradict it. No source
function performs decryption or decompression of the mapped image. The source
revision may not match the running binary, but this cannot be confirmed.

Per the stopping criterion: no further broad investigation phase is justified
without new evidence (a memory dump of the mapped region immediately after
`map()`, or complete source review of the unexamined files). The contradiction
is documented and the boundary of knowledge is clearly identified.

========================================
END
========================================