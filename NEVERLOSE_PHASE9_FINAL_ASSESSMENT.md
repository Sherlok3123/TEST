# NEVERLOSE PHASE 9 FINAL ASSESSMENT
====================================
Phase 9 — Resource #101 transformation and initialization lifecycle
assessment for the Neverlose.dll deep static analysis project.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. FINAL STATUS
====================================

**PARTIALLY RESOLVED**

The resource-to-runtime transformation and initialization lifecycle are
partially established. The mechanism by which resource #101 is loaded into
memory is source-confirmed, but the transformation that converts the
resource bytes into live executable code is NOT explained by the available
evidence.

========================================
2. WHAT IS ESTABLISHED
====================================

2.1 Source-confirmed initialization lifecycle (CONFIRMED)

| Stage | Source | Action |
|---|---|---|
| DLL injection | `injector/main.cpp:141` | `CreateRemoteThread` with `LoadLibraryA("neverlose.dll")` |
| DLL entry | `neverlose/main.cpp:21` | `DllMain` → `NtCreateThreadEx(MainThread, ...)` |
| Resource mapping | `neverlose/neverlose.cpp:16-47` | `map()` reads resource #101, allocates at `0x412a0000`, `NtWriteVirtualMemory` copies resource bytes |
| Import fixing | `neverlose/fix_dump.cpp:139` | `fix_imports()` resolves IAT at `0x43236000+` |
| Hook installation | `neverlose/main.cpp:15` | `setup_hooks()` installs detour hooks |
| Crypto capture | `neverlose/crypto_capture.cpp:12` | `install_crypto_capture()` hooks `0x41d9f3f0` |
| Cheat entry | `neverlose/entry.cpp` | Thread at `0x412a0a00` (`baseAddr + 0xa00`) |

2.2 Runtime-observed memory (CONFIRMED)

- Allocation base `0x412a0000`, 7 regions, total `0x3501000` (55,578,624 bytes)
- All MEM_PRIVATE, no PE header at base, no MEM_IMAGE modules in range
- Block 1 EXECUTE_READWRITE, Block 2 READONLY, Blocks 3-7 mixed protections
- All 10 previously reported function addresses are inside Block 1
- All live bytes at reported addresses are valid x86 code
- Internal call graph confirmed (`0x4140cb75` → `0x41b6c700`)
- None of the live byte sequences match the on-disk `neverlose.dll`

2.3 Resource #101 (CONFIRMED)

| Property | Value |
|---|---|
| ID | 101 (`IDR_BINARY`) |
| Type | `L"BINARY"` |
| RVA | `0x0006d170` |
| Size | 55,578,628 bytes |
| First 4 bytes | `a6 c0 4e c9` |
| SHA256 | `c219ed6b999bfcc1346160b8f574278460c2ae1aaf04a2a8c1da02151b02d21d` |
| Known format | None (not PE, Lua, PNG, JPEG, ZIP, ELF) |

========================================
3. WHAT REMAINS UNKNOWN
====================================

3.1 Resource-to-live-byte transformation (UNKNOWN)

`neverlose::map()` performs a straight `NtWriteVirtualMemory` copy of
resource #101 to `0x412a0000`. However:

- Resource #101 starts with `a6 c0 4e c9`
- Live memory at `0x412a0000` starts with `00 00 00 00`
- No decryption/decompression routine is visible in the reviewed source
- `fix_dump()` contains no image transformation step
- `install_crypto_capture()` hooks `0x41d9f3f0` but is a runtime data
  capture hook, not an image transformer

The transformation from resource bytes to live executable code is
**NOT established** by the available evidence.

3.2 Size discrepancy (UNKNOWN)

- Resource #101: 55,578,628 bytes
- Observed allocation: 55,578,624 bytes (0x3501000)
- Difference: 4 bytes (exactly the size of the resource's first 4 bytes)

It is unclear whether:
- The first 4 bytes are skipped during the copy
- The first 4 bytes are copied but then zeroed
- The source code revision differs from the running binary

3.3 Function role assignments (INFERRED)

The specific roles of functions at reported addresses (lag-comp gate,
record selection, aim consumer, etc.) were determined from disassembly
patterns in earlier phases. These remain INFERRED — no symbol names or
source code confirms them.

3.4 Function-to-DLL attribution (CONTRADICTED for on-disk DLL)

The 10 reported function addresses do NOT correspond to any byte sequence
in the on-disk `neverlose.dll`. They belong to resource #101 code in the
MEM_PRIVATE allocation at `0x412a0000`, but the resource bytes themselves
do not match the live bytes.

========================================
4. EVIDENCE CLASSIFICATION SUMMARY
====================================

| Claim | Classification | Basis |
|---|---|---|
| `neverlose::map()` reads resource #101 | SOURCE-CONFIRMED | `neverlose.cpp:19` |
| `neverlose::map()` allocates at `0x412a0000` | SOURCE-CONFIRMED | `neverlose.h:28` |
| `neverlose::map()` writes resource via `NtWriteVirtualMemory` | SOURCE-CONFIRMED | `neverlose.cpp:45` |
| Resource #101 size = 55,578,628 bytes | CONFIRMED | PE resource directory |
| Allocation total = 55,578,624 bytes (0x3501000) | RUNTIME-OBSERVED | VirtualQueryEx walk |
| Allocation base = `0x412a0000` | CONFIRMED | `neverlose.h:28` + VirtualQueryEx |
| Live code at reported addresses is valid x86 | RUNTIME-OBSERVED | ReadProcessMemory |
| Live bytes match on-disk `neverlose.dll` | CONTRADICTED | 0/10 byte sequences match |
| Resource bytes match live bytes at base | CONTRADICTED | `a6 c0 4e c9` vs `00 00 00 00` |
| `fix_dump()` decrypts mapped image | NOT SUPPORTED | No such code in source |
| `install_crypto_capture()` transforms mapped image | NOT SUPPORTED | Hooks `0x41d9f3f0`, doesn't touch image |
| Function roles (lag-comp gate, aim consumer, etc.) | INFERRED | Disassembly patterns, no symbols |
| Transformation from resource to live code | UNKNOWN | Not explained by source or runtime evidence |

========================================
5. BOUNDARY OF KNOWLEDGE
====================================

The available evidence establishes:

1. **SOURCE-CONFIRMED**: `neverlose::map()` reads resource #101 (`IDR_BINARY`,
   53 MB blob in `.rsrc`) and writes it via `NtWriteVirtualMemory` to a
   MEM_PRIVATE EXECUTE_READWRITE region at hardcoded base `0x412a0000`.

2. **RUNTIME-OBSERVED**: The live code at `0x412a0000+` is valid, internally
   consistent x86 code with a coherent call graph, but does NOT match any
   byte sequence in the on-disk `neverlose.dll`.

3. **UNKNOWN (the boundary)**: The transformation between resource #101 bytes
   and live executable code is not explained by the available source code.
   `neverlose::map()` performs a straight memory copy, but the bytes differ.
   Either:
   - A decryption/decompression step exists in source code we haven't fully
     examined (`entry()`, `setup_hooks()`, or parts of `fix_dump()` we haven't
     read)
   - The source code revision does not match the running binary
   - The resource is transformed by a mechanism not visible in the available
     source

The correct result is that the resource/runtime relationship is **partially
established**: we know how the resource gets into memory, but not how it
becomes the executable code we observe.

========================================
6. WHAT WOULD RESOLVE THE REMAINING UNKNOWN
============================================

To fully resolve the resource-to-runtime transformation, one would need:

1. **The running binary's `neverlose.dll`** — a memory dump of the mapped
   region at `0x412a0000` compared against the on-disk `neverlose.dll` and
   resource #101, to identify the transformation
2. **Complete source review** — reading `entry.cpp`, `setup_hooks.cpp`,
   `spoof.cpp`, and any other source files not yet examined, to find any
   decryption or transformation code
3. **Runtime tracing** — instrumenting `NtWriteVirtualMemory` and memory
   protection changes in the running `csgo.exe` to observe when and how the
   mapped region is modified after `map()` completes
4. **Resource #101 decoding** — determining whether the resource is
   encrypted, compressed, or encoded, and if so, with what algorithm/key

========================================
7. SOURCE CODE REVISION NOTE
==============================

The source code in `FemboyLose-main/neverlose/` contains addresses in the
`0x41xxxxxx–0x44xxxxxx` range (e.g., `g_stupid_ahh_shit_flow_fix[]`,
`g_imports[]` at `0x43236000+`) that match the live memory addresses
observed in `csgo.exe`. This confirms the source corresponds to the running
binary's general layout. However, differences between source and binary
(e.g., `imageSize` = `0x3501000` vs. resource size 55,578,628 bytes) suggest
the source may be from a slightly different revision.

========================================
END
========================================