# NEVERLOSE EXECUTABLE REGION MAP
================================
Phase 8 — Region-by-region inventory of the `csgo.exe` (PID 21580) address
space around the reported function addresses, with memory type, protection,
allocation base, and ownership confidence.

Read-only. Based on `VirtualQueryEx` region walking and `ReadProcessMemory`
of the live process. All addresses are runtime virtual addresses.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. SCAN PARAMETERS
========================================

- Target process: `csgo.exe`, PID 21580
- Python pointer size: 8 bytes (64-bit Python)
- MEMORY_BASIC_INFORMATION size: 48 bytes
- Scanned range: `0x40000000–0x42200000` (covers Block 1 and Block 2)
- Total regions scanned: 82

========================================
2. FULL REGION INVENTORY (0x40000000–0x42200000)
============================================

| Base | AllocBase | RegionSize | State | Protect | Type | MZ? |
|------|-----------|------------|-------|---------|------|-----|
| 0x40000000 | 0x3fa00000 | 0x0001f000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x4001f000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40020000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40061000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40062000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x400a3000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x400a4000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x400e5000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x400e6000 | 0x3fa00000 | 0x00053000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40139000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x4013a000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x4017b000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x4017c000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x401bd000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x401be000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x401ff000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40200000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40241000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40242000 | 0x3fa00000 | 0x0005a000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x4029c000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x4029d000 | 0x3fa00000 | 0x00021000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x402be000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x402bf000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40300000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40301000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40342000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40343000 | 0x3fa00000 | 0x00053000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40396000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40397000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x403d8000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x403d9000 | 0x3fa00000 | 0x000f8000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x404d1000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x404d2000 | 0x3fa00000 | 0x00050000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40522000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40523000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40564000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40565000 | 0x3fa00000 | 0x00050000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x405b5000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x405b6000 | 0x3fa00000 | 0x00050000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40606000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40607000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40648000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40649000 | 0x3fa00000 | 0x00021000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x4066a000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x4066b000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x406ac000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x406ad000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x406ee000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x406ef000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40730000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40731000 | 0x3fa00000 | 0x00041000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40772000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40773000 | 0x3fa00000 | 0x00080000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x407f3000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x407f4000 | 0x3fa00000 | 0x0004f000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40843000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40844000 | 0x3fa00000 | 0x0014c000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40990000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x40991000 | 0x3fa00000 | 0x00028000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x409b9000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | NOACCESS | MEM_PRIVATE | - |
| 0x409ba000 | 0x3fa00000 | 0x00015000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x409cf000 | 0x3fa00000 | 0x00001000 | MEM_PRIVATE | 0x00000000 | MEM_PRIVATE | - |
| 0x409d0000 | 0x409d0000 | 0x00005000 | MEM_PRIVATE | 0x00000000 | MEM_PRIVATE | - |
| 0x409d5000 | 0x409d0000 | 0x00266000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40c3b000 | 0x409d0000 | 0x00001000 | MEM_PRIVATE | 0x00000000 | MEM_PRIVATE | - |
| 0x40c3c000 | 0x00000000 | 0x00004000 | MEM_MAPPED | NOACCESS | MEM_PRIVATE | - |
| 0x40c40000 | 0x40c40000 | 0x00020000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40c60000 | 0x40c60000 | 0x0000d000 | MEM_PRIVATE | 0x00000000 | MEM_PRIVATE | - |
| 0x40c6d000 | 0x40c60000 | 0x00282000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x40eef000 | 0x40c60000 | 0x00001000 | MEM_PRIVATE | 0x00000000 | MEM_PRIVATE | - |
| 0x40ef0000 | 0x40ef0000 | 0x0017b000 | MEM_PRIVATE | 0x00000000 | MEM_PRIVATE | - |
| 0x4106b000 | 0x40ef0000 | 0x00002000 | MEM_PRIVATE | 0x00000104 | MEM_PRIVATE | - |
| 0x4106d000 | 0x40ef0000 | 0x00003000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x41070000 | 0x41070000 | 0x0017c000 | MEM_PRIVATE | 0x00000000 | MEM_PRIVATE | - |
| 0x411ec000 | 0x41070000 | 0x00002000 | MEM_PRIVATE | 0x00000104 | MEM_PRIVATE | - |
| 0x411ee000 | 0x41070000 | 0x00002000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x411f0000 | 0x411f0000 | 0x00003000 | MEM_PRIVATE | 0x00000000 | MEM_PRIVATE | - |
| 0x411f3000 | 0x411f0000 | 0x0009e000 | MEM_PRIVATE | READWRITE | MEM_PRIVATE | - |
| 0x41291000 | 0x411f0000 | 0x00001000 | MEM_PRIVATE | 0x00000000 | MEM_PRIVATE | - |
| 0x41292000 | 0x00000000 | 0x0000e000 | MEM_MAPPED | NOACCESS | MEM_PRIVATE | - |
| 0x412a0000 | 0x412a0000 | 0x00dba000 | MEM_PRIVATE | EXECUTE_READWRITE | MEM_PRIVATE | - |
| 0x4205a000 | 0x412a0000 | 0x001df000 | MEM_PRIVATE | READONLY | MEM_PRIVATE | - |

Total regions in range: 82
MEM_IMAGE regions: 0
MEM_PRIVATE executable regions: 2 (Block 1 and Block 2)

========================================
3. KEY REGIONS: BLOCK 1 AND BLOCK 2
===================================

**Block 1 — 0x412a0000–0x4205a000 (size 0x00dba000, ~13.9 MB)**
- Type: MEM_PRIVATE (private allocation, not image-backed)
- Protection: EXECUTE_READWRITE (PAGE_EXECUTE_READWRITE, 0x40)
- Allocation base: 0x412a0000 (self-referencing)
- MZ header: NO (confirmed all zeros at base, no PE signature)
- Contains: All 10 reported function addresses
- Source: `neverlose::map()` writes resource #101 (IDR_BINARY) here
  [FemboyLose-main/neverlose/neverlose.cpp:16-47]
- Confirmed: baseAddr = (PVOID)0x412A0000 hardcoded in neverlose.h:28

**Block 2 — 0x4205a000–0x42239000 (size 0x001df000, ~1.9 MB)**
- Type: MEM_PRIVATE (private allocation, not image-backed)
- Protection: READONLY (PAGE_READONLY, 0x02)
- Allocation base: 0x412a0000 (same as Block 1)
- MZ header: NO
- Contains: Unknown (read-only data associated with Block 1)
- Source: Likely another resource loaded by `load_res_to_mem()` or a
  read-only data section of the mapped cheat binary [neverlose.cpp:49-76]

========================================
4. PROTECTION ANALYSIS
=====================================

Block 1 is `EXECUTE_READWRITE` — both writable and executable. This is
unusual for a normal PE image (which typically has separate `.text` RX and
`.data` RW sections). The combined RWX protection is consistent with:

1. A manually allocated and written memory region (NtAllocateVirtualMemory
   with PAGE_EXECUTE_READWRITE, then NtWriteVirtualMemory to fill it)
2. A position where code is written then potentially re-protected later

The fact that Block 1 remains RWX (not split into RX code + RW data) suggests
either:
- The protection hasn't been changed yet (fix_dump() may do this later)
- The code is designed to remain RWX (unusual but possible)

Block 2 is READONLY — consistent with read-only data (constants, vtables,
etc.) associated with the mapped cheat binary.

========================================
5. NO MEM_IMAGE MODULES IN RANGE
================================

Notably, there are **zero MEM_IMAGE regions** in the scanned range
`0x40000000–0x42200000`. Every region is MEM_PRIVATE. This means:

- No standard PE module (DLL or EXE) is loaded at any address in this range
- The Windows loader did not map `neverlose.dll` here via the normal image
  path
- The code at `0x412a0000` was placed there by a manual allocation
  (NtAllocateVirtualMemory + NtWriteVirtualMemory), consistent with
  `neverlose::map()` source code

This is consistent with the injector source (`injector/main.cpp`) which uses
`LoadLibraryA` via `CreateRemoteThread` — the DLL loads normally via the
Windows loader at some other address, then `neverlose::map()` copies the real
cheat code (from resource #101) to this private region.

========================================
6. REGIONS CONTAINING REPORTED FUNCTION ADDRESSES
================================================

| Address | Region | Type | Protect | Contains MZ? | Owner |
|---------|--------|------|---------|--------------|-------|
| 0x413F94D0 | 0x412a0000–0x4205a000 | MEM_PRIVATE | EXECUTE_READWRITE | No | Resource #101 via neverlose::map() |
| 0x413F9E00 | 0x412a0000–0x4205a000 | MEM_PRIVATE | EXECUTE_READWRITE | No | Resource #101 via neverlose::map() |
| 0x4148F180 | 0x412a0000–0x4205a000 | MEM_PRIVATE | EXECUTE_READWRITE | No | Resource #101 via neverlose::map() |
| 0x41496DB0 | 0x412a0000–0x4205a000 | MEM_PRIVATE | EXECUTE_READWRITE | No | Resource #101 via neverlose::map() |
| 0x4140C710 | 0x412a0000–0x4205a000 | MEM_PRIVATE | EXECUTE_READWRITE | No | Resource #101 via neverlose::map() |
| 0x4140CB75 | 0x412a0000–0x4205a000 | MEM_PRIVATE | EXECUTE_READWRITE | No | Resource #101 via neverlose::map() |
| 0x41573930 | 0x412a0000–0x4205a000 | MEM_PRIVATE | EXECUTE_READWRITE | No | Resource #101 via neverlose::map() |
| 0x41573E80 | 0x412a0000–0x4205a000 | MEM_PRIVATE | EXECUTE_READWRITE | No | Resource #101 via neverlose::map() |
| 0x41408800 | 0x412a0000–0x4205a000 | MEM_PRIVATE | EXECUTE_READWRITE | No | Resource #101 via neverlose::map() |
| 0x41B6C700 | 0x412a0000–0x4205a000 | MEM_PRIVATE | EXECUTE_READWRITE | No | Resource #101 via neverlose::map() |

All 10 addresses share the same owner: Block 1 at `0x412a0000`.

========================================
7. WHAT IS NOT PRESENT
=====================================

- No `MEM_IMAGE` module at any address in `0x40000000–0x42200000`
- No PE header (MZ/PE signature) at `0x412a0000` (confirmed all zeros)
- No PE header at `0x4205a000` (Block 2 base)
- No separately loaded DLL in this range

The only code in this range is the manually written MEM_PRIVATE region at
`0x412a0000`, populated from resource #101 by `neverlose::map()`.

========================================
END
========================================