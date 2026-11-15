# NEVERLOSE ALLOCATION BOUNDARY CORRECTIONS
============================================
Phase 9 Investigation A — Corrected runtime allocation inventory for the
manually mapped Neverlose cheat code in `csgo.exe` (PID 21580).

Read-only. Based on `VirtualQueryEx` region walking of the live process.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. CORRECTED ALLOCATION INVENTORY
=================================

The previously reported allocation ranges (Block 1: `0x412a0000–0x4205a000`,
Block 2: `0x4205a000–0x42239000`) were **incomplete**. A wide scan of
`0x40000000–0x45000000` using `VirtualQueryEx` revealed that the allocation
at base `0x412a0000` consists of **7 contiguous regions** spanning the full
`0x3501000` bytes, exactly matching the source code's `imageSize = 0x3501000`
in `neverlose.h:28`.

Corrected allocation map (all share allocation base `0x412a0000`, all
MEM_PRIVATE, none with MZ header):

| # | Base | End | Size | Protect | Type | Contents (first bytes) |
|---|------|-----|------|---------|------|------------------------|
| 1 | 0x412a0000 | 0x4205a000 | 0xdba000 (~13.9 MB) | EXECUTE_READWRITE | MEM_PRIVATE | `00 00 00 00 00 00 00 00` (all zeros) |
| 2 | 0x4205a000 | 0x42239000 | 0x1df000 (~1.9 MB) | READONLY | MEM_PRIVATE | `00 00 00 00 1c 00 00 00` |
| 3 | 0x42239000 | 0x4252b000 | 0x2f2000 (~2.9 MB) | EXECUTE_READWRITE | MEM_PRIVATE | `e4 28 0f 42 00 00 00 00` |
| 4 | 0x4252b000 | 0x42553000 | 0x28000 (~163 KB) | EXECUTE_READ | MEM_PRIVATE | `f7 d0 0f bf c8 81 c6 04` |
| 5 | 0x42553000 | 0x42559000 | 0x6000 (24 KB) | READWRITE | MEM_PRIVATE | `30 f1 54 42 30 f1 54 42` |
| 6 | 0x42559000 | 0x43236000 | 0xcdd000 (~13.5 MB) | EXECUTE_READ | MEM_PRIVATE | `26 d2 ca 55 47 43 ae c5` |
| 7 | 0x43236000 | 0x447a1000 | 0x156b000 (~13.9 MB) | EXECUTE_READWRITE | MEM_PRIVATE | `e0 1d 85 77 20 d7 83 77` |
| **Total** | **0x412a0000** | **0x447a1000** | **0x3501000 (55,578,624)** | — | — | — |

Key observations:
- **Total size matches source**: `0x3501000` = 55,578,624 bytes = `imageSize`
  from `neverlose.h:28` (CONFIRMED)
- **Region 1 starts with zeros**: `0x412a0000` reads as all zeros, NOT as
  resource #101's first bytes `a6 c0 4e c9` (CONFIRMED)
- **Region 4 starts with x86 code**: `0x4252b000` reads `f7 d0 0f bf c8 81 c6 04`
  (`div eax; movsx ecx, ax; add esi, 4...`) — executable code (CONFIRMED)
- **Region 7 starts with `e0 1d 85 77...`**: Could be code or data
- **No MEM_IMAGE regions** in `0x40000000–0x42200000` — all are MEM_PRIVATE

========================================
2. CORRECTIONS TO PHASE 8 CLAIMS
=================================

| Phase 8 claim | Corrected claim | Basis |
|---|---|---|
| Block 1: `0x412a0000–0x4205a000` (0xdba000) | Part of larger allocation `0x412a0000–0x447a1000` (0x3501000) | VirtualQueryEx walk |
| Block 2: `0x4205a000–0x42239000` (0x1df000) | Still correct as region 2, but not the end of the allocation | VirtualQueryEx walk |
| Total combined: `0x00f99000` (~15.7 MB) | Actual total: `0x3501000` (~53 MB) | VirtualQueryEx walk — 3.4x larger than previously reported |
| `0x412a0000` is a PE image base | CONTRADICTED — base has no PE header, all zeros | ReadProcessMemory at base |
| Allocation is smaller than SizeOfImage | CONTRADICTED — allocation equals SizeofResource (0x3501000) | VirtualQueryEx + resource enumeration |

The previous claim that "the combined reported blocks (0x00f99000) are substantially smaller than PE SizeOfImage (0x035CA000)" was based on an incomplete allocation map. The actual allocation (0x3501000) matches the resource size, not the PE SizeOfImage (0x035CA000 ≈ 53.8 MB vs 0x3501000 ≈ 53.0 MB — close but not identical).

Note: `0x3501000` (55,578,624) vs resource size 55,578,628 = 4-byte difference. The on-disk DLL SizeOfImage is 0x035CA000 = 56,401,920 bytes, which is ~823 KB larger than the allocation. This is expected because the on-disk DLL includes the 53 MB `.rsrc` section, but only the resource data (not the PE headers/sections) is copied to the allocation.

========================================
3. REGION PROTECTION ANALYSIS
==============================

Block 1 (`0x412a0000–0x4205a000`, EXECUTE_READWRITE) is unusual — it is both
writable and executable. Normal PE images typically have separate RX code
sections and RW data sections. The combined RWX protection is consistent with:

1. Manual allocation + write (NtAllocateVirtualMemory with
   PAGE_EXECUTE_READWRITE, then NtWriteVirtualMemory) — matches
   `neverlose::map()` source
2. Protection not yet changed to RX (could happen in `fix_dump()` or later,
   but not observed in the source we reviewed)

Block 6 (`0x42559000–0x43236000`, EXECUTE_READ) and Region 4
(`0x4252b000–0x42553000`, EXECUTE_READ) are readable and executable but not
writable — consistent with code sections after protection has been adjusted.

Region 7 (`0x43236000–0x447a1000`, EXECUTE_READWRITE) contains the import
table (`g_imports` starts at `0x43236000` per `fix_imports.cpp`) and is both
writable and executable — consistent with import table being filled at runtime
via `fix_imports()`.

========================================
4. ADDITIONAL ALLOCATION DURING INITIALIZATION
===============================================

`last_resort_fixes()` (`fix_dump.cpp:113-135`) performs one additional
allocation:

```cpp
PVOID addr = VirtualAlloc(nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE,
                          PAGE_READWRITE);
*(PPVOID)0x424AFCC0 = addr;
*(PDWORD)0x4479EE00 = (DWORD)addr + 0x1000;
```

This allocates a 0x2000-byte RWX (PAGE_READWRITE) block at a system-chosen
address, stores the pointer at `0x424AFCC0` (within Block 7), and writes
`addr + 0x1000` to `0x4479EE00` (also within Block 7).

This allocation was NOT observed in our VirtualQueryEx scan because we only
scanned `0x40000000–0x42200000` (later extended to `0x45000000`). The
allocated address could be anywhere in the process address space. This is a
minor auxiliary allocation, not part of the main cheat image.

========================================
5. WHAT CHANGED FROM PHASE 8
============================

| Phase 8 claim | Phase 9 correction | Evidence |
|---|---|---|
| Block 1 ends at `0x4205a000` | Block 1 ends at `0x4205a000`, but 6 more regions follow to `0x447a1000` | VirtualQueryEx walk |
| Total allocation `0x00f99000` (~15.7 MB) | Total allocation `0x3501000` (~53 MB) | VirtualQueryEx walk |
| `0x412a0000–0x4205a000` is the full mapping | It is only Region 1 of 7 regions | VirtualQueryEx walk |
| Allocation is smaller than resource size | Allocation (0x3501000) is 4 bytes smaller than resource (55,578,628) | VirtualQueryEx + resource enumeration |

========================================
6. LIMITATIONS
========================================

- The VirtualQueryEx scan covered `0x40000000–0x45000000`; allocations
  outside this range (e.g., the `last_resort_fixes()` `VirtualAlloc`
  at a system-chosen address) were not mapped
- Region protections were observed at a single point in time; `fix_dump()`
  may change protections after `map()` completes
- The content of regions 3–7 was only sampled at their first 8 bytes; full
  content analysis was not performed

========================================
END
========================================