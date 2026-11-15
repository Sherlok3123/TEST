# NEVERLOSE RUNTIME REGION INVENTORY
====================================
Phase 7 — inventory of every known memory region relevant to the
neverlose.dll / csgo.exe investigation, with boundaries, permissions,
evidence source, and ownership confidence.

Read-only. Based on on-disk PE analysis + live memory reads of
`csgo.exe` (PID 21580). No memory was written.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. ON-DISK neverlose.dll REGIONS (file RVAs)
============================================
Source: `C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll`
SHA256: `529c59bd687901d4e86898f78f50534ca4fc5611d693c296c9a3bd7bf8f61253`
PE ImageBase: `0x10000000` (NOT the runtime base).

| Region | RVA range | Size | Perms | Content | Evidence | Confidence |
|--------|-----------|------|-------|---------|----------|------------|
| .text | 0x00001000 – 0x0003907A | ~229 KB | CODE (RX) | Executable code | PE header + raw bytes | CONFIRMED |
| .rdata | 0x0003A000 – 0x0006520E | ~174 KB | RD | Read-only data/constants | PE header + raw bytes | CONFIRMED |
| .data | 0x00066000 – 0x000689E8 | ~10 KB | RW | Writable structured data | PE header + raw bytes | CONFIRMED |
| .detourc | 0x00069000 – 0x0006A190 | ~4.5 KB | RD | Detour hook code stubs | PE header + raw bytes | CONFIRMED |
| .detourd | 0x0006B000 – 0x0006B00C | 12 B | RW | Detour hook data (zeros) | PE header + raw bytes | CONFIRMED |
| .fptable | 0x0006C000 – 0x0006C080 | 128 B | RD | Function-pointer table (NULL) | PE header + raw bytes | CONFIRMED |
| .rsrc | 0x0006D000 – 0x0035C4150 | ~53 MB | RD | Resources (6 entries) | PE header + resource enum | CONFIRMED |
| .reloc | 0x0035C500 – 0x00360124 | ~19 KB | R | Base-relocation table | PE header + raw bytes | CONFIRMED |
| Entry point | RVA 0x000015560 | — | — | DllMain | PE header | CONFIRMED |

.on-disk entry bytes at RVA 0x15560: `55 8b ec 83 7d 0c 01 75`.

========================================
2. REPORTED LIVE RANGES (runtime addresses, csgo.exe PID 21580)
==============================================================
Source: live memory reads via ReadProcessMemory.

| Reported region | Range | Size | Claimed perms | Evidence | Confidence | Notes |
|-----------------|-------|------|---------------|----------|------------|-------|
| Block 1 | 0x412A0000 – 0x4205A000 | 0x00DBA000 (~13.9 MB) | WCX | Earlier report | UNVERIFIED | Base is all zeros; no PE header |
| Block 2 | 0x4205A000 – 0x42239000 | 0x001DF000 (~1.9 MB) | RO | Earlier report | UNVERIFIED | Not independently verified |
| Combined | — | 0x00F99000 (~15.7 MB) | — | — | UNVERIFIED | Smaller than SizeOfImage 0x035CA000 |

Confirmed problems with Block 1:
  - First 64 bytes at `0x412A0000` are all `00`.
  - `e_lfanew` at `0x412A003C` = `0`.
  - No `MZ`/`PE` signature at base or `base+e_lfanew`.
  → `0x412A0000` is NOT a PE image base (CONFIRMED).

Confirmed problem with combined size:
  - `0x00F99000` < PE SizeOfImage `0x035CA000` (CONFIRMED).
  - `.rsrc` alone (0x03557150) exceeds the whole combined range (CONFIRMED).

Reported function addresses all lie within Block 1 per the earlier claim,
but the base is invalid, so their section membership is indeterminate.

========================================
3. LIVE CODE REGIONS AT REPORTED FUNCTION ADDRESSES
===================================================
Source: live memory reads (16 bytes each). All reads succeeded; all contain
valid x86 code. NONE match any byte sequence in the on-disk `neverlose.dll`.

| Address | First bytes (16) | Interpretation | In on-disk DLL? | Ownership confidence |
|---------|------------------|----------------|-----------------|----------------------|
| 0x413F94D0 | `57 56 83 ec 0c 8b 15 28 f4 23 42 ...` | `push edi/esi; sub esp,0xc; mov edx,[0x4223f428]` | No | UNKNOWN |
| 0x413F9E00 | `55 89 e5 53 57 56 83 e4 f0 81 ec 10 01...` | SEH prologue | No | UNKNOWN |
| 0x4148F180 | `55 57 56 83 ec 10 ... a1 00 27 26 42` | SEH prologue; stack cookie `[0x42262700]` | No | UNKNOWN |
| 0x41496DB0 | `55 89 e5 53 57 56 83 e4 f0 81 ec 60 01...` | SEH prologue; sub esp,0x160 | No | UNKNOWN |
| 0x4140C710 | `55 89 e5 53 57 56 83 ec 34 ...` | SEH prologue; sub esp,0x34 | No | UNKNOWN |
| 0x4140CB75 | `e8 86 fb 75 00 f2 0f 10 ...` | `call 0x75FB86` → 0x41B6C700 | No | UNKNOWN |
| 0x41573930 | `56 83 ec 48 ...` | `push esi; sub esp,0x48` | No | UNKNOWN |
| 0x41573E80 | `56 83 ec 38 ...` | `push esi; sub esp,0x38` | No | UNKNOWN |
| 0x41408800 | `89 c8 8b 4c 24 04 f2 0f 10 01 ...` | `movsd xmm0,[ecx]` | No | UNKNOWN |
| 0x41B6C700 | `55 89 e5 53 57 56 83 ec b0 00 00 00` | SEH prologue; sub esp,0xb0 | No | UNKNOWN |

Key finding: every live address contains real code, but none match the
on-disk `neverlose.dll`. Ownership of this live code is UNKNOWN — it may be
a different build of neverlose.dll, a different module, or a transformed
mapping. No module enumeration was performed to identify the owning module.

Internal call consistency CONFIRMED: `0x4140CB75` `e8 86 fb 75 00` calls
`0x41B6C700` (within live memory). These addresses form a coherent code
region, but the region's module ownership is not established.

========================================
4. CONTEXT AROUND 0x413F94D0 (CONFIRMED)
========================================
Bytes at `0x413F94C0–0x413F94DF`:
`4f 42 e8 f2 e7 9a 00 83 c4 14 5d c3 cc cc cc cc 57 56 83 ec 0c 8b 15 28 f4 23 42`

- `00 83 c4 14 5d c3` at `0x413F94C6–0x413F94CB` = `add esp,0x14; pop ebp; ret` — end of a prior function.
- `cc cc cc cc` at `0x413F94CC–0x413F94CF` = int3 padding / alignment.
- `57 56 83 ec 0c ...` at `0x413F94D0` = function start.

This confirms `0x413F94D0` is a genuine function boundary in live memory —
but again, the bytes do not match on-disk `neverlose.dll`, so ownership is
UNKNOWN.

========================================
5. OWNERSHIP CONFIDENCE SUMMARY
================================

| Region | Owner claimed in earlier reports | Evidence supports claim? | Current confidence |
|--------|----------------------------------|--------------------------|--------------------|
| On-disk neverlose.dll sections | neverlose.dll (the file) | Yes — direct file analysis | CONFIRMED |
| Block 1 `0x412A0000–0x4205A000` | neverlose.dll manual mapping | No — base is zeros, no PE header | CONTRADICTED as PE base |
| Block 2 `0x4205A000–0x42239000` | neverlose.dll continuation | No — not independently verified | UNKNOWN |
| Live code at reported addresses | neverlose.dll functions | No — no byte match to on-disk DLL | UNKNOWN |

No region in the live `csgo.exe` address space has been confirmed as the
mapped `neverlose.dll` image. The on-disk `neverlose.dll` sections are
CONFIRMED as belonging to the file, but their runtime location (if any) is
UNKNOWN.

========================================
6. WHAT WOULD RESOLVE THE INVENTORY
====================================
  - Module enumeration in `csgo.exe` (EnumProcessModules / NtQueryVirtualMemory
    region walk) to identify which module owns `0x413F0000–0x41B60000`.
  - A memory dump of the actually-injected `neverlose.dll` build, compared
    against the on-disk `neverlose.dll` (SHA256 529c59bd…).
  - Tracing the manual mapper to see how on-disk bytes are transformed
    (if at all) into memory.
  - Confirming whether `0x412A0000` belongs to any module at all (it reads
    as zeros, so it may be un/reserved, not committed code).

========================================
END
========================================