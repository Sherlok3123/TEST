# NEVERLOSE FUNCTION OWNERSHIP CORRECTIONS
==========================================
Phase 8 — Updated attribution status for all 10 previously reported native
function addresses, based on live module ownership evidence (VirtualQueryEx
region walk) and source code analysis (`FemboyLose-main/`).

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN /
CONTRADICTED.

========================================
1. SUMMARY OF CORRECTIONS
========================================

All 10 previously reported function addresses are now **CONFIRMED** to reside
inside a single MEM_PRIVATE, EXECUTE_READWRITE region at
`0x412a0000–0x4205a000` (allocation base `0x412a0000`). This region is
populated by `neverlose::map()` from resource `IDR_BINARY` (#101) in the
on-disk `neverlose.dll`.

The addresses do **NOT** belong to the on-disk `neverlose.dll` as a standard
PE image — they belong to the dynamically allocated cheat code from resource
#101.

========================================
2. UPDATED FUNCTION OWNERSHIP TABLE
====================================

| # | Address | Previous status | Updated status | Region owner | Source of bytes |
|---|---------|----------------|----------------|--------------|-----------------|
| 1 | 0x413F94D0 | UNVERIFIED (lag-comp gate) | CONFIRMED in region 0x412a0000 | Resource #101 via `neverlose::map()` | Resource #101 (IDR_BINARY) |
| 2 | 0x413F9E00 | UNVERIFIED (record freshness gate) | CONFIRMED in region 0x412a0000 | Resource #101 via `neverlose::map()` | Resource #101 (IDR_BINARY) |
| 3 | 0x4148F180 | UNVERIFIED (record selection) | CONFIRMED in region 0x412a0000 | Resource #101 via `neverlose::map()` | Resource #101 (IDR_BINARY) |
| 4 | 0x41496DB0 | UNVERIFIED (lag-comp orchestrator) | CONFIRMED in region 0x412a0000 | Resource #101 via `neverlose::map()` | Resource #101 (IDR_BINARY) |
| 5 | 0x4140C710 | UNVERIFIED (aim consumer entry) | CONFIRMED in region 0x412a0000 | Resource #101 via `neverlose::map()` | Resource #101 (IDR_BINARY) |
| 6 | 0x4140CB75 | UNVERIFIED (aim position computation) | CONFIRMED in region 0x412a0000 | Resource #101 via `neverlose::map()` | Resource #101 (IDR_BINARY) |
| 7 | 0x41573930 | UNVERIFIED (vector->angle) | CONFIRMED in region 0x412a0000 | Resource #101 via `neverlose::map()` | Resource #101 (IDR_BINARY) |
| 8 | 0x41573E80 | UNVERIFIED (angle normalize) | CONFIRMED in region 0x412a0000 | Resource #101 via `neverlose::map()` | Resource #101 (IDR_BINARY) |
| 9 | 0x41408800 | UNVERIFIED (aim-struct apply) | CONFIRMED in region 0x412a0000 | Resource #101 via `neverlose::map()` | Resource #101 (IDR_BINARY) |
| 10| 0x41B6C700 | UNVERIFIED (origin apply) | CONFIRMED in region 0x412a0000 | Resource #101 via `neverlose::map()` | Resource #101 (IDR_BINARY) |

**All 10 addresses:** Same owner — region `0x412a0000–0x4205a000`
(MEM_PRIVATE, EXECUTE_READWRITE, allocation base `0x412a0000`).

========================================
3. CONFIDENCE LEVELS BY CATEGORY
=================================

| Aspect | Confidence | Basis |
|--------|------------|-------|
| Addresses contain real x86 code | CONFIRMED | Live memory reads (16 bytes each, all valid instructions) |
| Addresses are inside `0x412a0000–0x4205a000` | CONFIRMED | VirtualQueryEx region walk |
| Region is MEM_PRIVATE EXECUTE_READWRITE | CONFIRMED | VirtualQueryEx |
| Allocation base is `0x412a0000` | CONFIRMED | VirtualQueryEx + source (`neverlose.h:28`) |
| Region populated from resource #101 | STRONGLY SUPPORTED | Source (`neverlose.cpp:16-47`) + resource enumeration + live memory |
| No MEM_IMAGE module contains these addresses | CONFIRMED | VirtualQueryEx: 0 MEM_IMAGE regions in `0x40000000–0x42200000` |
| No on-disk `neverlose.dll` byte match | CONFIRMED | Phase 7: 0/10 live 16-byte sequences found in on-disk image |
| Internal call graph (`0x4140CB75`→`0x41B6C700`) | CONFIRMED | Live memory: `e8 86 fb 75 00` resolves to `0x41B6C700` |
| Specific function roles (lag-comp gate, etc.) | INFERRED | Disassembly patterns + prior analysis; not independently verified against source symbols |
| Resource #101 → executable code transformation | UNKNOWN | Source shows straight `NtWriteVirtualMemory` copy; live code bytes differ from resource bytes |

========================================
4. WHAT CHANGED FROM PREVIOUS REPORTS
======================================

| Previous claim (Phase 7) | Corrected claim (Phase 8) | Basis |
|-------------------------|--------------------------|-------|
| Addresses belong to `neverlose.dll` | Addresses belong to resource #101 cheat code in MEM_PRIVATE region | Live memory + source |
| `0x412a0000` is a PE image base | `0x412a0000` is a private allocation with no PE header | Live memory (all zeros at base) + source (`neverlose.h:28`) |
| Loader uses manual mapping | Loader uses LoadLibraryA; DLL self-maps via `neverlose::map()` | Injector source + DLL source |
| Block 1 and Block 2 are separate mappings | Block 2 (0x4205a000) has same allocation base as Block 1 (0x412a0000) | VirtualQueryEx |
| Function roles confirmed | Function roles INFERRED (disassembly only, no symbols) | Source has no symbols for these functions |

========================================
5. FUNCTION ROLE ASSESSMENT (INFERRED)
======================================

The specific roles assigned to each address (lag-comp gate, record
selection, aim consumer, etc.) were determined from disassembly patterns
in earlier phases. These remain INFERRED because:

- No symbol names are available (stripped binary)
- No source file corresponds to these specific functions
- The functions exist in resource #101 (encrypted/encoded on disk), not in
  any source file we can read

The roles are consistent with the instruction patterns observed (SEH
prologues, vector math, calls to atan2, etc.) but should be treated as
hypotheses until confirmed against the actual resource #101 content.

========================================
6. RELATIONSHIP TO ON-DISK neverlose.dll
=========================================

The on-disk `neverlose.dll` is a **loader/stub**, not the cheat core:

| Component | Location | Nature |
|-----------|----------|--------|
| Stub DLL (loader, imports, hooks) | On-disk `neverlose.dll` `.text` | Loaded via LoadLibraryA by `loader.exe` |
| Real cheat binary | Resource #101 (`IDR_BINARY`) in `.rsrc` | Copied to MEM_PRIVATE at `0x412a0000` by `neverlose::map()` |
| Reported functions (0x413F94D0 etc.) | Live memory at `0x412a0000+` | Decoded/executed from resource #101 |

The reported function addresses are **not** in any source file. They exist
only in the compiled resource #101, which is loaded into memory at runtime
by `neverlose::map()`.

========================================
7. LIMITATIONS
================================

- Resource #101 has not been decoded; its exact format (encrypted?
  packed? plaintext?) is unknown
- `neverlose::map()` does a straight `NtWriteVirtualMemory` copy of
  resource bytes; no decryption routine is visible in the source. Either
  the resource is already executable code (obfuscated), or decryption
  happens in a later init step (`fix_dump()`, `install_crypto_capture()`,
  or `entry()`)
- `imageSize` in source (`0x3501000` ≈ 53 MB) doesn't match observed
  Block 1 size (`0x00dba000` ≈ 14 MB). Source version mismatch or partial
  allocation
- Function role names (lag-comp gate, aim consumer, etc.) are inferred
  from disassembly patterns, not confirmed by symbols or source

========================================
END
========================================