# PHASE11_NATIVE_FUNCTION_INVENTORY.md
========================================
Phase 9 Investigation C — Native code inventory of `neverlose.dll`.
Based on a linear disassembly sweep of `.text` (RVA 0x1000–0x3907A) and
cross-referencing of direct (`E8 rel32`) calls between functions.

Evidence levels: CONFIRMED (addresses + bytes from raw binary); 
STRONGLY SUPPORTED (call graph + source correlation); 
INFERRED (role from disassembly patterns, not independently verified).

Source file analyzed:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll
Section analyzed: `.text` (VirtAddr 0x1000, VirtSize 0x3807A, RawOffset 0x400)

========================================
1. INVENTORY SUMMARY
========================================

| Metric | Value |
|--------|-------|
| .text size (virtual) | 0x0003807A bytes (~229 KB) |
| .text size (raw) | 0x00038200 bytes |
| Function prologue candidates found | 1,027 |
| Functions with ≥1 direct call | 727 |
| Total direct call sites (E8 rel32) | 4,463 |
| Entry point (PE header) | RVA 0x000015560 |
| PE ImageBase | 0x10000000 |

Method: scanned `.text` for standard x86 prologues
(`push ebp; mov ebp, esp` / `push ebp; push esi; push edi` / etc.),
then cross-referenced `E8 rel32` call instructions within each function region.
Note: prologue scanning produces both true functions and false positives
(prologue byte sequences appearing mid-stream). Functions without a standard
prologue (e.g., leaf helpers starting directly with `sub esp`) are missed.
Coverage is therefore a skeleton, not a complete disassembly.

========================================
2. ENTRY POINT AND BOOTSTRAP CLUSTER (RVA 0x1000–0x2000)
========================================

The entry point is at RVA `0x15560` (confirmed by PE header). The early `.text`
region (`0x1040`–`0x2000`) contains dense function clustering and the highest
concentration of direct call sites — consistent with bootstrap/DllMain code.

Notable early functions (file RVA):
  `0x41481040` — first prologue; calls `0x414814CE`, `0x4148160C`, `0x41481304`,
                 `0x41481202`, `0x41481509`
  `0x414811B0` — calls out-of-region targets (0xA014483A, 0x0547D9BD, …) — likely
                 import thunks / IAT-mediated calls
  `0x414813F0`, `0x41481430`, `0x414814A0`, `0x414814C0`, `0x41481500`,
  `0x41481550` (entry), `0x41481590`, `0x414815B0`, `0x414815F0`,
  `0x41481620`, `0x41481640` — tightly clustered, mutually calling

The entry function at `0x4148F15560` corresponds to `DllMain` (PE
AddressOfEntryPoint). Correlation with source: `FemboyLose-main/neverlose/main.cpp`
— `DllMain` calls `DisableThreadLibraryCalls`, `apply_missing_entity_fix()`,
then `NtCreateThreadEx(MainThread, ...)`.

========================================
3. CALL-GRAPH CHARACTERISTICS
========================================

- 727 of 1,027 prologue candidates (71%) make at least one direct call.
- Average ~6.1 direct calls per calling function.
- Many call sites resolve to targets outside `.text` or to non-prologue
  addresses (marked "[data]"); these are either:
    (a) IAT-mediated calls (imports resolved at runtime),
    (b) jump-table / switch dispatch targets,
    (c) false positives from the prologue-based region splitting.
- Recursion / repeated calls observed (e.g., `0x41481040` calls `0x41481509`
  multiple times; `0x41481B10` calls `0x41481E48` five times) — consistent with
  loops or error-retry paths.

No symbol names are available (debug symbols stripped:
`IMAGE_FILE_DEBUG_STRIPPED` not set but no PDB referenced; no export names of
relevance). All function references below are by raw file RVA only.

========================================
4. CORRELATION WITH LIVE-PROCESS FINDINGS (PID 21580)
========================================

The following live-mapped addresses (from earlier read-only memory analysis)
map to file RVAs by subtracting the manual-mapping delta. Because the manual
mapper may not preserve a constant `ImageBase`→runtime delta, these are
presented as cross-references, not equivalences:

Live mapped address | File RVA (PE) | Role (from live disassembly)
--------------------|---------------|-----------------------------
0x412A15560 | 0x15560 | Entry point (PE header confirms)
0x413F94D0 | ~0x13F94D0? | Lag-comp acceptability gate
0x413F9E00 | ~0x13F9E00? | Record freshness gate
0x4148F180 | ~0x148F180? | Record selection
0x41496DB0 | ~0x1496DB0? | Lag-comp orchestrator
0x41B6C700 | ~0x1B6C700? | Origin apply
0x41B70930 | ~0x1B70930? | Small getter
0x4140C710 | ~0x140C710? | Aim consumer entry
0x4140CB75 | ~0x140CB75? | Aim position computation
0x41573930 | ~0x1573930? | Vector->angle
0x41573E80 | ~0x1573E80? | Angle normalize
0x41408800 | ~0x1408800? | memcpy-style apply

CAUTION: Manual mapping may relocate sections non-linearly. The above RVAs are
the file RVAs obtained by subtracting PE ImageBase `0x10000000` from the live
addresses; they are approximations and should be re-verified against the
on-disk `.text` before use.

========================================
5. FUNCTION GROUPING BY APPARENT RESPONSIBILITY (INFERRED)
========================================

The source tree (`FemboyLose-main/neverlose/`) confirms these subsystems;
the `.text` function distribution is consistent with them:

| Subsystem | Source files | Evidence in .text |
|-----------|--------------|-------------------|
| Bootstrap / entry / DllMain | main.cpp, entry.cpp | Entry point `0x415560`; early dense cluster `0x1040`–`0x2000` |
| Manual self-mapping | main.cpp (`g_neverlose.map`) | Nt* primitives imported; code in early region |
| Import reconstruction | fix_imports.cpp | IAT thunk calls (appear as out-of-region "[data]" targets) |
| Anti-tamper / spoof | spoof_*.cpp, fix_sha256.cpp | Scattered functions; flow-fix `0xEB` patches (~110 addrs) |
| Detour hooks | setup_hooks.cpp, HookFn.cpp, VEH.cpp | `.detourc` section (0x69000–0x6A190); VEH install |
| Interface / cvar fixing | fix_interfaces.cpp, fix_cvars.cpp | Not individually mapped in .text |
| Memory dispatcher | fix_mem_dispatcher.cpp | Not individually mapped |
| Crypto capture | install_crypto_capture | Not individually mapped |
| Record / lag-comp logic | (native, no dedicated source file) | `0x413F9E00`, `0x413F94D0`, `0x4148F180`, `0x41496DB0` |
| Aim pipeline | (native, no dedicated source file) | `0x4140C710`, `0x4140CB75`, `0x41573930`, `0x41573E80`, `0x41408800` |
| Geometry helpers | (native) | `0x41400BF0`, `0x413F6B40` (dead-end at trampoline `0x39C21170`) |

Functions confirmed ONLY in live memory (not yet located in on-disk `.text`
scan because manual-mapping delta is uncertain):
`0x413F94D0`, `0x413F9E00`, `0x4148F180`, `0x41496DB0`, `0x41B6C700`,
`0x41B70930`, `0x41400BF0`, `0x413F6B40`, `0x4140C710`, `0x4140CB75`,
`0x41573930`, `0x41573E80`, `0x41408800`, `0x41409D20`, `0x414091A0`,
`0x41407EB0`, `0x41403FB0`, `0x41596AA9`.

========================================
6. MAJOR UNEXPLORED CODE REGIONS
========================================

| Region (file RVA) | Size | Status | Notes |
|-------------------|------|--------|-------|
| 0x1000–0x2000 | 4 KB | Partially mapped | Bootstrap / DllMain cluster |
| 0x2000–0x3807A | ~225 KB | Partially mapped | 1,027 prologue candidates across full range |
| .detourc (0x69000–0x6A190) | 4.5 KB | NOT disassembled | Detour hook code stubs |
| .reloc (0x35C500–0x360124) | 19 KB | NOT parsed | Base-relocation table |

The majority of `.text` (`0x2000`–`0x3807A`) has a function-boundary skeleton
but no per-function purpose assignment. Decompilation was not performed.

========================================
7. LIMITATIONS
========================================

- Prologue scanning yields false positives and misses non-standard
  function entries. Count (1,027) is an upper-bound skeleton, not an
  authoritative function count.
- No symbol/PDB information; all roles inferred from byte patterns and
  source correlation, not confirmed by symbol names.
- Direct-call cross-reference excludes indirect calls (`call [reg]`),
  jump-table dispatch, and IAT thunks resolved at runtime.
- Live-mapped addresses could not be reliably translated to file RVAs
  because the manual-mapping delta is not confirmed constant.

========================================
END
========================================