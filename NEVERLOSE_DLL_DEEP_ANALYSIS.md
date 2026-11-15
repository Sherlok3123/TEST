# NEVERLOSE DLL DEEP STATIC ANALYSIS
====================================
Evidence-backed reconstruction of neverlose.dll as a software component.
All findings classified: CONFIRMED / STRONGLY SUPPORTED / INFERRED /
UNKNOWN / CONTRADICTED.

This is static software analysis and documentation only. No operational
modifications to cheat behavior, memory patches, aim manipulation, or
gameplay prediction were developed or provided. No binaries or source files
were modified.

========================================
1. EXACT BINARY IDENTIFICATION
========================================

Analyzed file:
  C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\neverlose.dll

Identity (CONFIRMED from PE header + raw hashes):
  Size:            56,370,688 bytes (53.76 MB)
  MD5:             6419c781156a70631cc92ddf84ac9c08
  SHA1:            b84438884434275101bc2ad4349d5102f3aaedca
  SHA256:          529c59bd687901d4e86898f78f50534ca4fc5611d693c296c9a3bd7bf8f61253
  Architecture:    x86 PE32 (MACHINE 0x14c)
  ImageBase:       0x10000000 (NOT the runtime base — see §3)
  EntryPoint RVA:  0x15560 (DllMain)
  SizeOfImage:     0x035CA000
  Sections:        8
  Timestamp:       1788894915
  Characteristics: 0x2102 (EXECUTABLE_IMAGE | 32BIT_MACHINE | DLL)
  Debug symbols:   stripped (no PDB/symbol names available)

On-disk DLL vs. manually mapped runtime image (CONFIRMED distinction):
  The on-disk DLL is NOT loaded at its PE ImageBase via the normal Windows
  loader. It is manually mapped at runtime allocation base 0x412A0000
  (PAGE_EXECUTE_WRITECOPY), with a separate read-only continuation block at
  0x4205A000. File RVAs below are on-disk RVAs; runtime addresses require
  the manual-mapping delta (not confirmed constant). Anchor instruction
  F3 0F 5B CA 0F 5B C9 0F 2E CB was observed at runtime 0x41400D8F.

Source of findings: PE header (on-disk) + raw byte analysis; live-process
observations (PID 21580) noted separately where used.

========================================
2. PE SECTION INVENTORY (SUMMARY)
========================================

Full detail: NEVERLOSE_PE_SECTION_INVENTORY.md.

| Section | VirtAddr | VirtSize | Entropy | Perms | Contents | Examined? |
|---------|----------|----------|---------|-------|----------|-----------|
| .text   | 0x1000   | 0x3807A  | 6.66    | CODE  | Executable code (~229 KB) | Partially — prologue + call graph |
| .rdata  | 0x3A000  | 0x2B20E  | 6.37    | RD    | Read-only data (constants/strings) | Partially |
| .data   | 0x66000  | 0x29E8   | 3.44    | RW    | Writable structured data | Not catalogued |
| .detourc| 0x69000  | 0x1190   | 4.01    | RD    | Detour hook code stubs | Not disassembled |
| .detourd| 0x6B000  | 0x000C   | 0.07    | RW    | Detour hook data (zeros) | Not analyzed |
| .fptable| 0x6C000  | 0x0080   | 0.00    | RD    | Function-pointer table (NULL) | Not analyzed |
| .rsrc   | 0x6D000  | 0x3557150| 7.27    | RD    | Resources (~53 MB) | Directory enumerated; blob undecoded |
| .reloc  | 0x35C500 | 0x4C24   | 6.45    | R     | Base-relocation table | Not parsed |

Coverage: ~97% of file bytes (by size) are in .rsrc or unexamined data
sections. Only the .text code skeleton (1,027 prologue candidates, 4,463
direct call sites) and the resource directory were mapped. The DLL is NOT
comprehensively analyzed.

========================================
3. RUNTIME MEMORY MAP (LIVE, PID 21580)
========================================

CONFIRMED via read-only memory observation:
  Block 1 (WCX): 0x412A0000 – 0x4205A000 (0x00DBA000) — main mapped image
  Block 2 (RO):  0x4205A000 – 0x42239000 (0x001DF000) — read-only continuation

Function addresses cited elsewhere (0x412Axxxx–0x4159xxxx) are in Block 1;
global data (0x42xxxxxx) is in Block 2 / adjacent pages.

Previous digit-transpose error (0x4134BA000) CONTRADICTED and corrected to
0x4205A000. See NEVERLOSE_ARCHITECTURE_CORRECTIONS.md.

========================================
4. RESOURCE SECTION (.rsrc) — SYSTEMATIC INVENTORY
==================================================

Full detail: NEVERLOSE_RESOURCE_ANALYSIS.md.

The .rsrc section (RVA 0x6D000, size 0x03557150 ≈ 53 MB) contains 6
entries, all under custom type "BINARY" except one RT_MANIFEST:

| Entry | RVA | Size | Format (preview) | Status |
|-------|-----|------|------------------|--------|
| BINARY #101 | 0x0006D170 | 55,578,628 (53.0 MB) | Transformed binary blob; repeating pattern "…-2026…"; NOT Lua bytecode magic | Undecoded — UNKNOWN format |
| BINARY #102 | 0x0356E178 | 2,921 | x86 CPUID code ("AuthenticAMD") | CONFIRMED code — env/anti-tamper check |
| BINARY #103 | 0x0356CEE8 | 4,096 | Data table / structure (one page) | Present; format UNKNOWN |
| BINARY #104 | 0x0356FCE8 | 305,945 | PNG image (447×447) | CONFIRMED PNG |
| BINARY #105 | 0x035BA808 | 38,850 | JPEG image (Exif) | CONFIRMED JPEG |
| RT_MANIFEST #2 | 0x035C3FD0 | 381 | XML application manifest | CONFIRMED manifest |

Key finding: Resource #101 is ~99.9% of .rsrc. It does NOT begin with Lua
bytecode magic (\x1bLua) and is not a simple 4-byte repeating XOR of
nl.bin (55,578,624 bytes, close in size but different content). Format and
purpose UNKNOWN. No consumer of #101 was identified in .text.

No resource was confirmed consumed by any specific code path. The DLL's
resource-loading imports (FindResourceW, SizeofResource, LockResource,
LoadResource) make access mechanically possible, but no consumer of any
resource ID was identified.

nl.bin (source-tree asset, 55,578,624 bytes) is NOT a runtime artifact and
is NOT referenced by any binary. See NEVERLOSE_RUNTIME_ARTIFACTS.md.

========================================
5. NATIVE CODE INVENTORY
========================

Full detail: NEVERLOSE_NATIVE_FUNCTION_INVENTORY.md.

.text (RVA 0x1000–0x3907A, ~229 KB):
  - 1,027 function prologue candidates
  - 727 functions with ≥1 direct call
  - 4,463 direct call sites (E8 rel32)
  - Entry point RVA 0x15560 (matches PE header)

Note: prologue scanning yields false positives and misses non-standard
entries; this is a skeleton, not a complete disassembly. No symbol names
available.

Bootstrap cluster (RVA 0x1040–0x2000): dense, mutually-calling functions
around the entry point — consistent with DllMain / MainThread bootstrap.

Notable live-mapped functions (addresses approximate; manual-mapping delta
not confirmed constant):
  - 0x413F9E00  Record freshness gate (cmp ecx,2 at 0x413F9EC0 =
    extrapolation_limit patch site; returns record ptr or 0)
  - 0x413F94D0  Lag-comp acceptability gate (al=1 accept default;
    horizontal distance vs [0x4206CDC0]=100.0f)
  - 0x4148F180  Record selection (3D distance search; half-tick z projection)
  - 0x41496DB0  Lag-comp orchestrator (SEH-wrapped; origin assembly)
  - 0x41B6C700  Origin apply (10 direct callers)
  - 0x41B70930  Small getter (mov eax,[ecx+0x9960]; ret)
  - 0x41400BF0 / 0x413F6B40 Geometry helpers (dead-end at trampoline 0x39C21170)
  - 0x4140C710  Aim consumer entry (SEH-wrapped; iterates [0x424AFD68])
  - 0x4140CB75  Aim position computation (writes 0x425023C8/23D0/23EC)
  - 0x41573930  Vector->angle (atan2 at 0x4202F7D0)
  - 0x41573E80  Angle normalize (0x42026D1B x3)
  - 0x41408800  memcpy-style aim-struct apply (0x71c bytes, ret 4)

Unexplored: .detourc (4.5 KB), .reloc (19 KB), most of .text (purpose
unassigned for most functions).

========================================
6. SOURCE-TO-BINARY COVERAGE
============================

Full detail: NEVERLOSE_SOURCE_BINARY_COVERAGE.md.

Source PRESENT (FemboyLose-main/neverlose/): main.cpp, entry.cpp,
fix_dump.cpp, fix_imports.cpp, fix_interfaces.cpp, fix_signatures.cpp,
fix_cvars.cpp, fix_mem_dispatcher.cpp, fix_sha256.cpp, spoof.cpp,
spoof_peb.cpp, spoof_kusd.cpp, spoof_cpuid.cpp, setup_hooks.cpp,
mem_dispatcher.cpp, VEH.cpp, HookFn.cpp, Requestor.cpp, neverlose.h,
internal_fixes.h, token.h, nops.h.

Coverage:
  - HIGH: bootstrap/entry/DllMain, manual mapping, import fix, HTTP/Lua
    request (Requestor.cpp QueryLuaLibrary → GET /lua/<name>).
  - MEDIUM–HIGH: anti-tamper/spoof/hooks/VEH (sections + trampoline present;
    individual functions not all located).
  - PARTIAL: record selection, lag-comp, aim pipeline, geometry helpers —
    present in binary, NO identified source file.
  - LOW: Lua VM entry point, .data/.rdata globals, .rsrc blob content.

CONCLUSION: Roughly half of the DLL's native behavior is source-backed
(bootstrap, mapping, imports, hooks, HTTP/Lua); the other half (record
selection, lag-comp, aim pipeline, geometry helpers) exists only in the
compiled binary with no identified source.

========================================
7. THREE-COMPONENT RECONCILIATION
=================================

Full detail: NEVERLOSE_COMPLETE_ARCHITECTURE.md, plus corrections below.

Components:
  - loader.exe (x86, 490 KB) — injector/downloader. Imports CreateRemoteThread,
    VirtualAllocEx, WriteProcessMemory, WININET (download). References port
    30031. Source ABSENT.
  - neverlose.dll (x86, 56 MB) — injected cheat core. Manually mapped at
    0x412A0000. WINHTTP client to 127.0.0.1:30031. Source PRESENT (partial).
  - neverlose-server.exe (x64, 9.7 MB) — local HTTP server on
    127.0.0.1:30031. CONFIRMED running (PID 11468, port connect test passed).
    Owns cabbitwin\ (session, token, accounts, per-user dirs, Lua libraries,
    TLS certs). Source ABSENT.

Communication (CONFIRMED direction):
  loader.exe → injects neverlose.dll into csgo.exe
  neverlose.dll → WinHTTP GET /lua/<name> → neverlose-server.exe:30031

Dependency order:
  1. neverlose-server.exe runs (standalone)
  2. loader.exe injects neverlose.dll into csgo.exe
  3. neverlose.dll initializes (map → fix_dump → hooks → entry)
  4. neverlose.dll connects to server on 30031; Lua scripts fetched

CORRECTION (status changed): Whether loader.exe starts neverlose-server.exe
is UNKNOWN (previously implied confirmed). The server runs independently
(PID 11468 vs csgo PID 21580) with no established link to loader.exe. See
NEVERLOSE_ARCHITECTURE_CORRECTIONS.md §7.

========================================
8. EVIDENCE AND CONTRADICTION AUDIT
===================================

Full detail: NEVERLOSE_ARCHITECTURE_CORRECTIONS.md.

Claim | Classification | Notes
------|----------------|-------
Mapped size 0x412A0000+0x00DBA000 = 0x4205A000 | CONFIRMED | Digit-transpose error (0x4134BA000) corrected |
nl.bin is a runtime artifact | CONTRADICTED | nl.bin is a source-tree build asset; not referenced at runtime |
Aim consumer is Lua | CONTRADICTED | Aim consumer is native (0x4140C710…0x41408800) |
Aim globals feed engine state | INFERRED (not confirmed) | Globals written; downstream consumer UNKNOWN |
0x71c memcpy semantics | UNKNOWN | Copy CONFIRMED; structure meaning unknown |
cabbitwin\ owned by server | STRONGLY SUPPORTED | Server file I/O imports + data present |
Server started by loader | UNKNOWN | No link established |
Resource #101 = nl.bin | CONTRADICTED | Different first bytes; no consistent XOR key |

Corrections applied in NEVERLOSE_ARCHITECTURE_CORRECTIONS.md rather than
silently carried forward.

========================================
9. ASSESSMENT OF UNDERSTANDING
==============================

Understood (source-backed or directly observed):
  - DLL identity, PE layout, section inventory, entry point.
  - Manual self-mapping at 0x412A0000 + RO continuation block.
  - Import reconstruction (IAT at 0x43236000+).
  - Bootstrap lifecycle (DllMain → MainThread → map → fix_dump → hooks → entry).
  - HTTP/Lua request path (WinHTTP → 127.0.0.1:30031 → GET /lua/<name>).
  - Detour hooks, VEH, anti-tamper spoofing (sections + trampoline present).
  - Resource directory (6 entries); PNG, JPEG, manifest, CPUID code identified.
  - Three-component relationships and communication mechanisms.

Partially understood (binary only, no source):
  - Record freshness gate, lag-comp acceptability gate, record selection,
    lag-comp orchestrator, origin apply, aim pipeline, geometry helpers.
  - Function-level purpose for most of .text (1,027 prologue candidates,
    roles unassigned).

Not understood:
  - .rsrc blob #101 (53 MB, format unknown).
  - Lua VM entry point and auto-loaded script list.
  - Native→Lua / Lua→native aim boundary (no verified binding).
  - Consumers of aim output globals and the 0x71c struct.
  - Obfuscated helpers past trampoline 0x39C21170.
  - loader.exe download URL; whether loader starts the server.

Overall coverage: The DLL's architecture (bootstrap, mapping, imports, hooks,
HTTP/Lua, component relationships) is understood at a high level. The
majority of byte count (.rsrc blob) and a substantial portion of native
behavior (record/lag-comp/aim/geometry) remain undocumented at the source
level. Approximately 97% of file bytes are either undecoded resources or
uncatalogued data sections.

========================================
10. DELIVERABLES PRODUCED THIS PHASE
====================================

1. NEVERLOSE_DLL_DEEP_ANALYSIS.md          (this file)
2. NEVERLOSE_PE_SECTION_INVENTORY.md       (sections, entropy, coverage)
3. NEVERLOSE_RESOURCE_ANALYSIS.md          (.rsrc enumeration, 6 entries)
4. NEVERLOSE_NATIVE_FUNCTION_INVENTORY.md  (1,027 prologues, 4,463 calls)
5. NEVERLOSE_SOURCE_BINARY_COVERAGE.md     (source vs binary coverage table)
6. NEVERLOSE_ARCHITECTURE_CORRECTIONS.md   (corrections to earlier reports)
7. NEVERLOSE_NEXT_UNKNOWN_AREAS.md         (prioritized unknowns)

All located in C:\Users\Intel i7 10700k\Desktop\MIAUSTAFF\

========================================
END
========================================