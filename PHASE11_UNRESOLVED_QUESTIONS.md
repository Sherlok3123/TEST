# PHASE11_UNRESOLVED_QUESTIONS.md
========================================
Phase 11 — Prioritized remaining unknowns from the Neverlose DLL deep static
analysis. Each entry states why it is unresolved and what specific evidence
would resolve it.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN.

========================================
1. CRITICAL (block architectural understanding)
==============================================

### 1.1 Resource #101 → Live Memory Transformation (PRIMARY UNKNOWN)

**Impact:** Determines whether the engine code observed at `0x412a0000` is
actually derived from resource #101, or comes from a different source
entirely.

**Evidence:**
- `neverlose::map()` reads resource #101 via `FindResource`/`LoadResource`/
  `LockResource` and writes via `NtWriteVirtualMemory` to `0x412a0000`
  (**SOURCE-CONFIRMED**, `neverlose.cpp:16-47`)
- Live memory at `0x412a0000` reads as `00 00 00 00` (**OBSERVED**, read-only
  memory read from PID 21580/8780)
- Resource #101 starts with `a6 c0 4e c9` (**CONFIRMED**, PE resource extraction)
- No source function decrypts, decompresses, or otherwise transforms the
  mapped image (**OBSERVED**, full source review of `neverlose.cpp`,
  `fix_dump.cpp`, `resolve_helper.cpp`, `mem_dispatcher.cpp`,
  `missingent.cpp`, `client_patches.cpp`, `spoof.cpp`, `spoof_peb.cpp`,
  `spoof_kusd.cpp`, `spoof_cpuid.cpp`, `fix_cvars.cpp`, `fix_sha256.cpp`,
  `VEH.cpp`, `HookFn.cpp`, `setup_hooks.cpp`)

**Required to resolve:**
- A memory dump of `0x412a0000` taken **immediately after**
  `neverlose::map()` completes but **before** any subsequent initialization
  step (`fix_dump()`, `set_veh()`, `setup_hooks()`, `spoof()`, `entry()`)
  This would show whether resource bytes are written correctly (and then
  zeroed later), or never written at all.
- OR: Complete source review of all `.cpp` files not fully read
  (`fix_interfaces.cpp`, `fix_cvars.cpp`, `fix_signatures.cpp`,
  `fix_mem_dispatcher.cpp`, `spoof.cpp`, `spoof_peb.cpp`,
  `spoof_kusd.cpp`, `spoof_cpuid.cpp`, `HookFn.cpp`, `VEH.cpp`,
  `missingent.cpp`) to find any transformation step not yet examined.

---

### 1.2 Function Role Assignments for Addresses at `0x41xxxxxx–0x44xxxxxx`

**Impact:** Determines what each function at these addresses actually does,
which is essential for understanding the complete prediction pipeline.

**Evidence:**
- All 10 reported addresses contain real, internally consistent x86 code
  (**OBSERVED**, live memory reads)
- Internal call graph confirmed: `0x4140CB75` `e8 86 fb 75 00` → `0x41B6C700`
  (**OBSERVED**, instruction-level)
- None of these byte sequences match any location in the on-disk
  `neverlose.dll` (**CONFIRMED**, 0/10 live 16-byte sequences matched,
  Phase 7)

**Required to resolve:**
- Full static analysis of each function at these addresses
- Runtime trace to observe actual inputs/outputs
- Symbol names or source code for these functions (unavailable)

---

### 1.3 Relationship Between `record+0x00` and `record+0x18`

**Impact:** Determines whether the record structure has one or two position
fields, which affects understanding of the lag-comp distance calculation.

**Evidence:**
- `record+0x00` used in record-selection distance metric at `0x4148F180`
  (**OBSERVED**, `subss xmm0, [eax]`)
- `record+0x18` used in lag-comp acceptability distance at `0x413F94D0`
  (**OBSERVED**, `movsd xmm0, [ecx+0x18]`)
- Not shown being copied into each other in examined regions

**Required to resolve:**
- Runtime struct dump of a live record
- Disassembly showing both fields written from the same source

---

### 1.4 Write Sites for Global `0x424F4B18`

**Impact:** This global is written to `record+0xAC` by `0x413F9E00` and read
86 times, but no write sites were found. Understanding its source would
clarify the tick-correction mechanism.

**Evidence:**
- Written to `record+0xAC` by `0x413F9ECF` (`mov [edx+0xac], eax`)
  (**OBSERVED**)
- 86 read-only xrefs found (**OBSERVED**)
- No write sites found (**OBSERVED**)

**Required to resolve:**
- Write watchbreakpoint on `0x424F4B18` during runtime
- Full xref scan including indirect writes

---

### 1.5 Trampoline Calls `0x41400BF0` / `0x413F6B40`

**Impact:** These geometry/visibility helpers are reached from the record
selection loop, but their behavior is unknown due to obfuscation.

**Evidence:**
- Both helpers end in `jmp` to trampoline `0x39C21170` (**OBSERVED**)
- Junk bytes and opaque predicates prevent static tracing (**OBSERVED**)
- Called from record-selection loop at `0x4148F3EC` and `0x4148F5B4`
  (**OBSERVED**)

**Required to resolve:**
- Dynamic instrumentation of csgo.exe stepping through the helpers
- De-obfuscation of the `0x39C21170` trampoline region

---

## 2. HIGH (affects data-flow accuracy)

### 2.1 Source/Binary Revision Match

**Impact:** Determines whether the source code in
`FemboyLose-main/neverlose/` exactly matches the running binary.

**Evidence:**
- Addresses in source match live memory (`0x41xxxxxx–0x44xxxxxx`)
  (**STRONGLY SUPPORTED**)
- `imageSize` in source (`0x3501000`) differs from resource size
  (55,578,628 = `0x3501014`) by 4 bytes (**OBSERVED**)

**Required to resolve:**
- Build metadata from the running `neverlose.dll`
- Git history or version stamps (not available in workspace)

---

### 2.2 Meaning of `record+0x38` Velocity Component

**Impact:** Determines whether the half-tick projection in record selection
is truly velocity-based or something else entirely.

**Evidence:**
- `movss xmm1, [eax+0x38]; mulss xmm1, [0x4205A518]` (0.5)
  (**OBSERVED**, instruction-level)
- No correlation with `m_vecVelocity()` at runtime (**UNKNOWN**)

**Required to resolve:**
- Runtime correlation of `record+0x38` with `m_vecVelocity()`
- Disassembly showing where `record+0x38` is written

---

### 2.3 Contents of Geometry Sub-structure at `record+0xA4`

**Impact:** This struct is passed to the geometry helper `0x41400BF0` but its
contents are unknown.

**Evidence:**
- `lea eax, [edi+0xA4]` at `0x4148F582` (**OBSERVED**)
- Passed as arg2 to `0x41400BF0` (**OBSERVED**)
- Contents unknown

**Required to resolve:**
- Runtime memory dump of `record+0xA4` region
- Disassembly showing what's written there

---

### 2.4 Ordering of Two Paths Inside `0x41496DB0`

**Impact:** Determines whether origin assembly happens before or after record
selection.

**Evidence:**
- Two paths separated by guards on `[0x424B03C0]` /
  `[0x424B03D4]` / `[0x424B03B4]` (**OBSERVED**)
- Relative ordering undetermined (**UNKNOWN**)

**Required to resolve:**
- Control-flow trace of `0x41496DB0` during runtime

---

### 2.5 How `0x41596AA9` (Aim-Caller) is Entered

**Impact:** Determines the complete call chain for aim computation.

**Evidence:**
- Calls into aim pipeline (`0x41367250`, `0x41412FE0`, `0x41427FA0`,
  `0x41428C40`, `0x41395030`) then reaches `0x4140C710`
  (**OBSERVED**)
- NO direct E8 callers found (**OBSERVED**)

**Required to resolve:**
- Caller scan including indirect calls (`call [reg]`)
- Traceback from `0x4140C710` during runtime

---

## 3. MEDIUM (nice-to-have)

### 3.1 `.detourc` / `.detourd` / `.fptable` Contents

**Impact:** 4.5 KB of hook stubs and a NULL-initialized pointer table were
not disassembled. Hook targets unknown.

**Evidence:** Sections present in PE header, contents not analyzed

### 3.2 `.rdata` / `.data` / `.reloc` Global Contents

**Impact:** Section headers read; individual globals and constants not
catalogued. Would clarify fixed constants, vtables, and global state.

### 3.3 Whether Resource #101 is Loaded at Runtime

**Impact:** DLL imports resource APIs
(`FindResourceW`, `LoadResource`, `LockResource`, `SizeofResource`) but no
consumer of `0x412a0000` was identified in `.text`.

### 3.4 Resource #102 CPUID Code Invocation Context

**Impact:** Confirmed as x86 CPUID code ("AuthenticAMD"), but where/when it
is called during init is unknown.

### 3.5 Resources #104 (PNG) and #105 (JPEG) Purpose

**Impact:** Confirmed as image assets; purpose (splash, logo, avatar, UI)
unknown.

---

## 4. ARCHITECTURE-LEVEL

### 4.1 Is There a Single Final Aim Position?

**Status:** UNKNOWN (leaning NO). Native aim consumer exists; Lua-side
prediction is render/telemetry-only; no unification found.

### 4.2 Can Lua Influence Native Aim at All?

**Status:** UNKNOWN. No Lua→native aim binding or verified aim-injection patch
point identified.

---

## 5. WHAT WOULD COMPLETE THE DLL INVESTIGATION

1. **Decode resource #101** — compression/encryption/XOR analysis; locate its
   consumer in `.text`
2. **Fully document record-selection, lag-comp, aim-pipeline, and
   geometry-helper functions** in `.text` (no source available)
3. **Capture a Lua `require()` trace** from inside csgo.exe at init
4. **Dynamically instrument** the obfuscated helpers past trampoline
   `0x39C21170`
5. **Trace consumers of aim globals** `0x425023C8/23D0/23EC` and the `0x71c`
   struct
6. **Resource-extract and identify** `#104` (PNG) and `#105` (JPEG)
7. **Parse `.reloc` and enumerate `.rdata`/`.data` globals**

========================================
END
========================================