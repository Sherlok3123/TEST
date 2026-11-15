# NEVERLOSE NEXT UNKNOWN AREAS
==============================
Prioritized remaining unknowns for the Neverlose.dll deep static analysis.
Each entry states why it is unresolved and what specific evidence would
resolve it. This supersedes NEVERLOSE_FINAL_UNKNOWNS.md for DLL-specific
questions; component-level unknowns (loader download URL, server auth, etc.)
remain in that document.

Evidence levels: CONFIRMED / STRONGLY SUPPORTED / INFERRED / UNKNOWN.

========================================
1. CRITICAL (block architectural understanding of the DLL core)
================================================================

1.1 Native subsystems without source (record selection, lag-comp, aim pipeline, geometry helpers)
--------------------------------------------------------------------------------------------------
Impact: The core cheat logic (record selection, lag compensation, aim
consumer, geometry helpers) exists only in the compiled binary. Without
source, their exact semantics, inputs, and outputs cannot be confirmed
beyond the disassembly already performed.

Why unresolved: No source file in FemboyLose-main/neverlose/ corresponds
to these subsystems. They are not in main.cpp, fix_dump.cpp, fix_imports.cpp,
setup_hooks.cpp, VEH.cpp, HookFn.cpp, or Requestor.cpp.

What would resolve it: (a) locate the missing source files (possibly in an
uninspected archive or a different branch), or (b) fully decompile the
relevant .text regions and document semantics purely from disassembly.

1.2 The 53 MB .rsrc blob (resource #101) — format and purpose
-----------------------------------------------------------------
Impact: It is ~99.9% of the DLL file. If it contains embedded Lua scripts,
config, or assets, it is central to initialization. If it is unrelated
padding, it is noise.

Why unresolved: First bytes (a6 c0 4e c9…) match no known magic. Not raw
Lua bytecode. Not a simple 4-byte repeating XOR of nl.bin. Shows a repeating
pattern ("…-2026…"). Entropy contribution to .rsrc = 7.27 (high).

What would resolve it: (a) entropy/profile analysis of #101 to distinguish
compressed vs. encrypted vs. structured; (b) attempt common decompression
(zlib, lz4, lzma) and XOR keys; (c) locate code that loads resource #101
(via FindResourceW/LoadResource/LockResource call sites in .text).

1.3 Lua VM entry point and auto-loaded script list
---------------------------------------------------
Impact: Determines which Lua scripts execute at neverlose.dll init and how
the VM is bootstrapped. Currently UNKNOWN; only server-side library files
are known.

Why unresolved: The Lua VM entry point was not located in the binary or
source. No runtime require() trace was captured. require("neverlose/…")
calls exist in workspace scripts but runtime loading is server-driven.

What would resolve it: (a) a Lua require() trace from inside csgo.exe
(PID 21580) at init; (b) disassembly of the Lua VM initialization code in
. text; (c) neverlose.dll source showing its startup require() list.

1.4 Native→Lua and Lua→native aim boundary
------------------------------------------
Impact: Determines whether Lua can read or influence native aim output.
Currently: Lua has NO verified binding to the native aim consumer
(0x4140C710…0x41408800). Lua→native is FFI patches only.

Why unresolved: No Lua binding reads 0x425023C8/23D0/23EC (aim output
globals). No verified patch point for aim injection was identified.

What would resolve it: (a) identify a native→Lua callback for aim results;
(b) identify a verified memory-patch location that alters aim behavior;
(c) confirm the consumer of globals 0x425023C8/23D0/23EC.

========================================
2. HIGH (affects data-flow accuracy)
======================================

2.1 Consumer of aim output globals 0x425023C8/23D0/23EC
-------------------------------------------------------
Impact: Without a consumer, the aim pipeline's output destination is
unknown (engine state? render? stored only?).

Why unresolved: 0x4140CB75 writes these globals; 0x41408800 copies the
0x71c-byte struct; but nothing in the enumerated .text call graph reads
them back into engine state.

What would resolve it: a write/read trace on these globals during runtime,
or disassembly tracing their consumers.

2.2 Semantics of the 0x71c-byte structure copied by 0x41408800
-------------------------------------------------------------
Impact: Determines what the aim pipeline actually produces (aim result,
entity state, config blob).

Why unresolved: The memcpy is CONFIRMED; the structure's meaning is not.

What would resolve it: structural analysis of the copied buffer (field
offsets, values) during runtime, or source for the apply function.

2.3 Write sites for global 0x424F4B18 (tick correction)
-------------------------------------------------------
Impact: 0x413F9E00 writes record+0xAC from 0x424F4B18; 86 read-only xrefs
found, NO write sites. Who writes 0x424F4B18 affects lag-comp timing.

Why unresolved: No write site located in .text; possibly written via
indirect store or from a section outside .text.

What would resolve it: a write watchbreakpoint on 0x424F4B18 during runtime,
or a fuller xref scan including indirect writes and other sections.

2.4 Behavior of obfuscated helpers past trampoline 0x39C21170
-------------------------------------------------------------
Impact: 0x41400BF0 and 0x413F6B40 (geometry/visibility helpers) dead-end at
the obfuscated trampoline. Their true behavior (geometry check? visibility?
anti-tamper?) is unknown.

Why unresolved: Junk bytes + opaque predicates + indirect jumps prevent
static tracing past the trampoline.

What would resolve it: dynamic instrumentation of csgo.exe (PID 21580)
stepping through the helpers; or de-obfuscation of the trampoline region.

2.5 Relationship between record+0x00 and record+0x18
-----------------------------------------------------
Impact: Both used as positions (0x00 in record-selection distance at
0x4148F180; 0x18 in lag-comp acceptability at 0x413F94D0). If they differ
(origin vs. corrected origin), the pipeline has two position fields.

Why unresolved: Not shown being copied into each other in examined regions.

What would resolve it: a runtime struct dump of a live record, or
disassembly showing both fields written from the same source.

2.6 Ordering of the two paths inside 0x41496DB0 (lag-comp orchestrator)
------------------------------------------------------------------------
Impact: Determines whether origin assembly happens before or after record
selection.

Why unresolved: Two paths (guarded by [0x424B03C0], [0x424B03D4],
[0x424B03B4]); relative order undetermined.

What would resolve it: a control-flow trace of 0x41496DB0 during runtime.

2.7 How 0x41596AA9 (aim-consumer caller) is entered
---------------------------------------------------
Impact: 0x41596AA9 calls into the aim pipeline then reaches 0x4140C710, but
has NO direct E8 callers — reached via jump, indirect call, or hook entry.

Why unresolved: No E8 caller found.

What would resolve it: a caller scan including indirect calls (call [reg]),
or a traceback from 0x4140C710 during runtime.

========================================
3. MEDIUM (nice-to-have)
========================

3.1 .detourc / .detourd / .fptable contents (detour hooks)
----------------------------------------------------------
Why: 4.5 KB of hook stubs and a NULL-initialized pointer table were not
disassembled. Hook targets unknown.

3.2 .rdata / .data / .reloc global contents
-------------------------------------------
Why: Section headers read; individual globals and constants not catalogued.
Would clarify fixed constants, vtables, and global state.

3.3 Whether resource #101 is loaded at runtime
----------------------------------------------
Why: DLL imports resource APIs (FindResourceW, LoadResource, LockResource,
SizeofResource) but no consumer of #101 was identified in .text.

3.4 Resource #102 CPUID code invocation context
-----------------------------------------------
Why: Confirmed as x86 CPUID code ("AuthenticAMD"), but where/when it is
called during init is unknown.

3.5 Resources #104 (PNG) and #105 (JPEG) purpose
------------------------------------------------
Why: Confirmed as image assets; purpose (splash, logo, avatar, UI) unknown.

========================================
4. ARCHITECTURE-LEVEL
=====================

4.1 Is there a single final aim position?
-----------------------------------------
Status: UNKNOWN (leaning NO). Native aim consumer exists; Lua-side
prediction is render/telemetry-only; no unification found.

4.2 Can Lua influence native aim at all?
----------------------------------------
Status: UNKNOWN. No Lua→native aim binding or verified aim-injection patch
point identified.

========================================
5. WHAT WOULD COMPLETE THE DLL INVESTIGATION
============================================

  1. Decompile / fully document the record-selection, lag-comp, aim-pipeline,
     and geometry-helper functions in .text (no source available).
  2. Decode resource #101 (compression/encryption/XOR analysis; locate its
     consumer in .text).
  3. Capture a Lua require() trace from inside csgo.exe at init.
  4. Dynamically instrument the obfuscated helpers past trampoline 0x39C21170.
  5. Trace consumers of aim globals 0x425023C8/23D0/23EC and the 0x71c struct.
  6. Resource-extract and identify #104 (PNG) and #105 (JPEG).
  7. Parse .reloc and enumerate .rdata/.data globals.

========================================
END
========================================